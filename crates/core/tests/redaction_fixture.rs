//! Executable consumer for the spec fixture
//! `fixtures/redaction-fixture.json` (per-message redaction / tombstone
//! vectors).
//!
//! The SDK-implementable subset drives
//! [`arkret_core::events::redaction::redaction_tombstone_message_value`] and
//! asserts the field-preservation + plaintext-erasure contract the fixture's
//! `preserved_fields` case pins. The remaining cases are server-reducer
//! semantics (pending/materialization ordering, audit-view split, snapshot
//! pruning, hard-erasure receipts, policy scope) and are consumed here at the
//! metadata level only — their promised `expected` outcome strings are pinned
//! so the fixture cannot silently drift ahead of this consumer, but the
//! behaviour stays owned by the soland reducer suite:
//!
//! * `dangling_redaction` / `late_target_event` — need a message store to park the redaction
//!   pending and materialize the target later.
//! * `audit_visibility` — needs the default-view / audit-view split.
//! * `snapshot_pruning_stub` / `hard_erasure_receipt` — need snapshot pruning and signed erasure
//!   receipts.
//! * `space_target_ref_schema` / `policy_scope` — need the object-lifecycle redaction schema
//!   acceptance and Realm quarantine policy timeline.

use arkret_core::events::redaction::{
    REDACTED_MESSAGE_PLACEHOLDER, REDACTED_MESSAGE_STATE, redaction_tombstone_message_value,
};
use arkret_core::schema::embedded_json_artifact;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

const FIXTURE_PATH: &str = "fixtures/redaction-fixture.json";

fn fixture() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded redaction fixture must load")
}

fn case(fixture: &Value, name: &str) -> Value {
    fixture["cases"]
        .as_array()
        .expect("fixture cases must be an array")
        .iter()
        .find(|case| case["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("fixture case {name} missing"))
        .clone()
}

#[test]
fn fixture_case_manifest_is_pinned() {
    // Guard: extend this consumer when the spec adds or renames cases.
    let fixture = fixture();
    let names: Vec<&str> = fixture["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .map(|case| case["name"].as_str().expect("case name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "preserved_fields",
            "dangling_redaction",
            "late_target_event",
            "audit_visibility",
            "snapshot_pruning_stub",
            "space_target_ref_schema",
            "policy_scope",
            "hard_erasure_receipt",
        ],
        "redaction fixture case manifest drifted — update the SDK consumer"
    );
}

#[test]
fn preserved_fields_survive_tombstone_and_body_is_erased() {
    let case = case(&fixture(), "preserved_fields");
    let preserve: Vec<&str> = case["preserve"]
        .as_array()
        .expect("preserve list")
        .iter()
        .map(|value| value.as_str().expect("preserve field name"))
        .collect();
    // The fixture pins the audit-metadata set a redaction tombstone MUST keep.
    assert_eq!(
        preserve,
        vec!["event_id", "created_at", "actor_id", "redacts"],
        "preserved-field set drifted from the fixture"
    );

    // A redacted message-create carrying every preserved field plus a
    // plaintext body and derived surfaces that MUST NOT survive.
    let mut event = json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:01970e58-0004-7000-8000-0000000005a1",
        "created_at": "2026-04-26T00:00:00.000Z",
        "actor_id": "did:webvh:z6mkfixture:alice.example",
        "redacts": "ak:event:01970e58-0004-7000-8000-0000000005a0",
        "content": {"kind": "ak.content.text", "body": "secret plaintext"},
        "reactions": [{"actor": "did:webvh:z6mkfixture:bob.example", "key": "+1"}],
        "mentions": [{"actor_id": "did:webvh:z6mkfixture:bob.example"}],
        "search_terms": ["secret", "plaintext"],
    });
    let redacted_at = DateTime::parse_from_rfc3339("2026-04-26T00:05:00.000Z")
        .unwrap()
        .with_timezone(&Utc);

    redaction_tombstone_message_value(
        &mut event,
        redacted_at,
        Some("ak:event:01970e58-0004-7000-8000-0000000005a2"),
    );

    // Every fixture-preserved field must survive verbatim.
    for field in &preserve {
        assert!(
            event.get(*field).is_some(),
            "preserved field {field} must survive the redaction tombstone"
        );
    }
    assert_eq!(
        event["event_id"],
        json!("ak:event:01970e58-0004-7000-8000-0000000005a1")
    );
    assert_eq!(event["created_at"], json!("2026-04-26T00:00:00.000Z"));
    assert_eq!(
        event["actor_id"],
        json!("did:webvh:z6mkfixture:alice.example")
    );
    assert_eq!(
        event["redacts"],
        json!("ak:event:01970e58-0004-7000-8000-0000000005a0")
    );

    // The plaintext body and every derived surface must be gone / cleared.
    assert_eq!(
        event["content"]["body"],
        json!(REDACTED_MESSAGE_PLACEHOLDER)
    );
    assert_eq!(event["state"], json!(REDACTED_MESSAGE_STATE));
    assert_eq!(event["redacted"], json!(true));
    assert!(
        event.get("reactions").is_none(),
        "reactions must be stripped"
    );
    assert!(event.get("mentions").is_none(), "mentions must be stripped");
    assert!(
        event.get("search_terms").is_none(),
        "search terms must be stripped"
    );

    // No residual leak of the original plaintext anywhere in the value.
    let serialized = serde_json::to_string(&event).expect("serialize tombstone");
    assert!(
        !serialized.contains("secret plaintext"),
        "tombstone must not leak the original plaintext body"
    );
}

#[test]
fn reducer_residual_cases_pin_their_expected_outcomes() {
    // The remaining cases are server-reducer semantics. Consume them at the
    // metadata level: pin every promised `expected` outcome string so the
    // fixture cannot drift ahead of this consumer unnoticed.
    let fixture = fixture();
    let expectations: &[(&str, &str)] = &[
        ("dangling_redaction", "pending_until_target_or_expiry"),
        ("late_target_event", "render_redacted_on_materialization"),
        ("audit_visibility", "audit_view_retains_tombstone_only"),
        (
            "snapshot_pruning_stub",
            "snapshot_and_backfill_retain_verification_stub",
        ),
        (
            "space_target_ref_schema",
            "schema_accepts_ak_space_target_ref_rejects_malformed",
        ),
        (
            "policy_scope",
            "content_stripped_timeline_position_and_quarantine_fingerprint_retained",
        ),
        (
            "hard_erasure_receipt",
            "signed_receipt_and_stub_conform_no_plaintext_fingerprint_legal_hold_blocks",
        ),
    ];
    for (name, expected) in expectations {
        let case = case(&fixture, name);
        assert_eq!(
            case["expected"].as_str(),
            Some(*expected),
            "reducer-residual case {name} expected outcome drifted"
        );
    }
}
