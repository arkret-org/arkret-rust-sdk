//! Executable consumer for the spec fixture
//! `fixtures/reaction-fixture.json` (OR-Set reducer vectors for
//! `ck.reaction.add` / `ck.reaction.remove`).
//!
//! The SDK-implementable subset runs the fixture events through
//! [`arkret_core::events::ReactionManager`] and asserts the expected OR-Set
//! terminal state (membership + counts). Cases whose expectations require a
//! full server-side reducer (pending/dependency tracking, redaction view
//! split, capability gating, rate limiting, MLS decryption) are consumed as
//! metadata-level checks here and remain owned by the soland reducer suite:
//!
//! * `dangling_reaction_before_target_arrives` — needs a message store to park the reaction as
//!   pending (`dependency_missing`).
//! * `target_redacted_drops_default_view_keeps_audit` — needs the default-view / audit-view split
//!   driven by `ck.message.redact`.
//! * `capability_revoked_blocks_subsequent_add` — needs capability evaluation before reducer state
//!   changes.
//! * `rate_limit_high_rate_reaction_burst` — carries no events at all, only a rate-limit policy
//!   expectation.
//! * The `audit_event_ids` / `audit_view_*` halves of the OR-Set cases — `ReactionManager` keeps
//!   aggregate state, not a per-event audit log.
//! * `after_client_decryption_summary` in the epoch-rotation case — needs live MLS decryption of
//!   the routing-digest keys.

use arkret_core::Did;
use arkret_core::events::{ReactionManager, is_standard_event_kind};
use arkret_core::schema::{embedded_error_code_identifiers, embedded_json_artifact};
use serde_json::Value;

const FIXTURE_PATH: &str = "fixtures/reaction-fixture.json";

fn fixture() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded reaction fixture must load")
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

fn did(value: &str) -> Did {
    Did::new(value.to_owned()).expect("fixture actor_id must be a valid DID")
}

/// Mirror of `ReactionManager`'s shortcode normalisation so fixture keys
/// (raw emoji or `sha256:` routing digests) map onto aggregate map keys.
fn normalized_key(key: &str) -> String {
    let trimmed = key.trim();
    if trimmed.starts_with(':') && trimmed.ends_with(':') {
        trimmed.to_owned()
    } else {
        format!(":{trimmed}:")
    }
}

/// Apply every reaction event of a fixture case, in fixture order, to a
/// fresh manager. Panics on kinds the OR-Set manager cannot consume so a
/// case is never silently half-applied.
fn apply_reaction_events(case: &Value) -> ReactionManager {
    let mut manager = ReactionManager::new();
    for event in case["events"].as_array().expect("case events array") {
        let kind = event["kind"].as_str().expect("event kind");
        let actor = did(event["actor_id"].as_str().expect("actor_id"));
        let payload = &event["payload"];
        let target = payload["target_ref"].as_str().expect("target_ref");
        let key = payload["key"].as_str().expect("key");
        match kind {
            "ck.reaction.add" => {
                manager.add_reaction(target, actor, key);
            }
            "ck.reaction.remove" => {
                manager.remove_reaction(target, &actor, key);
            }
            other => panic!("case contains kind {other} the OR-Set manager cannot consume"),
        }
    }
    manager
}

/// Assert an OR-Set terminal entry: the aggregate count matches the member
/// list length and every expected member's entry is individually present
/// (probed via a clone + `remove_reaction`, which returns membership).
fn assert_members(manager: &ReactionManager, target: &str, key: &str, expected_members: &[&str]) {
    let summary = manager.aggregate(target);
    let count = summary
        .counts
        .get(&normalized_key(key))
        .copied()
        .unwrap_or(0);
    assert_eq!(
        count,
        expected_members.len(),
        "aggregate count for {target}/{key} must equal expected member count"
    );
    for member in expected_members {
        let mut probe = manager.clone();
        assert!(
            probe.remove_reaction(target, &did(member), key),
            "expected member {member} missing from OR-Set entry {target}/{key}"
        );
    }
}

/// Pull `(target_ref, key, members)` triples out of a fixture summary array
/// (both the plaintext `key` and the E2EE `routing_digest_key` spellings).
fn summary_entries(expected_summary: &Value) -> Vec<(String, String, Vec<String>)> {
    expected_summary
        .as_array()
        .expect("expected summary must be an array")
        .iter()
        .map(|entry| {
            let target = entry["target_ref"].as_str().expect("target_ref").to_owned();
            let key = entry["key"]
                .as_str()
                .or_else(|| entry["routing_digest_key"].as_str())
                .expect("summary entry key")
                .to_owned();
            let members = entry["members"]
                .as_array()
                .expect("summary members array")
                .iter()
                .map(|member| member.as_str().expect("member DID").to_owned())
                .collect();
            (target, key, members)
        })
        .collect()
}

fn assert_summary(case: &Value, summary_field: &str) {
    let manager = apply_reaction_events(case);
    for (target, key, members) in summary_entries(&case["expected"][summary_field]) {
        let members: Vec<&str> = members.iter().map(String::as_str).collect();
        assert_members(&manager, &target, &key, &members);
    }
}

#[test]
fn fixture_case_manifest_is_pinned() {
    // Guard: extend this test module when the spec adds or renames cases.
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
            "or_set_basic_add_then_remove",
            "or_set_dedup_double_add_same_actor",
            "or_set_concurrent_add_remove_remove_wins_in_default_view",
            "different_actors_independent_or_set",
            "dangling_reaction_before_target_arrives",
            "target_redacted_drops_default_view_keeps_audit",
            "e2ee_routing_digest_dedup",
            "e2ee_epoch_rotation_breaks_dedup",
            "capability_revoked_blocks_subsequent_add",
            "rate_limit_high_rate_reaction_burst",
        ],
        "reaction fixture case manifest drifted — update the SDK consumers"
    );
}

#[test]
fn fixture_event_kinds_are_registered_standard_kinds() {
    let fixture = fixture();
    for case in fixture["cases"].as_array().expect("cases array") {
        let Some(events) = case["events"].as_array() else {
            continue;
        };
        for event in events {
            let kind = event["kind"].as_str().expect("event kind");
            assert!(
                is_standard_event_kind(kind),
                "fixture references unregistered event kind {kind}"
            );
        }
    }
}

#[test]
fn or_set_basic_add_then_remove() {
    let case = case(&fixture(), "or_set_basic_add_then_remove");
    assert_summary(&case, "summary");
}

#[test]
fn or_set_dedup_double_add_same_actor() {
    // Summary half only; `audit_event_ids` needs a per-event audit log the
    // in-memory manager does not keep (server-side reducer residual).
    let case = case(&fixture(), "or_set_dedup_double_add_same_actor");
    assert_summary(&case, "summary");
}

#[test]
fn or_set_concurrent_add_remove_remove_wins_in_default_view() {
    // Summary half only; `audit_view_retains_both` is audit-log residual.
    let case = case(
        &fixture(),
        "or_set_concurrent_add_remove_remove_wins_in_default_view",
    );
    assert_summary(&case, "summary");
}

#[test]
fn different_actors_independent_or_set() {
    let case = case(&fixture(), "different_actors_independent_or_set");
    assert_summary(&case, "summary");
}

#[test]
fn e2ee_routing_digest_dedup_collapses_same_epoch_adds() {
    // The manager treats the keyed-HMAC routing digest as an opaque key, so
    // same-actor / same-digest adds collapse to a single OR-Set membership
    // exactly like plaintext keys. The `must_not_*` privacy invariants are
    // server-side conduct rules, not reducer terminal state.
    let case = case(&fixture(), "e2ee_routing_digest_dedup");
    assert_summary(&case, "server_side_summary");
}

#[test]
fn e2ee_epoch_rotation_breaks_dedup_server_side() {
    // Server-side half: rotated-epoch digests are distinct opaque keys, so
    // the OR-Set holds two independent entries of one member each. The
    // `after_client_decryption_summary` half needs live MLS decryption.
    let case = case(&fixture(), "e2ee_epoch_rotation_breaks_dedup");
    let expected_distinct = case["expected"]["server_side_summary_distinct_keys"]
        .as_u64()
        .expect("server_side_summary_distinct_keys") as usize;

    let manager = apply_reaction_events(&case);
    let target = case["events"][0]["payload"]["target_ref"]
        .as_str()
        .expect("target_ref");
    let summary = manager.aggregate(target);
    assert_eq!(
        summary.counts.len(),
        expected_distinct,
        "epoch rotation must yield distinct routing-digest OR-Set entries"
    );
    assert!(
        summary.counts.values().all(|count| *count == 1),
        "each rotated-epoch entry holds exactly one member"
    );
}

#[test]
fn reducer_residual_cases_reference_registered_error_identifiers() {
    // The four server-reducer-owned cases are consumed here at the metadata
    // level: every rejection / pending reason they promise must be a
    // registered identifier in the embedded error-code registry, so the
    // fixture cannot drift ahead of the registry unnoticed.
    let fixture = fixture();
    let identifiers =
        embedded_error_code_identifiers().expect("embedded error-code registry must load");

    let pending = case(&fixture, "dangling_reaction_before_target_arrives");
    let reason = pending["expected"]["pending_reactions"][0]["reason"]
        .as_str()
        .expect("pending reason");
    assert!(
        identifiers.contains(reason),
        "pending reason {reason} not registered"
    );

    let revoked = case(&fixture, "capability_revoked_blocks_subsequent_add");
    let rejection = revoked["expected"]["rejection_code"]
        .as_str()
        .expect("rejection_code");
    assert!(
        identifiers.contains(rejection),
        "rejection code {rejection} not registered"
    );

    let rate_limited = case(&fixture, "rate_limit_high_rate_reaction_burst");
    for code in rate_limited["expected"]["error_code_one_of"]
        .as_array()
        .expect("error_code_one_of array")
    {
        let code = code.as_str().expect("error code string");
        assert!(
            identifiers.contains(code),
            "rate-limit error code {code} not registered"
        );
    }
}
