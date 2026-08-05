use std::collections::BTreeMap;

use arkret_wire::{
    Did, Event, EventId, EventRequirements, Hlc, MAX_ACTOR_SEQ_SIBLINGS, MAX_AUTHORITY_CHAIN_DEPTH,
    MAX_AUTHORITY_CONTROL_DEPTH, MAX_AUTHORIZED_BY_REFS, MAX_EVENT_ENVELOPE_BYTES,
    MAX_EVENT_PREV_REFS, MAX_EVENT_REFS, MAX_EVENT_RESOLVE, MAX_EVENT_SUBMIT_BATCH, RealmId,
    ScopeRef, prev_frontier_digest, validate_actor_seq_sibling_count,
    validate_authority_chain_depth, validate_authority_control_depth,
    validate_authorized_by_ref_count, validate_event_envelope_byte_len, validate_event_prev_refs,
    validate_event_ref_count, validate_event_submit_batch_count,
};
use serde_json::json;

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-8000-8000-65c7feb295d7").unwrap()
}

#[test]
fn event_new_sets_required_event_id() {
    let event = Event::new(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: realm_id(),
        },
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({"body": "hello"}),
    )
    .unwrap();

    assert!(event.event_id.as_str().starts_with("ak:event:"));
}

#[test]
fn event_digest_uses_canonical_payload_without_proofs_or_unsigned() {
    let event = Event {
        event_id: EventId::new("ak:event:01904100-0000-8000-8000-a0086f45c575").unwrap(),
        kind: "ak.message.create".into(),
        realm_id: realm_id(),
        scope_ref: ScopeRef::Realm {
            realm_id: realm_id(),
        },
        actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        actor_seq: 1,
        created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
        hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
        prev_refs: Vec::new(),
        refs: Vec::new(),
        preconditions: Vec::new(),
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        payload: BTreeMap::from([("body".to_owned(), json!("hello"))]),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: BTreeMap::from([("local_receive_time".to_owned(), json!("ignored"))]),
        causal_refs: Vec::new(),
        proofs: Vec::new(),
    };

    // Pinned after `scope_ref` became a producer-signed transcript member,
    // `effective_scope` / `effects` / `conflict_keys_digest` left the wire, and
    // `event_id` left the digest preimage because section 4.0 derives it from
    // this very digest (`conformance/encoding.md` sections 2, 4.0 and 6). Every
    // v1 Event digest changed; this value must only move again with the spec.
    assert_eq!(
        event.event_digest().unwrap(),
        "sha256:808e5292e5a9084ead79d4540162e1d6340ccc229ca8ea8059654f05fd179db6"
    );
    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(value["payload"]["body"], "hello");
    assert!(value.get("content").is_none());
}

#[test]
fn prev_frontier_digest_sorts_and_deduplicates_refs() {
    let refs_a = [
        "ak:event:01904100-0000-8000-8000-000000000003",
        "ak:event:01904100-0000-8000-8000-000000000001",
        "ak:event:01904100-0000-8000-8000-000000000003",
        "ak:event:01904100-0000-8000-8000-000000000002",
    ];
    let refs_b = [
        "ak:event:01904100-0000-8000-8000-000000000001",
        "ak:event:01904100-0000-8000-8000-000000000002",
        "ak:event:01904100-0000-8000-8000-000000000003",
    ];

    assert_eq!(
        prev_frontier_digest(refs_a).unwrap(),
        prev_frontier_digest(refs_b).unwrap()
    );
    assert_ne!(
        prev_frontier_digest(std::iter::empty::<&str>()).unwrap(),
        prev_frontier_digest(refs_b).unwrap()
    );
    assert_eq!(MAX_ACTOR_SEQ_SIBLINGS, 16);
}

#[test]
fn event_scalability_limits_match_v1_profile() {
    assert_eq!(MAX_EVENT_ENVELOPE_BYTES, 1024 * 1024);
    assert_eq!(MAX_EVENT_SUBMIT_BATCH, 1_000);
    assert_eq!(MAX_EVENT_RESOLVE, 100);
    assert_eq!(MAX_EVENT_PREV_REFS, 128);
    assert_eq!(MAX_EVENT_REFS, 128);
    assert_eq!(MAX_AUTHORIZED_BY_REFS, 64);
    assert_eq!(MAX_AUTHORITY_CHAIN_DEPTH, 4);
    assert_eq!(MAX_AUTHORITY_CONTROL_DEPTH, 4);
}

#[test]
fn event_scalability_helpers_reject_over_limits() {
    validate_event_envelope_byte_len(MAX_EVENT_ENVELOPE_BYTES).unwrap();
    assert!(validate_event_envelope_byte_len(MAX_EVENT_ENVELOPE_BYTES + 1).is_err());
    validate_event_submit_batch_count(MAX_EVENT_SUBMIT_BATCH).unwrap();
    assert!(validate_event_submit_batch_count(MAX_EVENT_SUBMIT_BATCH + 1).is_err());
    validate_event_ref_count(MAX_EVENT_REFS).unwrap();
    assert!(validate_event_ref_count(MAX_EVENT_REFS + 1).is_err());
    validate_authorized_by_ref_count(MAX_AUTHORIZED_BY_REFS).unwrap();
    assert!(validate_authorized_by_ref_count(MAX_AUTHORIZED_BY_REFS + 1).is_err());
    validate_actor_seq_sibling_count(MAX_ACTOR_SEQ_SIBLINGS).unwrap();
    assert!(validate_actor_seq_sibling_count(MAX_ACTOR_SEQ_SIBLINGS + 1).is_err());
    validate_authority_chain_depth(MAX_AUTHORITY_CHAIN_DEPTH).unwrap();
    assert!(validate_authority_chain_depth(MAX_AUTHORITY_CHAIN_DEPTH + 1).is_err());
    validate_authority_control_depth(MAX_AUTHORITY_CONTROL_DEPTH).unwrap();
    assert!(validate_authority_control_depth(MAX_AUTHORITY_CONTROL_DEPTH + 1).is_err());

    let prev_refs = (0..MAX_EVENT_PREV_REFS)
        .map(|index| format!("ak:event:01904100-0000-8000-8000-{index:012x}"))
        .collect::<Vec<_>>();
    validate_event_prev_refs(prev_refs.iter().map(String::as_str)).unwrap();
    let mut duplicate = prev_refs;
    duplicate.push(duplicate[0].clone());
    assert!(validate_event_prev_refs(duplicate.iter().map(String::as_str)).is_err());
}

/// `event-and-patch.md` §75 names producer-selected `auth_context.capability_refs`
/// alongside `effects` as a field a v1 receiver MUST reject with
/// `schema_violation`, and the envelope schema closes `auth_context` over
/// `{did, key_id, key_epoch, credential_epoch}`.
///
/// Rejecting is the point: effective capabilities are derived from the accepted
/// governance basis, so a producer that ships a list has either been tampered
/// with or is running pre-v1 code. Silently dropping the member would make both
/// look like a well-formed Event.
#[test]
fn auth_context_rejects_a_producer_selected_capability_list() {
    let base = json!({
        "did": "did:webvh:z6mkfixture:alice.example",
        "key_id": "ak:device:01904100-0000-7000-8000-65c7feb295d8",
        "key_epoch": 1
    });
    serde_json::from_value::<arkret_wire::AuthContext>(base.clone())
        .expect("the closed member set must still parse");

    let mut smuggled = base;
    smuggled["capability_refs"] = json!(["ak:grant:01904100-0000-7000-8000-65c7feb295d9"]);
    let error = serde_json::from_value::<arkret_wire::AuthContext>(smuggled)
        .expect_err("a producer-selected capability list must not deserialize");
    assert!(
        error.to_string().contains("capability_refs"),
        "unexpected error: {error}"
    );
}
