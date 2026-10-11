use arkret_wire::{
    DidCoreId, Event, MAX_AUTHORIZED_BY_REFS, MAX_EVENT_ENVELOPE_BYTES, MAX_EVENT_RESOLVE,
    MAX_EVENT_SUBMIT_BATCH, MAX_SEMANTIC_REFS, RealmId, ScopeRef, validate_authorized_by_ref_count,
    validate_event_envelope_byte_len, validate_event_submit_batch_count,
    validate_semantic_ref_count,
};
use serde_json::json;

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5").unwrap()
}

fn raw_event() -> Event {
    arkret_wire::test_support::raw_event(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: realm_id(),
        },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
        json!({"body": "hello"}),
    )
    .unwrap()
}

#[test]
fn event_new_sets_content_bound_event_id() {
    let event = raw_event();
    assert!(event.event_id.as_str().starts_with("ak:event:"));
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
}

#[test]
fn event_digest_is_the_compact_producer_payload_without_id_or_producer_proof() {
    let event = raw_event();
    let payload = event.digest_payload().unwrap();
    let object = payload.as_object().unwrap();

    assert!(!object.contains_key("event_id"));
    assert!(!object.contains_key("producer_proof"));
    assert_eq!(payload["kind"], "ak.message.create");
    assert_eq!(payload["realm_id"], realm_id().as_str());
    assert_eq!(payload["scope_ref"]["kind"], "realm");
    assert_eq!(payload["payload"]["body"], "hello");
}

#[test]
fn event_scalability_limits_match_v1_profile() {
    assert_eq!(MAX_EVENT_ENVELOPE_BYTES, 1024 * 1024);
    assert_eq!(MAX_EVENT_SUBMIT_BATCH, 1_000);
    assert_eq!(MAX_EVENT_RESOLVE, 100);
    assert_eq!(MAX_SEMANTIC_REFS, 128);
    assert_eq!(MAX_AUTHORIZED_BY_REFS, 64);
}

#[test]
fn event_scalability_helpers_reject_over_limits() {
    validate_event_envelope_byte_len(MAX_EVENT_ENVELOPE_BYTES).unwrap();
    assert!(validate_event_envelope_byte_len(MAX_EVENT_ENVELOPE_BYTES + 1).is_err());
    validate_event_submit_batch_count(MAX_EVENT_SUBMIT_BATCH).unwrap();
    assert!(validate_event_submit_batch_count(MAX_EVENT_SUBMIT_BATCH + 1).is_err());
    validate_semantic_ref_count(MAX_SEMANTIC_REFS).unwrap();
    assert!(validate_semantic_ref_count(MAX_SEMANTIC_REFS + 1).is_err());
    validate_authorized_by_ref_count(MAX_AUTHORIZED_BY_REFS).unwrap();
    assert!(validate_authorized_by_ref_count(MAX_AUTHORIZED_BY_REFS + 1).is_err());
}

#[test]
fn event_digest_preimage_agrees_with_typed_digest_payload() {
    let event = raw_event();
    let envelope = serde_json::to_value(&event).unwrap();
    assert_eq!(
        arkret_wire::event_digest_preimage(&envelope).unwrap(),
        event.digest_payload().unwrap()
    );
}

#[test]
fn event_digest_preimage_drops_exactly_id_and_producer_proof() {
    let envelope = json!({
        "event_id": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:webvh:z6mkfixture",
        "scope_ref": {"kind": "realm", "realm_id": realm_id()},
        "payload": {"body": "hello"},
        "producer_proof": {"kind": "detached_jws"}
    });

    let preimage = arkret_wire::event_digest_preimage(&envelope).unwrap();
    let object = preimage.as_object().unwrap();
    assert!(!object.contains_key("event_id"));
    assert!(!object.contains_key("producer_proof"));
    assert_eq!(object.len(), 4);
    assert!(object.contains_key("scope_ref"));
}

#[test]
fn event_digest_preimage_rejects_a_non_object_envelope() {
    for input in [json!(null), json!([]), json!("event")] {
        assert!(arkret_wire::event_digest_preimage(&input).is_err());
    }
}
