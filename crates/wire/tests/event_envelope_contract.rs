use std::collections::BTreeMap;

use arkret_wire::{
    AccountId, ActorId, DidCoreId, DigestSuiteCode, Event, EventId, EventIdentityKey,
    EventRequirements, Hlc, MAX_ACTOR_SEQ_SIBLINGS, MAX_AUTHORITY_CHAIN_DEPTH,
    MAX_AUTHORITY_CONTROL_DEPTH, MAX_AUTHORIZED_BY_REFS, MAX_EVENT_ENVELOPE_BYTES,
    MAX_EVENT_PREV_REFS, MAX_EVENT_REFS, MAX_EVENT_RESOLVE, MAX_EVENT_SUBMIT_BATCH, RealmId,
    ScopeRef, prev_frontier_digest, validate_authorized_by_ref_count,
    validate_event_envelope_byte_len, validate_event_ref_count, validate_event_submit_batch_count,
};
use serde_json::json;

fn realm_id() -> RealmId {
    RealmId::from_event_id(&strong_ref(0x65))
}

fn strong_ref(seed: u8) -> EventId {
    let identity = EventIdentityKey::new(DigestSuiteCode::Sha256, [seed; 32]);
    identity.event_id()
}

fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
    ))
}

#[test]
fn event_new_sets_required_event_id() {
    let event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: realm_id(),
        },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
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
        event_id: strong_ref(0xa0),
        kind: "ak.message.create".into(),
        realm_id: realm_id(),
        scope_ref: ScopeRef::Realm {
            realm_id: realm_id(),
        },
        actor_id: actor(),
        actor_seq: 1,
        created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
        hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
        prev_refs: Vec::new(),
        refs: Vec::new(),
        preconditions: Vec::new(),
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        payload: BTreeMap::from([("body".to_owned(), json!("hello"))]),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        unsigned: BTreeMap::from([("local_receive_time".to_owned(), json!("ignored"))]),
        causal_refs: Vec::new(),
        proofs: Vec::new(),
    };

    // Pinned after `scope_ref` and the actor's Station coordinate became producer-signed transcript
    // members, `effective_scope` / `effects` / `conflict_keys_digest` left the wire, and
    // `event_id` left the digest preimage because section 4.0 derives it from
    // this very digest (`conformance/encoding.md` sections 2, 4.0 and 6). Every
    // v1 Event digest changed; this value must only move again with the spec.
    assert_eq!(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
        "sha256:c7f5a132533ef5cb62c1f03c47ac69aac22e4f97aab34e5b92711d96d0b68d8c"
    );
    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(value["payload"]["body"], "hello");
    assert!(value.get("content").is_none());
}

#[test]
fn prev_frontier_digest_sorts_and_deduplicates_refs() {
    let refs_a = [strong_ref(3), strong_ref(1), strong_ref(3), strong_ref(2)];
    let refs_b = [strong_ref(1), strong_ref(2), strong_ref(3)];

    assert_eq!(
        prev_frontier_digest(&refs_a).unwrap(),
        prev_frontier_digest(&refs_b).unwrap()
    );
    assert_ne!(
        prev_frontier_digest(&[]).unwrap(),
        prev_frontier_digest(&refs_b).unwrap()
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
}

/// `event-and-patch.md` §75 names producer-selected `auth_context.capability_refs`
/// alongside `effects` as a field a v1 receiver MUST reject with
/// `schema_violation`, and the envelope schema closes `auth_context` over
/// `{key_id, key_epoch, credential_epoch}`. The Event envelope is the sole
/// carrier of `actor_id`.
///
/// Rejecting is the point: effective capabilities are derived from the accepted
/// governance basis, so a producer that ships a list has either been tampered
/// with or is running pre-v1 code. Silently dropping the member would make both
/// look like a well-formed Event.
#[test]
fn auth_context_rejects_a_producer_selected_capability_list() {
    let base = json!({
        "key_id": "device:01904100-0000-7000-8000-65c7feb295d8",
        "key_epoch": 1
    });
    serde_json::from_value::<arkret_wire::AuthContext>(base.clone())
        .expect("the closed member set must still parse");

    let mut smuggled = base;
    smuggled["capability_refs"] = json!(["ak:grant:AexFmdraZt6B8bFfhx2bo_5tSexCveR9J0cIyonQUfe_"]);
    let error = serde_json::from_value::<arkret_wire::AuthContext>(smuggled)
        .expect_err("a producer-selected capability list must not deserialize");
    assert!(
        error.to_string().contains("capability_refs"),
        "unexpected error: {error}"
    );
}

/// `event_digest_preimage` is the single implementation of the
/// `conformance/encoding.md` §6 exclusion rule, and it MUST agree with
/// [`Event::digest_payload`] field for field.
///
/// The two used to be independent copies of the same rule — one for callers
/// holding a typed `Event`, one open-coded at every verifier holding raw JSON.
/// The copies drifted: one forgot `event_id`, another hashed the envelope
/// itself. None failed loudly; each produced bytes no other
/// implementation reproduces, so valid signatures verified as invalid.
#[test]
fn event_digest_preimage_agrees_with_typed_digest_payload() {
    let event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: realm_id(),
        },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({"body": "hello"}),
    )
    .unwrap();

    let envelope = serde_json::to_value(&event).unwrap();
    assert_eq!(
        arkret_wire::event_digest_preimage(&envelope).unwrap(),
        event.digest_payload().unwrap()
    );
}

/// Every excluded field is excluded, and nothing else is dropped.
///
/// Spelled out per field so a future edit that widens or narrows the set has to
/// state which field it is changing and why: `proofs` (a signature cannot cover
/// itself), `unsigned` (receiver-local, attached after signing) and `event_id`
/// (§4.0 derives it *from* this digest, so leaving it in has no fixed point).
#[test]
fn event_digest_preimage_drops_exactly_the_excluded_fields() {
    let envelope = json!({
        "event_id": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:webvh:z6mkfixture",
        "authorization_ref": "ak:grant:AexFmdraZt6B8bFfhx2bo_5tSexCveR9J0cIyonQUfe_",
        "scope_ref": {"realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},
        "payload": {"body": "hello"},
        "proofs": [{"kind": "detached_jws"}],
        "unsigned": {"local_receive_time": "ignored"}
    });

    let preimage = arkret_wire::event_digest_preimage(&envelope).unwrap();
    let object = preimage.as_object().expect("preimage is an object");
    for excluded in ["event_id", "proofs", "unsigned"] {
        assert!(
            !object.contains_key(excluded),
            "{excluded} must not enter the digest preimage"
        );
    }
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "actor_id",
            "authorization_ref",
            "kind",
            "payload",
            "scope_ref"
        ],
        "the preimage must keep every producer-signed member, `scope_ref` included"
    );
}

/// A non-object input is a caller bug, not an empty preimage: silently hashing
/// `null` would hand back a digest that verifies against nothing.
#[test]
fn event_digest_preimage_rejects_a_non_object_envelope() {
    for input in [json!(null), json!([]), json!("event")] {
        assert!(arkret_wire::event_digest_preimage(&input).is_err());
    }
}
