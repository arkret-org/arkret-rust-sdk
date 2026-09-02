use arkret_event_draft::{
    EventDraftKindRegistry, OperationEnvelope, OperationEnvelopeBuilder,
    event_draft_kind_conformance_vectors,
};
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{
    DidCoreId, DidUrl, EventKind, Hash, Hlc, OperationId, ProducerEventProof, RealmId, ScopeRef,
    StrandId, event_spec,
};
use serde_json::json;

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
}

fn scope_ref() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: realm_id(),
    }
}

#[test]
fn operation_envelope_uses_spec_fields_and_digest_ignores_proofs() {
    let proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1").unwrap(),
        event_digest: Hash::new(
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        )
        .unwrap(),
        signer_resolution_evidence_ref: None,
        created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "sig-a".to_owned(),
    };
    let envelope: OperationEnvelope = serde_json::from_value(json!({
        "operation_id": "ak:operation:01904100-0000-7000-8000-0198d483044c",
        "scope_ref": scope_ref(),
        "actor_id": {
            "kind": "service",
            "service_id": "ak:did_core:webvh:z6mkfixture"
        },
        "kind": EventKind::MessageCreate,
        "target_ref": "ak:thread:general",
        "causal": {
            "deps": ["ak:operation:01904100-0000-7000-8000-5f8278b99124"],
            "hlc": "01970e589d21-0004-a13f9c2e",
            "actor_seq": 7
        },
        "payload": {"body": "hello"},
        "proofs": [proof]
    }))
    .unwrap();
    let mut different_proof = envelope.clone();
    different_proof.proofs = vec![ProducerEventProof {
        jws: "sig-b".to_owned(),
        ..proof
    }];

    assert_eq!(
        envelope.operation_digest().unwrap(),
        different_proof.operation_digest().unwrap()
    );
    envelope.validate_for_submit().unwrap();

    let encoded = serde_json::to_value(&envelope).unwrap();
    assert_eq!(
        encoded["actor_id"],
        json!({
            "kind": "service",
            "service_id": "ak:did_core:webvh:z6mkfixture"
        })
    );
    assert_eq!(encoded["kind"], "ak.message.create");
    assert_eq!(encoded["payload"]["body"], "hello");
    assert!(encoded.get("content").is_none());
    assert!(encoded.get("actor").is_none());
    assert!(encoded.get("type").is_none());
    assert!(encoded.get("body").is_none());
    assert!(encoded.get("signature").is_none());
}

#[test]
fn event_draft_kind_registry_accepts_only_canonical_kinds() {
    let registry = EventDraftKindRegistry::default();
    let canonical = registry
        .canonicalize(EventKind::MessageCreate.as_str())
        .unwrap();
    assert_eq!(canonical.canonical_kind, EventKind::MessageCreate.as_str());
    assert!(registry.canonicalize("message_create").is_err());
    assert!(registry.canonicalize("ak.task.move").is_err());
    assert!(registry.canonicalize("ak.relation.move").is_err());
    assert_eq!(registry.kinds().count(), EventKind::ALL.len());
}

#[test]
fn event_draft_kind_registry_validates_kind_and_payload_container() {
    let registry = EventDraftKindRegistry::default();
    let envelope: OperationEnvelope = serde_json::from_value(json!({
        "operation_id": "ak:operation:01904100-0000-7000-8000-0198d483044c",
        "scope_ref": scope_ref(),
        "actor_id": {
            "kind": "service",
            "service_id": "ak:did_core:webvh:z6mkfixture"
        },
        "kind": EventKind::MessageCreate,
        "causal": {
            "deps": [],
            "hlc": "01970e589d21-0004-a13f9c2e",
            "actor_seq": 1
        },
        "payload": {
            "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hello"}
        },
        "proofs": []
    }))
    .unwrap();

    let validation = registry.validate_envelope(&envelope).unwrap();
    assert_eq!(validation.canonical_kind, EventKind::MessageCreate.as_str());
    let mut scalar_value = serde_json::to_value(envelope).unwrap();
    scalar_value["payload"] = json!("not an object");
    let scalar_payload: OperationEnvelope = serde_json::from_value(scalar_value).unwrap();
    assert!(registry.validate_envelope(&scalar_payload).is_err());
}

#[test]
fn operation_envelope_builder_derives_kind_from_typed_payload() {
    let registry = EventDraftKindRegistry::default();
    let payload = MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "discussion",
        ContentBlock::text("hello"),
    );
    let builder = OperationEnvelopeBuilder::<event_spec::MessageCreate>::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-76b2a3b35ad0").unwrap(),
        scope_ref(),
        arkret_wire::ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
        ),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        payload,
    );

    let envelope = builder.build(&registry).unwrap();
    assert_eq!(envelope.kind(), &EventKind::MessageCreate);
}

#[test]
fn event_draft_kind_conformance_vectors_cover_every_registered_event_kind() {
    let vectors = event_draft_kind_conformance_vectors();
    assert_eq!(vectors.len(), EventKind::ALL.len());
    for kind in EventKind::ALL {
        assert!(vectors.iter().any(|vector| {
            vector.input_kind == kind.as_str() && vector.canonical_kind == kind.as_str()
        }));
    }
}
