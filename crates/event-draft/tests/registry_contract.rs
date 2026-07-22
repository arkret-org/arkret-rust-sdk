use arkret_event_draft::{
    CausalRef, EventDraftKindRegistry, OperationEnvelope, OperationEnvelopeBuilder,
    event_draft_kind_conformance_vectors, required_fields_for_event_kind,
};
use arkret_wire::{Did, EventKind, Hash, Hlc, OperationId, Proof, RealmId};
use serde_json::json;

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
}

#[test]
fn operation_envelope_uses_spec_fields_and_digest_ignores_proofs() {
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:webvh:z6mkfixture:alice.example#device-1".to_owned(),
        event_digest: Hash::new(
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        )
        .unwrap(),
        created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
        domain: None,
        audience: None,
        jws: "sig-a".to_owned(),
    };
    let envelope = OperationEnvelope {
        operation_id: OperationId::new("ak:operation:01904100-0000-7000-8000-0198d483044c")
            .unwrap(),
        realm_id: realm_id(),
        actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        kind: "ak.message.create".to_owned(),
        target_ref: Some("ak:thread:general".to_owned()),
        causal: CausalRef {
            deps: vec![
                OperationId::new("ak:operation:01904100-0000-7000-8000-5f8278b99124").unwrap(),
            ],
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            actor_seq: 7,
        },
        payload: json!({"body": "hello"}),
        authz_ref: None,
        proofs: vec![proof.clone()],
    };
    let mut different_proof = envelope.clone();
    different_proof.proofs = vec![Proof {
        jws: "sig-b".to_owned(),
        ..proof
    }];

    assert_eq!(
        envelope.operation_digest().unwrap(),
        different_proof.operation_digest().unwrap()
    );
    envelope.validate_for_submit().unwrap();

    let encoded = serde_json::to_value(&envelope).unwrap();
    assert_eq!(encoded["actor_id"], "did:webvh:z6mkfixture:alice.example");
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
    let canonical = registry.canonicalize(EventKind::MESSAGE_CREATE).unwrap();
    assert_eq!(canonical.canonical_kind, EventKind::MESSAGE_CREATE);
    assert!(registry.canonicalize("message_create").is_err());
    assert!(registry.canonicalize("ak.task.move").is_err());
    assert!(registry.canonicalize("ak.relation.move").is_err());
    assert_eq!(registry.kinds().count(), EventKind::ALL.len());
}

#[test]
fn event_draft_kind_registry_rejects_removed_strand_alias_kinds() {
    let registry = EventDraftKindRegistry::default();
    for kind in [
        "ak.subject.create",
        "ak.subject.update",
        "ak.subject.archive",
        "ak.subject.restore",
        "ak.subject.link_surface",
        "ak.subject.unlink_surface",
        "ak.subject.set_primary_surface",
    ] {
        assert!(registry.canonicalize(kind).is_err(), "removed kind: {kind}");
    }
}

#[test]
fn event_draft_kind_registry_drives_envelope_semantics() {
    let registry = EventDraftKindRegistry::default();
    let envelope = OperationEnvelope {
        operation_id: OperationId::new("ak:operation:01904100-0000-7000-8000-0198d483044c")
            .unwrap(),
        realm_id: realm_id(),
        actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        kind: EventKind::MESSAGE_CREATE.to_owned(),
        target_ref: None,
        causal: CausalRef {
            deps: Vec::new(),
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            actor_seq: 1,
        },
        payload: json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }),
        authz_ref: None,
        proofs: Vec::new(),
    };

    let validation = registry.validate_envelope(&envelope).unwrap();
    assert_eq!(validation.canonical_kind, EventKind::MESSAGE_CREATE);
    let mut missing_strand = envelope;
    missing_strand.payload = json!({"track_name": "discussion"});
    assert!(registry.validate_envelope(&missing_strand).is_err());
}

#[test]
fn operation_envelope_builder_covers_every_registered_event_kind() {
    let registry = EventDraftKindRegistry::default();
    let realm_id = realm_id();
    let actor_id = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let hlc = Hlc::new("01970e589d21-0004-a13f9c2e").unwrap();

    for (index, kind) in EventKind::ALL.iter().enumerate() {
        let mut builder = OperationEnvelopeBuilder::new(
            OperationId::new(format!("ak:operation:01904100-0000-7000-8000-{index:012x}")).unwrap(),
            realm_id.clone(),
            actor_id.clone(),
            kind.as_str(),
            index as u64 + 1,
            hlc.clone(),
        );
        for field in required_fields_for_event_kind(kind.as_str()) {
            builder = builder.with_payload_field(field, json!("value"));
        }
        let envelope = builder.build(&registry).unwrap();
        assert_eq!(envelope.kind, kind.as_str());
        registry.validate_envelope(&envelope).unwrap();
    }
}

#[test]
fn operation_envelope_builder_requires_registered_kind_and_payload_fields() {
    let registry = EventDraftKindRegistry::default();
    let builder = OperationEnvelopeBuilder::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-76b2a3b35ad0").unwrap(),
        realm_id(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        EventKind::MESSAGE_CREATE,
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    );

    assert!(builder.clone().build(&registry).is_err());
    let envelope = builder
        .with_payload_field(
            "strand_id",
            json!("ak:strand:01904100-0000-7000-8000-6c663fa0205f"),
        )
        .with_payload_field("track_name", json!("discussion"))
        .build(&registry)
        .unwrap();
    assert_eq!(envelope.kind, EventKind::MESSAGE_CREATE);

    let unknown = OperationEnvelopeBuilder::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-e9d434a97fb1").unwrap(),
        realm_id(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        "unknown",
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    );
    assert!(unknown.build(&registry).is_err());
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
