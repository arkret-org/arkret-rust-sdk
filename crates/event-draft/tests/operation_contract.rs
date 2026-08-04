use arkret_event_draft::{
    EventDraftKindRegistry, Operation, OperationEnvelopeBuilder, OperationEventConversion,
};
use arkret_identifiers::{Did, Hlc, OperationId, RealmId};
use arkret_wire::{Audience, DidUrl, EventKind, Hash, Proof, ProofBindingRequirements, ScopeRef};
use chrono::Utc;
use serde_json::json;

fn test_realm_id() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
}

fn test_scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: test_realm_id(),
    }
}

#[test]
fn operation_serializes_protocol_field_names() {
    let mut operation = Operation::create(
        OperationId::new("ak:operation:01904100-0000-7000-8000-d408d6a2241c").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        "morph",
        json!({"id":"ak:morph:01904100-0000-7000-8000-c12dc98b2948"}),
    );
    operation.object_id = Some("ak:morph:01904100-0000-7000-8000-c12dc98b2948".to_owned());

    let value = serde_json::to_value(operation).unwrap();

    assert_eq!(value["record_kind"], "operation");
    assert!(value.get("type").is_none());
    assert_eq!(value["operation_kind"], "create");
    assert_eq!(
        value["object_id"],
        "ak:morph:01904100-0000-7000-8000-c12dc98b2948"
    );
    assert_eq!(value["object_kind"], "morph");
    assert!(value.get("target_object_id").is_none());
    assert_eq!(value["schema"], Operation::SCHEMA);
}

#[test]
fn operation_validate_proof_bindings_with_context_requires_cross_domain_binding() {
    let mut operation = OperationEnvelopeBuilder::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-9c5aa4740640").unwrap(),
        test_scope(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        EventKind::MESSAGE_CREATE,
        7,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    )
    .with_payload(json!({
        "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": "hello"}
    }))
    .build(&EventDraftKindRegistry::default())
    .unwrap();
    let digest = operation.operation_digest().unwrap();
    operation.proofs = vec![Proof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: Hash::new(digest).unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: Some(Audience::Single(
            "did:webvh:z6mkfixture:service.example".to_owned(),
        )),
        proof_purpose: None,
        jws: "sig".to_owned(),
    }];

    assert!(
        operation
            .validate_proof_bindings_with_context(
                Some("ak:trust_domain:example.net".to_owned()),
                Some(Audience::Single(
                    "did:webvh:z6mkfixture:service.example".to_owned()
                )),
                ProofBindingRequirements::cross_domain(),
            )
            .unwrap_err()
            .to_string()
            .contains("proof_binding_missing")
    );
}

#[test]
fn operation_draft_explicitly_materializes_event_envelope_without_signed_operation_id() {
    let operation = OperationEnvelopeBuilder::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-9c5aa474063f").unwrap(),
        test_scope(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        EventKind::MESSAGE_CREATE,
        7,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    )
    .with_payload(json!({
        "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": "hello"}
    }))
    .build(&EventDraftKindRegistry::default())
    .unwrap();

    let event = operation
        .into_event_envelope(OperationEventConversion::default())
        .unwrap();
    assert_eq!(event.kind, EventKind::MESSAGE_CREATE);
    assert_eq!(event.actor_seq, 7);
    assert_eq!(
        serde_json::to_value(&event.payload).unwrap(),
        json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hello"}
        })
    );
    assert_eq!(
        event.unsigned["local_operation_idempotency_alias"],
        json!("ak:operation:01904100-0000-7000-8000-9c5aa474063f")
    );
    assert!(
        !event
            .digest_payload()
            .unwrap()
            .to_string()
            .contains("local_operation_id")
    );
}
