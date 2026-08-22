use arkret_event_draft::{
    EventDraftKindRegistry, OperationEnvelopeBuilder, OperationEventConversion,
    ProjectedEventOperation,
};
use arkret_identifiers::{DidCoreId, Hlc, OperationId, RealmId};
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{
    Audience, DidUrl, EventKind, Hash, OperationKind, ProducerEventProof, ProofBindingRequirements,
    ScopeRef, StrandId, event_spec,
};
use chrono::Utc;
use serde_json::json;

fn test_realm_id() -> RealmId {
    RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
}

fn test_scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: test_realm_id(),
    }
}

fn message_payload() -> MessageCreatePayload {
    MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "discussion",
        ContentBlock::text("hello"),
    )
}

fn projected_event_with_proof(
    actor_id: &str,
    executed_by: Option<&str>,
    verification_method: &str,
) -> ProjectedEventOperation {
    let actor_id = DidCoreId::new(actor_id.to_owned()).unwrap();
    let mut event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        test_scope(),
        actor_id.clone(),
        actor_id,
        7,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({}),
    )
    .unwrap();
    event.executed_by = executed_by.map(|value| DidCoreId::new(value.to_owned()).unwrap());
    event.proofs = vec![
        ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new(verification_method).unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: Utc::now(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "e30..c2ln".to_owned(),
        }
        .into(),
    ];
    ProjectedEventOperation::from_accepted_event(
        OperationId::new("ak:operation:01904100-0000-7000-8000-9c5aa4740641").unwrap(),
        OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
}

#[test]
fn accepted_event_projection_derives_the_ordinary_producer_device() {
    let operation = projected_event_with_proof(
        "ak:did_core:web:alice.example",
        None,
        "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001",
    );

    assert_eq!(
        operation
            .context
            .producer_device_id
            .as_ref()
            .map(|device_id| device_id.as_str()),
        Some("ak:device:01904100-0000-7000-8000-000000000001")
    );
}

#[test]
fn accepted_event_projection_uses_executed_by_as_the_producer_signer() {
    let operation = projected_event_with_proof(
        "ak:did_core:web:alice.example",
        Some("ak:did_core:web:agent.example"),
        "did:web:agent.example#ak:device:01904100-0000-7000-8000-000000000002",
    );

    assert_eq!(
        operation.context.sender.as_str(),
        "ak:did_core:web:alice.example"
    );
    assert_eq!(
        operation
            .context
            .producer_device_id
            .as_ref()
            .map(|device_id| device_id.as_str()),
        Some("ak:device:01904100-0000-7000-8000-000000000002")
    );
}

#[test]
fn accepted_event_projection_does_not_fabricate_or_fallback_a_device() {
    for verification_method in [
        "did:web:bob.example#ak:device:01904100-0000-7000-8000-000000000003",
        "did:web:alice.example#01904100-0000-7000-8000-000000000003",
        "did:example:alice#ak:device:01904100-0000-7000-8000-000000000003",
    ] {
        let operation =
            projected_event_with_proof("ak:did_core:web:alice.example", None, verification_method);
        assert!(operation.context.producer_device_id.is_none());
    }
}

#[test]
fn accepted_event_projection_requires_exactly_one_producer_proof() {
    let actor_id = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let mut event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        test_scope(),
        actor_id.clone(),
        actor_id,
        7,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({}),
    )
    .unwrap();
    let without_proof = ProjectedEventOperation::from_accepted_event(
        OperationId::new("ak:operation:01904100-0000-7000-8000-9c5aa4740642").unwrap(),
        OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert!(without_proof.context.producer_device_id.is_none());

    let proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new(
            "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000004",
        )
        .unwrap(),
        event_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "e30..c2ln".to_owned(),
    };
    event.proofs = vec![proof.clone().into(), proof.into()];
    let with_two_proofs = ProjectedEventOperation::from_accepted_event(
        OperationId::new("ak:operation:01904100-0000-7000-8000-9c5aa4740643").unwrap(),
        OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    assert!(with_two_proofs.context.producer_device_id.is_none());
}

#[test]
fn operation_validate_proof_bindings_with_context_requires_cross_domain_binding() {
    let mut operation = OperationEnvelopeBuilder::<event_spec::MessageCreate>::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-9c5aa4740640").unwrap(),
        test_scope(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
        7,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        message_payload(),
    )
    .build(&EventDraftKindRegistry::default())
    .unwrap();
    let digest = operation.operation_digest().unwrap();
    operation.proofs = vec![ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
        event_digest: Hash::new(digest).unwrap(),
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
        created_at: Utc::now(),
        domain: None,
        audience: Some(Audience::Single(
            "did:webvh:z6mkfixture:service.example".to_owned(),
        )),
        proof_purpose: None,
        jws: "e30..c2ln".to_owned(),
    }];

    let error = operation
        .validate_proof_bindings_with_context(
            Some("ak:trust_domain:example.net".to_owned()),
            Some(Audience::Single(
                "did:webvh:z6mkfixture:service.example".to_owned(),
            )),
            ProofBindingRequirements::cross_domain(),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("proof_binding_missing"),
        "unexpected proof-binding error: {error}"
    );
}

#[test]
fn operation_draft_explicitly_materializes_event_envelope_without_signed_operation_id() {
    let operation = OperationEnvelopeBuilder::<event_spec::MessageCreate>::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-9c5aa474063f").unwrap(),
        test_scope(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
        7,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        message_payload(),
    );

    let event = operation
        .into_event_envelope(
            &EventDraftKindRegistry::default(),
            OperationEventConversion::default(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    assert_eq!(event.kind, EventKind::MessageCreate);
    assert_eq!(event.actor_seq, 7);
    assert_eq!(
        serde_json::to_value(&event.payload).unwrap(),
        json!({
            "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "format": "plain", "body": "hello"}
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
