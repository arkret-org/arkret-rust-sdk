use arkret_event_draft::{
    EventDraftKindRegistry, OperationEnvelopeBuilder, OperationEventConversion,
};
use arkret_identifiers::{DidCoreId, Hlc, OperationId, RealmId};
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{
    Audience, DidUrl, EventKind, Hash, Proof, ProofBindingRequirements, ScopeRef, StrandId,
    event_spec,
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
        )
        .unwrap();
    assert_eq!(event.kind, EventKind::MessageCreate);
    assert_eq!(event.actor_seq, 7);
    assert_eq!(
        serde_json::to_value(&event.payload).unwrap(),
        json!({
            "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
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
