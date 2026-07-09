use std::collections::BTreeMap;

use serde_json::json;

use super::super::*;
use super::test_realm_id;

#[test]
fn event_new_sets_required_event_id() {
    let event = Event::new(
        "ak.message.create",
        test_realm_id(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    assert!(event.event_id.as_str().starts_with("ak:event:"));
}

#[test]
fn event_digest_uses_canonical_payload_without_proofs_or_unsigned() {
    let event = Event {
        event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
        kind: "ak.message.create".into(),
        realm_id: test_realm_id(),
        actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        actor_seq: 1,
        created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
        hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        prev_refs: Vec::new(),
        effective_scope: None,
        refs: Vec::new(),
        preconditions: Vec::new(),
        effects: Vec::new(),
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        payload: json!({ "body": "hello" }),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: BTreeMap::from([("local_receive_time".to_owned(), json!("ignored"))]),
        proofs: Vec::new(),
    };

    assert_eq!(
        event.event_digest().unwrap(),
        "sha256:09cc279fa161b58434e5ad6cad100b9aa7ecb3395d07941f90d70431cb2b8332"
    );

    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(value["payload"]["body"], "hello");
    assert!(value.get("content").is_none());
}

#[test]
fn prev_frontier_digest_sorts_and_deduplicates_refs() {
    let refs_a = [
        "ak:event:01904100-0000-7000-8000-000000000003",
        "ak:event:01904100-0000-7000-8000-000000000001",
        "ak:event:01904100-0000-7000-8000-000000000003",
        "ak:event:01904100-0000-7000-8000-000000000002",
    ];
    let refs_b = [
        "ak:event:01904100-0000-7000-8000-000000000001",
        "ak:event:01904100-0000-7000-8000-000000000002",
        "ak:event:01904100-0000-7000-8000-000000000003",
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
    assert_eq!(MAX_DELEGATION_CHAIN_DEPTH, 4);
    assert_eq!(MAX_DELEGATION_CONTROL_DEPTH, 4);
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

    validate_delegation_chain_depth(MAX_DELEGATION_CHAIN_DEPTH).unwrap();
    assert!(validate_delegation_chain_depth(MAX_DELEGATION_CHAIN_DEPTH + 1).is_err());

    validate_delegation_control_depth(MAX_DELEGATION_CONTROL_DEPTH).unwrap();
    assert!(validate_delegation_control_depth(MAX_DELEGATION_CONTROL_DEPTH + 1).is_err());

    let prev_refs = (0..MAX_EVENT_PREV_REFS)
        .map(|index| format!("ak:event:01904100-0000-7000-8000-{index:012x}"))
        .collect::<Vec<_>>();
    validate_event_prev_refs(prev_refs.iter().map(String::as_str)).unwrap();
    let mut duplicate = prev_refs;
    duplicate.push(duplicate[0].clone());
    assert!(validate_event_prev_refs(duplicate.iter().map(String::as_str)).is_err());
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
        created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
        domain: None,
        audience: None,
        jws: "sig-a".to_owned(),
    };
    let envelope = OperationEnvelope {
        operation_id: OperationId::new("ak:operation:01904100-0000-7000-8000-0198d483044c")
            .unwrap(),
        realm_id: test_realm_id(),
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
fn operation_kind_registry_accepts_only_canonical_kinds() {
    let registry = OperationKindRegistry::default();

    let canonical = registry.canonicalize(OP_MESSAGE_CREATE).unwrap();
    assert_eq!(canonical.canonical_kind, OP_MESSAGE_CREATE);

    assert!(registry.canonicalize("message_create").is_err());
    assert!(registry.canonicalize("cx.task.move").is_err());
    assert!(registry.canonicalize("cx.relation.move").is_err());
    assert!(registry.kinds().count() >= BUILT_IN_OPERATION_KINDS.len());
}

#[test]
fn operation_kind_registry_rejects_removed_strand_alias_kinds() {
    let registry = OperationKindRegistry::default();
    for kind in [
        "cx.subject.create",
        "cx.subject.update",
        "cx.subject.archive",
        "cx.subject.restore",
        "cx.subject.link_surface",
        "cx.subject.unlink_surface",
        "cx.subject.set_primary_surface",
    ] {
        assert!(
            registry.canonicalize(kind).is_err(),
            "removed kind should not be canonical: {kind}"
        );
    }
}

#[test]
fn operation_kind_registry_drives_envelope_semantics() {
    let registry = OperationKindRegistry::default();
    let envelope = OperationEnvelope {
        operation_id: OperationId::new("ak:operation:01904100-0000-7000-8000-0198d483044c")
            .unwrap(),
        realm_id: test_realm_id(),
        actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        kind: OP_MESSAGE_CREATE.to_owned(),
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
    assert_eq!(validation.canonical_kind, OP_MESSAGE_CREATE);

    let mut missing_strand = envelope;
    missing_strand.payload = json!({"track_name": "discussion"});
    assert!(registry.validate_envelope(&missing_strand).is_err());
}

#[test]
fn operation_envelope_builder_covers_every_builtin_kind() {
    let registry = OperationKindRegistry::default();
    let realm_id = test_realm_id();
    let actor_id = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let hlc = Hlc::new("01970e589d21-0004-a13f9c2e").unwrap();

    for (index, kind) in BUILT_IN_OPERATION_KINDS.iter().enumerate() {
        let mut builder = OperationEnvelopeBuilder::new(
            OperationId::new(format!("ak:operation:01904100-0000-7000-8000-{index:012x}")).unwrap(),
            realm_id.clone(),
            actor_id.clone(),
            *kind,
            index as u64 + 1,
            hlc.clone(),
        );
        for field in required_fields_for_operation_kind(kind) {
            builder = builder.with_payload_field(field, json!("value"));
        }
        let envelope = builder.build(&registry).unwrap();
        assert_eq!(envelope.kind, *kind);
        registry.validate_envelope(&envelope).unwrap();
    }
}

#[test]
fn operation_envelope_builder_requires_registered_kind_and_payload_fields() {
    let registry = OperationKindRegistry::default();
    let builder = OperationEnvelopeBuilder::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-76b2a3b35ad0").unwrap(),
        test_realm_id(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        OP_MESSAGE_CREATE,
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
    assert_eq!(envelope.kind, OP_MESSAGE_CREATE);

    let unknown = OperationEnvelopeBuilder::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-e9d434a97fb1").unwrap(),
        test_realm_id(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        "unknown",
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    );
    assert!(unknown.build(&registry).is_err());
}

#[test]
fn operation_kind_conformance_vectors_cover_every_builtin() {
    let vectors = operation_kind_conformance_vectors();
    assert_eq!(vectors.len(), BUILT_IN_OPERATION_KINDS.len());
    for kind in BUILT_IN_OPERATION_KINDS {
        assert!(
            vectors
                .iter()
                .any(|vector| { vector.input_kind == *kind && vector.canonical_kind == *kind })
        );
    }
}
