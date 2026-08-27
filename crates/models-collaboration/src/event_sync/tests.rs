use arkret_wire::{
    AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy,
    AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind,
    AuthorizationLease, AuthorizationLeaseId, ControlProposalAckKind, DeviceId, DidKey, DidUrl,
    EventProof, Hash, IngressReceipt, LeaseBasisRef, NotarySig, PayloadProof, PayloadSignature,
    PrincipalServerAdmissionProof, PrincipalServerAdmissionProofKind, ReceiptId, RiskTier,
    ScopeRef, SealSignature,
};
use serde_json::json;

use super::*;

#[test]
fn federation_submit_union_rejects_unknown_unit_kind_without_fallback() {
    let error = serde_json::from_value::<EventsSubmitFederationRequestBody>(json!({
        "unit_kind": "future_unit",
        "events": []
    }))
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported federation submit unit_kind")
    );
}

#[test]
fn realm_actor_frontier_distinguishes_empty_and_seq_zero_histories() {
    let actor_id = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    RealmActorFrontierView::new(
        realm_id.clone(),
        actor_id.clone(),
        0,
        Vec::new(),
        DigestSuite::Sha256,
    )
    .unwrap();
    RealmActorFrontierView::new(
        realm_id.clone(),
        actor_id.clone(),
        1,
        vec![EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()],
        DigestSuite::Sha256,
    )
    .unwrap();

    assert!(
        RealmActorFrontierView::new(realm_id, actor_id, 1, Vec::new(), DigestSuite::Sha256)
            .is_err()
    );
}

#[test]
fn realm_actor_frontier_digest_matches_the_spec_vector() {
    let mut frontier_event_ids = vec![
        EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
        EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap(),
    ];
    frontier_event_ids.sort();
    let frontier = RealmActorFrontierView::new(
        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        43,
        frontier_event_ids,
        DigestSuite::Sha256,
    )
    .unwrap();
    assert_eq!(
        frontier.frontier_digest.as_str(),
        "sha256:cb4775b3b4590faa096cafd34b0dfd9abc77ad02729a451c0fe5dfdee10d5dc1"
    );
}

/// A well-formed reducer-input DataEvent: `ak.message.create` is registered
/// on the data plane, so the envelope must carry `seal_ref` + `auth_context`
/// and no `seal_basis`.
fn event_with_device_proof() -> Event {
    serde_json::from_value(json!({
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind": "ak.message.create",
        "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "scope_ref": {
            "kind": "realm",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        },
        "actor_id": "ak:did_core:web:alice.example",
        "principal_server_id": "ak:did_core:web:ps.example",
        "actor_seq": 1,
        "created_at": "2026-07-21T08:00:00.000Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "prev_refs": [],
        "seal_ref": format!("ak:seal:sha256:{}", "e".repeat(64)),
        "auth_context": {
            "key_id": "device:01904100-0000-7000-8000-000000000002",
            "key_epoch": 1
        },
        "payload": {},
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000002",
            "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "created_at": "2026-07-21T08:00:00.000Z",
            "jws": "header..signature"
        }]
    }))
    .unwrap()
}

fn publication_proof(
    verification_method: &DidUrl,
    payload_digest: Hash,
    created_at: DateTime<Utc>,
) -> PayloadProof {
    PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "a..b".to_owned(),
    }
}

/// Wrap a transported Event in the publication evidence the federation rail
/// now requires: the basis-bound lease that authorized it and the ingress
/// receipt that recorded its first publication inside the lease window.
fn federation_submission(mut event: Event) -> EventFederationSubmission {
    let issued_at: DateTime<Utc> = "2026-07-21T08:00:00.000Z".parse().unwrap();
    let event_digest = Hash::new(
        event
            .event_digest_with_digest_suite(DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.proofs[0].as_producer_mut().unwrap().event_digest = event_digest;
    let producer = event.proofs[0].as_producer().unwrap().clone();
    event.proofs.push(EventProof::PrincipalServerAdmission(
        PrincipalServerAdmissionProof {
            kind: PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
            verification_method: DidUrl::new("did:web:ps.example#key-1").unwrap(),
            event_digest: producer.event_digest.clone(),
            producer_proof_digest: PrincipalServerAdmissionProof::producer_proof_digest(&producer)
                .unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key: DidKey::new("did:key:z6Mkhfixture").unwrap(),
            producer_signer_resolution_evidence_ref: None,
            producer_signer_resolution_evidence_digest: None,
            signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            signer_resolution_evidence_digest: Hash::new(format!("sha256:{}", "11".repeat(32)))
                .unwrap(),
            accepted_at: issued_at,
            jws: "admission..signature".to_owned(),
        },
    ));
    let authority_set_policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: event.scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: "ak:event:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD".to_owned(),
            source_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
            generation_ref: "1".to_owned(),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: "realm_admission".to_owned(),
            issuer_role: AuthoritySetIssuerRole::RealmAdmission,
            allowed_actions: vec![event.kind.as_str().to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method: DidUrl::new("did:web:authority.example#key-1").unwrap(),
            }],
            threshold: 1,
        }],
    };
    let authority_set_ref = AuthoritySetRef {
        authority_set_id: authority_set_policy.authority_set_id.clone(),
        authority_set_digest: authority_set_policy.digest().unwrap(),
    };
    let control_proposal_ack = event
        .seal_basis
        .as_ref()
        .map(|_| control_proposal_ack_for(&event, &authority_set_ref, issued_at));
    let mut authorization_lease = AuthorizationLease {
        authorization_lease_id: AuthorizationLeaseId::new(
            "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
        )
        .unwrap(),
        basis_ref: LeaseBasisRef::Seal(
            SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
        ),
        actor_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
        scope_ref: event.scope_ref.clone(),
        action: event.kind.as_str().to_owned(),
        authorization_rule_id: "realm_admission".to_owned(),
        risk_tier: RiskTier::Low,
        issued_at,
        expires_at: issued_at + chrono::Duration::hours(1),
        authority_set_ref: authority_set_ref.clone(),
        authority_set_policy,
        proofs: Vec::new(),
    };
    let lease_digest = authorization_lease.lease_digest().unwrap();
    authorization_lease.proofs = vec![publication_proof(
        &DidUrl::new("did:web:authority.example#key-1").unwrap(),
        lease_digest,
        issued_at,
    )];

    let mut receipt = IngressReceipt {
        receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-cccccccccccc").unwrap(),
        event_digest: Hash::new(
            event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap(),
        qualified_ingress_id: DidFullId::new("did:web:authority.example").unwrap(),
        received_at: issued_at,
        ingress_frontier: vec![event.event_id.clone()],
        proofs: Vec::new(),
    };
    let receipt_digest = receipt.receipt_digest().unwrap();
    receipt.proofs = vec![publication_proof(
        &DidUrl::new("did:web:authority.example#key-1").unwrap(),
        receipt_digest,
        issued_at,
    )];

    EventFederationSubmission {
        event,
        authorization_lease: Some(authorization_lease),
        ingress_receipts: vec![receipt],
        control_proposal_ack,
        membership_compensation_evidence: None,
    }
}

fn control_proposal_ack_for(
    event: &Event,
    authority_set_ref: &AuthoritySetRef,
    received_at: DateTime<Utc>,
) -> ControlProposalAck {
    let proposal_digest = Hash::new(
        event
            .event_digest_with_digest_suite(DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let authority_set_digest = authority_set_ref.authority_set_digest.clone();
    let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
        realm_id: event.realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at,
        decision_due_at: received_at + chrono::Duration::seconds(30),
        absolute_due_at: received_at + chrono::Duration::seconds(90),
        authority_set_ref: authority_set_digest.clone(),
        signature: PayloadSignature {
            verification_method: DidUrl::new("did:web:authority.example#key-1").unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: received_at,
            jws: "a..b".to_owned(),
        },
    };
    authority_ack.signature.payload_digest = authority_ack.authority_ack_digest().unwrap();
    ControlProposalAck {
        kind: ControlProposalAckKind::SignedAck,
        realm_id: event.realm_id.clone(),
        proposal_digest,
        received_at,
        decision_due_at: received_at + chrono::Duration::seconds(30),
        absolute_due_at: received_at + chrono::Duration::seconds(90),
        defer_count: 0,
        authority_set_ref: authority_set_digest,
        authority_acks: vec![authority_ack],
    }
}

#[test]
fn realm_seal_frontier_distinguishes_protocol_bounds_from_exact_policy() {
    let event = control_move_over(&federation_prerequisite_seal());
    let submission = federation_submission(event.clone());
    let received_at = DateTime::parse_from_rfc3339("2026-07-29T20:57:46.276Z")
        .unwrap()
        .with_timezone(&Utc);
    let ack = control_proposal_ack_for(
        &event,
        &submission
            .authorization_lease
            .as_ref()
            .expect("fixture uses delayed federation")
            .authority_set_ref,
        received_at,
    );
    let health = ControlGovernanceHealth {
        status: ControlGovernanceHealthStatus::Healthy,
        pending_proposals: vec![PendingControlProposal {
            proposal_digest: ack.proposal_digest.clone(),
            current_decision_due_at: ack.decision_due_at,
            absolute_due_at: ack.absolute_due_at,
            defer_count: 0,
            decision_state: ControlProposalDecisionState::Pending,
            fault_reason: None,
            control_proposal_ack: ack,
            decisions: Vec::new(),
        }],
        retained_faults: Vec::new(),
    };
    let frontier = RealmSealFrontierView::new(
        event.realm_id,
        SealBasis {
            leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap()],
        },
        health,
        RealmSealFrontierObservationCoordinate {
            service_id: "ak:did_core:web:server.test".parse().unwrap(),
            sequence: 7,
            observed_at: received_at,
        },
    );

    frontier
        .validate_protocol_bounds()
        .expect("a 30s/90s Realm frontier is inside protocol ceilings");
    frontier
        .validate_with_policy(ControlProposalDecisionPolicy::default())
        .expect("the same frontier matches the effective default Realm policy");
    assert!(
        frontier
            .validate_with_policy(ControlProposalDecisionPolicy::protocol_maximum())
            .is_err(),
        "protocol ceilings must not masquerade as the exact Realm policy"
    );
}

fn federation_request(events: Vec<Event>) -> EventsSubmitFederationBatchRequestBody {
    let realm_id = events[0].realm_id.clone();
    EventsSubmitFederationBatchRequestBody {
        service_binding_ref: FederationServiceBindingRef {
            realm_id,
            realm_policy_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            membership_frontier: Vec::new(),
            delivery_binding_frontier: Vec::new(),
            destination_service_kind: "principal_server".to_owned(),
        },
        events: events.into_iter().map(federation_submission).collect(),
        cba_proof_bundles: Vec::new(),
    }
}

/// Turn the DataEvent fixture into a Control Move: registered control-plane
/// kinds carry `seal_basis` and MUST NOT carry `seal_ref`/`auth_context`.
fn control_move_over(basis_seal: &Seal) -> Event {
    let mut control = event_with_device_proof();
    control.kind = "ak.capability.grant".into();
    control.seal_ref = None;
    control.auth_context = None;
    control.seal_basis = Some(basis_seal.seal_basis());
    control
}

fn federation_prerequisite_seal() -> Seal {
    let hash = |byte: char| Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap();
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap(),
        realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
        predecessor_refs: Vec::new(),
        delta: vec![Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap()],
        control_event_set_root: hash('2'),
        state_root: hash('3'),
        completeness_root: hash('4'),
        notary_seq: 0,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(SealSignature {
            verification_method: DidUrl::new("did:web:notary.example#key-1").unwrap(),
            payload_digest: hash('5'),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }),
        sealed_at: "2026-07-21T08:00:00Z".parse().unwrap(),
        hlc: arkret_wire::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
    };
    seal.id = seal.derive_id(DigestSuite::Sha256).unwrap();
    seal
}

#[test]
fn federation_transport_is_single_realm_and_control_first() {
    let data = event_with_device_proof();
    let mut other_realm = data.clone();
    let foreign_realm =
        RealmId::new("ak:realm:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk").unwrap();
    other_realm.realm_id = foreign_realm.clone();
    // The signed scope has to move with the envelope Realm, otherwise the
    // envelope is rejected for an inconsistent scope before the transport
    // single-Realm rule is ever reached.
    other_realm.scope_ref = ScopeRef::Realm {
        realm_id: foreign_realm,
    };
    assert!(
        federation_request(vec![data.clone(), other_realm])
            .validate_federation_transport(&[DigestSuite::Sha256; 2])
            .is_err()
    );

    let control = control_move_over(&federation_prerequisite_seal());
    assert!(
        federation_request(vec![data, control])
            .validate_federation_transport(&[DigestSuite::Sha256; 2])
            .is_err()
    );
}

#[test]
fn federation_transport_enforces_event_limit_and_header_only_idempotency() {
    let event = event_with_device_proof();
    let mut empty = federation_request(vec![event.clone()]);
    empty.events.clear();
    assert!(empty.validate_federation_transport(&[]).is_err());
    let too_many_suites = vec![DigestSuite::Sha256; MAX_FEDERATED_EVENTS + 1];
    assert!(
        federation_request(vec![event.clone(); MAX_FEDERATED_EVENTS + 1])
            .validate_federation_transport(&too_many_suites)
            .is_err()
    );

    let request = federation_request(vec![event]);
    let value = serde_json::to_value(&request).unwrap();
    assert!(value.get("idempotency_key").is_none());
    let mut value = value;
    value
        .as_object_mut()
        .unwrap()
        .insert("idempotency_key".to_owned(), json!("header-only"));
    assert!(serde_json::from_value::<EventsSubmitFederationBatchRequestBody>(value).is_err());
}

#[test]
fn federation_transport_seal_closure_is_rooted_at_control_basis_leaves() {
    // The federation body no longer carries a bare `seals[]`: CBA
    // prerequisites travel inside `cba_proof_bundles`, and the closure rule
    // is unchanged — every disclosed Seal must be reachable from a
    // transported DataEvent `seal_ref` or Control Move `seal_basis` leaf.
    let seal = federation_prerequisite_seal();
    let control = control_move_over(&seal);

    let mut request = federation_request(vec![control]);
    request.cba_proof_bundles = vec![CbaProofBundle {
        target_seal_ref: seal.id.clone(),
        seals: vec![seal],
        control_moves: Vec::new(),
        inclusion_proofs: Vec::new(),
        availability_proofs: Vec::new(),
    }];
    request
        .validate_federation_transport(&[DigestSuite::Sha256])
        .expect("a Control Event may transport its non-local Seal basis");
}

#[test]
fn federation_transport_rejects_a_seal_no_transported_event_roots() {
    // Same closure rule, negative direction: a bundle whose Seal is not
    // reachable from any transported Event is unrelated disclosure.
    let seal = federation_prerequisite_seal();
    let mut request = federation_request(vec![event_with_device_proof()]);
    request.cba_proof_bundles = vec![CbaProofBundle {
        target_seal_ref: seal.id.clone(),
        seals: vec![seal],
        control_moves: Vec::new(),
        inclusion_proofs: Vec::new(),
        availability_proofs: Vec::new(),
    }];
    let error = request
        .validate_federation_transport(&[DigestSuite::Sha256])
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unrelated to transported Events"),
        "{error}"
    );
}

#[test]
fn federation_transport_requires_publication_evidence_bound_to_each_event() {
    // `events[]` is no longer a bare Event array. Each transported Event
    // travels with the lease that authorized it and at least one ingress
    // receipt binding that exact Event digest inside the lease window.
    let request = federation_request(vec![event_with_device_proof()]);
    request
        .validate_federation_transport(&[DigestSuite::Sha256])
        .expect("an Event with its lease and ingress receipt is transportable");

    let mut without_receipt = request.clone();
    without_receipt.events[0].ingress_receipts.clear();
    assert!(
        without_receipt
            .validate_federation_transport(&[DigestSuite::Sha256])
            .is_err()
    );

    let mut foreign_digest = request.clone();
    foreign_digest.events[0].ingress_receipts[0].event_digest =
        Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
    assert!(
        foreign_digest
            .validate_federation_transport(&[DigestSuite::Sha256])
            .is_err()
    );

    let mut foreign_actor = request;
    foreign_actor.events[0]
        .authorization_lease
        .as_mut()
        .expect("fixture uses delayed federation")
        .actor_id = DidCoreId::new("ak:did_core:web:mallory.example").unwrap();
    assert!(
        foreign_actor
            .validate_federation_transport(&[DigestSuite::Sha256])
            .is_err()
    );
}
