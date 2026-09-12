//! Registered-cell reads replay real content-bound Event/Seal history. The
//! checkpoint is already trusted: signature cryptography belongs to checkpoint
//! admission, while these tests exercise reducer roots and accepted-cut selection.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_identifiers::TrustDomainId;
use arkret_models_collaboration::events_payloads::{
    RealmCreatePayload, RealmGenesis, RealmPurpose,
};
use arkret_state::mls_governance_proof::{
    MlsGovernanceVerificationCheckpoint,
    materialize_registered_cell_value_at_basis_from_verified_checkpoint,
    materialize_registered_cell_value_from_verified_checkpoint,
    membership_from_verified_checkpoint,
};
use arkret_state::{
    GovernanceView, MemoryCellStateRegistry, ResolvedCellState, SequencedStateValue,
    StateModelKind, compute_state_root,
};
use arkret_wire::base64url::base64url_encode;
use arkret_wire::{
    CanonicalCellState, CanonicalSequencedState, CellFamilyId, CellRef, CommandResultEffect,
    DidCoreId, EncryptionProfile, Event, EventCellExecution, EventCellValueShape, EventKind,
    GenesisSalt, Hash, Hlc, LatticeOp, LatticeOpType, NotarySignerDescriptor, NotaryValue,
    ProducerEventProof, ProjectedCellWrite, ProjectedOp, ScopeRef, Seal, SealBasis,
    SealCommandOutcome, SealId, SealSignature, SecurityClass,
};
use serde_json::json;

const SUITE: DigestSuite = DigestSuite::Sha256;

fn cell(family: &str) -> CellRef {
    CellRef::new(arkret_wire::null_subject_cell(family)).unwrap()
}

fn member_cell(event: &Event) -> CellRef {
    let subject =
        arkret_wire::cell::composite_subject(&[event.actor_id.canonical_key().unwrap()]).unwrap();
    CellRef::new(arkret_wire::cell::subject_cell(
        CellFamilyId::MEMBER_STATE_V1,
        &subject,
    ))
    .unwrap()
}

fn digest(event: &Event) -> Hash {
    Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap()).unwrap()
}

fn projection(
    event: &Event,
    _: DigestSuite,
    _: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<arkret_state::ControlProjection, String> {
    let mut membership = LatticeOp::empty();
    membership.op_type = LatticeOpType::Transition;
    let is_create = event.kind == EventKind::RealmCreate;
    membership.from = Some(json!(if is_create { "leave" } else { "join" }));
    membership.to = Some(json!(if is_create { "join" } else { "leave" }));
    let mut writes = vec![ProjectedCellWrite {
        cell_id: member_cell(event),
        op: ProjectedOp::Direct(membership),
    }];
    if is_create {
        for (family, value) in [
            (
                CellFamilyId::NOTARY_V1,
                event.payload["object"]["notary"].clone(),
            ),
            (CellFamilyId::REALM_DIGEST_SUITE_V1, json!("sha256")),
        ] {
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Set;
            op.value = Some(value);
            writes.push(ProjectedCellWrite {
                cell_id: cell(family),
                op: ProjectedOp::Direct(op),
            });
        }
    }
    Ok(arkret_state::ControlProjection {
        writes,
        security_reads: Vec::new(),
    })
}

fn registry() -> MemoryCellStateRegistry {
    let mut registry = MemoryCellStateRegistry::empty();
    for family in [
        CellFamilyId::MEMBER_STATE_V1,
        CellFamilyId::NOTARY_V1,
        CellFamilyId::REALM_DIGEST_SUITE_V1,
    ] {
        registry.register(
            family,
            EventCellExecution::Security,
            StateModelKind::SequencedState,
            EventCellValueShape::Register,
            None,
        );
    }
    registry
        .register_domain_transition(
            CellFamilyId::MEMBER_STATE_V1,
            Some(json!("leave")),
            vec![
                (json!("leave"), json!("join")),
                (json!("join"), json!("leave")),
            ],
        )
        .unwrap();
    registry
}

fn attach_proof(event: &mut Event, descriptor: &NotarySignerDescriptor) {
    let evidence = Hash::new(arkret_canonical::sha256_digest(b"accepted-signer-evidence")).unwrap();
    event.proofs = vec![ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: descriptor.verification_method.clone(),
        event_digest: digest(event),
        signer_resolution_evidence_ref: if event.kind == EventKind::RealmCreate {
            None
        } else {
            Some(
                arkret_wire::SignerEvidenceRef::new(format!("ak:signer_evidence:{evidence}"))
                    .unwrap(),
            )
        },
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: format!("eyJhbGciOiJFZDI1NTE5In0..{}", base64url_encode([0; 64])),
    }];
}

fn seal(
    predecessor: Option<&Seal>,
    event: &Event,
    covered_events: &[Event],
    state: &BTreeMap<CellRef, ResolvedCellState>,
    descriptor: &NotarySignerDescriptor,
) -> Seal {
    let covered = covered_events.iter().map(digest).collect::<BTreeSet<_>>();
    let touched = projection(event, SUITE, state)
        .unwrap()
        .writes
        .into_iter()
        .map(|write| write.cell_id)
        .collect::<BTreeSet<_>>();
    let effects = state
        .iter()
        .filter(|(cell, _)| touched.contains(*cell))
        .map(|(cell_id, state)| {
            let ResolvedCellState::Sequenced(state) = state else {
                panic!("governance state must be sequenced")
            };
            CommandResultEffect {
                cell_id: cell_id.clone(),
                state: CanonicalCellState::SequencedState(CanonicalSequencedState {
                    revision_event_id: state.revision_event_id.clone(),
                    value: state.value.clone(),
                }),
            }
        })
        .collect();
    let event_digest = digest(event);
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32))).unwrap(),
        realm_id: event.realm_id.clone(),
        predecessor_ref: predecessor.map(|seal| seal.id.clone()),
        delta: vec![event_digest.clone()],
        control_event_set_root: arkret_state::control_event_set_root(&covered, SUITE).unwrap(),
        state_root: compute_state_root(GovernanceView::new(state), SUITE).unwrap(),
        notary_seq: u64::from(predecessor.is_some()),
        availability_receipt_digests: Vec::new(),
        covered_event_digests: covered.into_iter().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: SealSignature {
            verification_method: descriptor.verification_method.clone(),
            payload_digest: Hash::new(arkret_canonical::sha256_digest(b"placeholder")).unwrap(),
            jws: format!("e30..{}", base64url_encode([0; 64])),
        },
        sealed_at: event.created_at,
        hlc: event.hlc.clone().unwrap(),
        configuration_ref: event.event_id.clone(),
        command_results: vec![
            SealCommandOutcome::committed(event_digest.clone(), vec![event_digest], effects, SUITE)
                .unwrap(),
        ],
        authorization_closures: Vec::new(),
        existence_anchors: Vec::new(),
    };
    let body = seal.canonical_bytes_for_id().unwrap();
    seal.id = Seal::id_from_canonical_bytes(&body, SUITE).unwrap();
    let protected = base64url_encode(
        arkret_canonical::canonical_json_value_bytes(&json!({
            "alg": "Ed25519", "kid": descriptor.verification_method,
        }))
        .unwrap(),
    );
    let transcript = seal.commit_transcript_bytes(SUITE).unwrap();
    seal.notary_signature = SealSignature {
        verification_method: descriptor.verification_method.clone(),
        payload_digest: Hash::new(arkret_canonical::digest(SUITE, transcript)).unwrap(),
        jws: format!("{protected}..{}", base64url_encode([0; 64])),
    };
    seal
}

fn checkpoint() -> (MlsGovernanceVerificationCheckpoint, SealBasis, CellRef) {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/history-key-recovery-fixture.json")
            .unwrap();
    let descriptor: NotarySignerDescriptor = serde_json::from_value(
        fixture["direct_traversal_replay_kat"]["signing_inputs"]["historical_descriptor"].clone(),
    )
    .unwrap();
    descriptor.validate().unwrap();
    let notary = NotaryValue::new(descriptor.clone(), 0).unwrap();
    let genesis = RealmGenesis::event_derived(
        RealmPurpose::Collaboration,
        GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        TrustDomainId::new("ak:trust_domain:checkpoint.example").unwrap(),
        vec![arkret_wire::SchemaId::REALM_V1.to_owned()],
        arkret_wire::CORE_REDUCER_PROFILE,
        SUITE,
        SecurityClass::Standard,
        EncryptionProfile::MlsRfc9420,
        notary.clone(),
    )
    .unwrap();
    let principal = DidCoreId::new("ak:did_core:web:replay-kat.example").unwrap();
    let station = DidCoreId::new("ak:did_core:web:checkpoint-station.example").unwrap();
    let created_at = "2026-08-31T12:00:00.000Z".parse().unwrap();
    let mut create = arkret_wire::test_support::raw_event_at(
        EventKind::RealmCreate.to_string(),
        ScopeRef::RealmGenesis,
        principal.clone(),
        station.clone(),
        0,
        Hlc::new("0198d35d9800-0000-a13f9c2e").unwrap(),
        RealmCreatePayload::new(genesis).to_value().unwrap(),
        created_at,
    )
    .unwrap();
    attach_proof(&mut create, &descriptor);
    let membership_cell = member_cell(&create);
    let mut state = BTreeMap::from([
        (
            cell(CellFamilyId::NOTARY_V1),
            ResolvedCellState::Sequenced(SequencedStateValue {
                revision_event_id: create.event_id.clone(),
                value: serde_json::to_value(notary).unwrap(),
            }),
        ),
        (
            cell(CellFamilyId::REALM_DIGEST_SUITE_V1),
            ResolvedCellState::Sequenced(SequencedStateValue {
                revision_event_id: create.event_id.clone(),
                value: json!("sha256"),
            }),
        ),
        (
            membership_cell.clone(),
            ResolvedCellState::Sequenced(SequencedStateValue {
                revision_event_id: create.event_id.clone(),
                value: json!("join"),
            }),
        ),
    ]);
    let genesis_seal = seal(
        None,
        &create,
        std::slice::from_ref(&create),
        &state,
        &descriptor,
    );
    let historical = SealBasis {
        leaves: vec![genesis_seal.id.clone()],
    };
    let mut leave = arkret_wire::test_support::raw_event_at(
        EventKind::MemberState.to_string(),
        ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        principal,
        station,
        1,
        Hlc::new("0198d35d9800-0001-a13f9c2e").unwrap(),
        json!({"realm_id": create.realm_id, "member_id": create.actor_id, "membership": "leave"}),
        created_at,
    )
    .unwrap();
    leave.prev_refs = vec![create.event_id.clone()];
    leave.seal_basis = Some(historical.clone());
    leave
        .refresh_content_bound_identity_with_digest_suite(SUITE)
        .unwrap();
    attach_proof(&mut leave, &descriptor);
    state.insert(
        membership_cell.clone(),
        ResolvedCellState::Sequenced(SequencedStateValue {
            revision_event_id: leave.event_id.clone(),
            value: json!("leave"),
        }),
    );
    let successor = seal(
        Some(&genesis_seal),
        &leave,
        &[create.clone(), leave.clone()],
        &state,
        &descriptor,
    );
    let checkpoint = MlsGovernanceVerificationCheckpoint {
        realm_id: create.realm_id.clone(),
        basis: SealBasis {
            leaves: vec![successor.id.clone()],
        },
        live_digest_suite: SUITE,
        accepted_seals: vec![successor, genesis_seal],
        accepted_events: vec![leave, create],
        governance_dependencies: Vec::new(),
    };
    checkpoint.validate_checkpoint().unwrap();
    (checkpoint, historical, membership_cell)
}

#[tokio::test]
async fn membership_uses_the_exact_cut_and_does_not_require_mls_lineage() {
    let (mut checkpoint, historical, _) = checkpoint();
    let actor = checkpoint.accepted_events[0].actor_id.clone();
    let scope = arkret_wire::HistoryEffectiveScope::Realm {
        realm_id: checkpoint.realm_id.clone(),
    };
    assert!(
        membership_from_verified_checkpoint(&checkpoint, &scope, &actor, &registry(), projection)
            .await
            .is_err()
    );

    checkpoint.basis = historical;
    checkpoint
        .accepted_seals
        .retain(|seal| checkpoint.basis.leaves.contains(&seal.id));
    checkpoint
        .accepted_events
        .retain(|event| event.kind == EventKind::RealmCreate);
    let member =
        membership_from_verified_checkpoint(&checkpoint, &scope, &actor, &registry(), projection)
            .await
            .unwrap();
    assert_eq!(
        member.incarnation(),
        &arkret_models_collaboration::history_key::AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref: checkpoint.accepted_events[0].event_id.clone(),
        }
    );
    assert_eq!(
        arkret_state::mls_governance_proof::member_history_from_verified_checkpoint(
            &checkpoint,
            &scope,
            &actor,
            &registry(),
            projection,
        )
        .await
        .unwrap()
        .1,
        None
    );

    let other = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:replay-kat.example").unwrap(),
        DidCoreId::new("ak:did_core:web:another-station.example").unwrap(),
    ));
    assert!(
        membership_from_verified_checkpoint(&checkpoint, &scope, &other, &registry(), projection)
            .await
            .is_err()
    );
    let other_scope = arkret_wire::HistoryEffectiveScope::Realm {
        realm_id: arkret_wire::RealmId::new(
            "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
        )
        .unwrap(),
    };
    assert!(
        membership_from_verified_checkpoint(
            &checkpoint,
            &other_scope,
            &actor,
            &registry(),
            projection
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn registered_cell_reads_historical_join_and_current_leave_from_one_checkpoint() {
    let (checkpoint, historical, cell) = checkpoint();
    let registry = registry();
    assert_eq!(
        materialize_registered_cell_value_at_basis_from_verified_checkpoint(
            &checkpoint,
            &historical,
            &cell,
            &registry,
            projection,
        )
        .await
        .unwrap(),
        json!("join"),
    );
    assert_eq!(
        materialize_registered_cell_value_at_basis_from_verified_checkpoint(
            &checkpoint,
            &checkpoint.basis,
            &cell,
            &registry,
            projection,
        )
        .await
        .unwrap(),
        json!("leave"),
    );
    assert_eq!(
        materialize_registered_cell_value_from_verified_checkpoint(
            &checkpoint,
            &cell,
            &registry,
            projection,
        )
        .await
        .unwrap(),
        json!("leave"),
    );
}

#[tokio::test]
async fn registered_cell_rejects_unknown_seal_even_beside_an_accepted_leaf() {
    let (checkpoint, historical, cell) = checkpoint();
    let unknown = SealId::new(format!("ak:seal:sha256:{}", "ff".repeat(32))).unwrap();
    for leaves in [
        vec![unknown.clone()],
        vec![historical.leaves[0].clone(), unknown],
    ] {
        let error = materialize_registered_cell_value_at_basis_from_verified_checkpoint(
            &checkpoint,
            &SealBasis { leaves },
            &cell,
            &registry(),
            projection,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("unverified Seal"), "{error}");
    }
}

#[tokio::test]
async fn registered_cell_does_not_substitute_another_accounts_membership() {
    let (checkpoint, historical, _) = checkpoint();
    let other = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:replay-kat.example").unwrap(),
        DidCoreId::new("ak:did_core:web:another-station.example").unwrap(),
    ));
    let subject = arkret_wire::cell::composite_subject(&[other.canonical_key().unwrap()]).unwrap();
    let other_cell = CellRef::new(arkret_wire::cell::subject_cell(
        CellFamilyId::MEMBER_STATE_V1,
        &subject,
    ))
    .unwrap();
    let error = materialize_registered_cell_value_at_basis_from_verified_checkpoint(
        &checkpoint,
        &historical,
        &other_cell,
        &registry(),
        projection,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("target cell is missing"),
        "{error}"
    );
}

#[tokio::test]
async fn seal_commit_keeps_all_views_unchanged_when_a_late_validation_fails() {
    use arkret_state::state_model::ordered_log::IssuedOp;
    use arkret_state::{
        CellStore, ControlEventStore, MemoryCellStore, MemoryControlEventStore,
        MemorySealCommitStore, MemorySealStore, SealCommitStore, SealStore, StateWrite,
    };

    let (checkpoint, _, membership) = checkpoint();
    let genesis = checkpoint
        .accepted_seals
        .iter()
        .find(|seal| seal.predecessor_ref.is_none())
        .unwrap();
    let event = checkpoint
        .accepted_events
        .iter()
        .find(|event| event.kind == EventKind::RealmCreate)
        .unwrap();
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    events
        .insert_verified_replay_event_with_digest_suite(event, SUITE)
        .unwrap();
    events.register_verified_replay_units(genesis).unwrap();
    let commit = MemorySealCommitStore::new(&events, &seals, &cells);
    let mut op = LatticeOp::empty();
    op.op_type = LatticeOpType::Transition;
    op.from = Some(json!("leave"));
    op.to = Some(json!("join"));
    let writes = vec![(
        membership,
        IssuedOp {
            issuer_id: event.actor_id.clone(),
            op: StateWrite::new(event.event_id.clone(), op),
        },
    )];
    let mut invalid = genesis.clone();
    invalid.id = SealId::new(format!("ak:seal:sha256:{}", "ff".repeat(32))).unwrap();
    assert!(commit.commit_seal(&invalid, &writes, SUITE).await.is_err());
    assert_eq!(
        seals.confirmed_head(&checkpoint.realm_id).await.unwrap(),
        None
    );
    assert!(
        cells
            .list_cells(&checkpoint.realm_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        events
            .covering_seals(&digest(event))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(commit.commit_seal(genesis, &writes, SUITE).await.unwrap());
    assert_eq!(
        seals.confirmed_head(&checkpoint.realm_id).await.unwrap(),
        Some(genesis.id.clone())
    );
    assert_eq!(
        cells.list_cells(&checkpoint.realm_id).await.unwrap().len(),
        1
    );
    assert_eq!(
        events.covering_seals(&digest(event)).await.unwrap().len(),
        1
    );
    assert!(commit.commit_seal(genesis, &writes, SUITE).await.unwrap());
    assert_eq!(
        events.covering_seals(&digest(event)).await.unwrap().len(),
        1
    );
}
