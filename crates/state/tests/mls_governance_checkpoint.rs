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
    CellState, EventCellBottom, GovernanceView, MemoryCellRegistry, compute_state_root,
};
use arkret_wire::base64url::base64url_encode;
use arkret_wire::{
    CellFamilyId, CellRef, DidCoreId, EncryptionProfile, Event, EventKind, GenesisSalt, Hash, Hlc,
    LatticeOp, LatticeOpType, NotarySig, NotarySignerDescriptor, NotaryValue, ProducerEventProof,
    ProjectedCellWrite, ProjectedOp, ScopeRef, Seal, SealBasis, SealId, SealSignature,
    SecurityClass,
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

fn projection(event: &Event, _: DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> {
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
    Ok(writes)
}

fn registry() -> MemoryCellRegistry {
    let mut registry = MemoryCellRegistry::default();
    registry.register_fsm(
        CellFamilyId::MEMBER_STATE_V1,
        Some(json!("leave")),
        vec![
            (json!("leave"), json!("join")),
            (json!("join"), json!("leave")),
        ],
        EventCellBottom::Reject,
    );
    registry
}

fn attach_proof(event: &mut Event, descriptor: &NotarySignerDescriptor) {
    let evidence = Hash::new(arkret_canonical::sha256_digest(b"accepted-signer-evidence")).unwrap();
    event.proofs = vec![
        ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: descriptor.verification_method.clone(),
            event_digest: digest(event),
            signer_resolution_evidence_ref: Some(
                arkret_wire::SignerEvidenceRef::new(format!("ak:signer_evidence:{evidence}"))
                    .unwrap(),
            ),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: format!("eyJhbGciOiJFZDI1NTE5In0..{}", base64url_encode([0; 64])),
        }
        .into(),
    ];
}

/// The `cas_register` heads this fixture's linear chain ends on.
///
/// Section 6.2.1 gives a CAS cell a `{"heads":[…]}` leaf, so a Seal's declared
/// `state_root` cannot come from the value map alone. Each cell here is written
/// by one chain, so the head is the last covered Event whose projection touches
/// it — the same identity `apply_seal` derives. It asks this fixture's own
/// `projection`, because that is what seeds the notary and digest-suite cells
/// here; the registered projector would find no writer for them.
fn expected_cas_heads(
    covered_events: &[Event],
    state: &BTreeMap<CellRef, CellState>,
) -> arkret_state::CasHeadsByCell {
    let mut out = arkret_state::CasHeadsByCell::new();
    for (cell, cell_state) in state {
        // `fsm` is a causal register too (§9.3.1.5), so it needs its head set
        // here as well; asking only about `cas_register` left every membership
        // cell with a value-shaped leaf the builder no longer produces.
        if !arkret_wire::is_registered_causal_register_cell(cell.as_str()) {
            continue;
        }
        let CellState::Value(value) = cell_state else {
            continue;
        };
        // §9.3.1.7 item 4 reproduced, not copied: a write with a basis replaces
        // the heads it observed, a basis-free anchor write joins them.
        let mut heads: Vec<arkret_state::lattice::cas_register::CasHead> = Vec::new();
        for event in covered_events {
            if !projection(event, SUITE)
                .is_ok_and(|writes| writes.iter().any(|write| &write.cell_id == cell))
            {
                continue;
            }
            if event.seal_basis.is_some() {
                heads.clear();
            }
            heads.push(arkret_state::lattice::cas_register::CasHead {
                move_id: digest(event),
                value: value.clone(),
            });
        }
        heads.sort_by_key(|head| {
            arkret_wire::EventId::from_event_digest(&head.move_id)
                .map(|id| id.token_bytes())
                .unwrap_or([0_u8; 33])
        });
        if !heads.is_empty() {
            out.insert(cell.clone(), heads);
        }
    }
    out
}

fn seal(
    predecessor: Option<&Seal>,
    event: &Event,
    covered_events: &[Event],
    state: &BTreeMap<CellRef, CellState>,
    descriptor: &NotarySignerDescriptor,
) -> Seal {
    let covered = covered_events.iter().map(digest).collect::<BTreeSet<_>>();
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32))).unwrap(),
        realm_id: event.realm_id.clone(),
        predecessor_refs: predecessor
            .map(|seal| vec![seal.id.clone()])
            .unwrap_or_default(),
        delta: vec![digest(event)],
        control_event_set_root: arkret_state::control_event_set_root(&covered, SUITE).unwrap(),
        state_root: compute_state_root(
            GovernanceView::new(state, &expected_cas_heads(covered_events, state)),
            SUITE,
        )
        .unwrap(),
        completeness_root: arkret_state::control_event_completeness_root(
            &covered_events
                .iter()
                .cloned()
                .map(|event| (event, SUITE))
                .collect::<Vec<_>>(),
            &covered,
            SUITE,
        )
        .unwrap(),
        notary_seq: u64::from(predecessor.is_some()),
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: covered.into_iter().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(SealSignature {
            verification_method: descriptor.verification_method.clone(),
            payload_digest: Hash::new(arkret_canonical::sha256_digest(b"placeholder")).unwrap(),
            jws: String::new(),
        }),
        sealed_at: event.created_at,
        hlc: event.hlc.clone().unwrap(),
    };
    let body = seal.canonical_bytes_for_id().unwrap();
    seal.id = Seal::id_from_canonical_bytes(&body, SUITE).unwrap();
    let protected = base64url_encode(
        arkret_canonical::canonical_json_value_bytes(&json!({
            "alg": "Ed25519", "kid": descriptor.verification_method,
        }))
        .unwrap(),
    );
    seal.notary_signature = NotarySig::Single(SealSignature {
        verification_method: descriptor.verification_method.clone(),
        payload_digest: Hash::new(arkret_canonical::digest(SUITE, body)).unwrap(),
        jws: format!("{protected}..{}", base64url_encode([0; 64])),
    });
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
    let notary = NotaryValue::single_signer(descriptor.clone());
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
            CellState::Value(serde_json::to_value(notary).unwrap()),
        ),
        (
            cell(CellFamilyId::REALM_DIGEST_SUITE_V1),
            CellState::Value(json!("sha256")),
        ),
        (membership_cell.clone(), CellState::Value(json!("join"))),
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
    state.insert(membership_cell.clone(), CellState::Value(json!("leave")));
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
        arkret_state::direct_traversal::history_join_epoch_from_verified_membership(
            &checkpoint.accepted_events,
            &member
        )
        .unwrap(),
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
