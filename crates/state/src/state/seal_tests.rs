use arkret_wire::{ActorId, DidCoreId, DidUrl};

/// Attach a fixed issuer to a sealed op. These fixtures exercise
/// non-ordered-log lattices, where the issuer is carried but unused.
fn issued(op: SealedOp) -> IssuedOp {
    IssuedOp {
        issuer_id: ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        ),
        op,
    }
}

use arkret_wire::ProducerEventProof;
use arkret_wire::event_envelope::{EventRef, ScopeRef};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;
use crate::lattice::SealedOp;
use crate::state::store::memory::{
    MemoryCellRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
};
use crate::state::store::{
    AcklessSelfPrincipalIngress, BottomMode, CellStore, ControlEventStore, ControlProposalIngress,
    SealStore, control_event_digest,
};
use crate::{
    Event, EventId, Hlc, LatticeOp, LatticeOpType, NotarySig, Precondition, Predicate, PredicateOp,
    ProjectedOp, SealBasis, SealSignature,
};

const SUITE: arkret_canonical::DigestSuite = arkret_canonical::DigestSuite::Sha256;

/// Models a durable backend that does not expose candidate cell ops until
/// their accepting Seal is committed. PostgreSQL uses this visibility
/// rule so orphaned writes from an interrupted apply cannot enter an
/// effective Realm view.
#[derive(Default)]
struct SealGatedCellStore {
    inner: MemoryCellStore,
}

#[async_trait]
impl CellStore for SealGatedCellStore {
    async fn list_cells(&self, _realm_id: &RealmId) -> crate::state::StoreResult<Vec<CellRef>> {
        Ok(Vec::new())
    }

    async fn sealed_ops_for_cell(
        &self,
        _realm_id: &RealmId,
        _cell: &CellRef,
    ) -> crate::state::StoreResult<Vec<IssuedOp>> {
        Ok(Vec::new())
    }

    async fn sealed_op_batches_for_cell(
        &self,
        _realm_id: &RealmId,
        _cell: &CellRef,
    ) -> crate::state::StoreResult<Vec<(SealId, Vec<IssuedOp>)>> {
        Ok(Vec::new())
    }

    async fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> crate::state::StoreResult<Option<CellState>> {
        self.inner.cached_state(realm_id, cell, view_hash).await
    }

    async fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> crate::state::StoreResult<()> {
        self.inner
            .put_cached_state(realm_id, cell, view_hash, state)
            .await
    }

    async fn append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> crate::state::StoreResult<()> {
        self.inner
            .append_sealed_effects(realm_id, seal, new_ops)
            .await
    }

    async fn rollback_seal(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
    ) -> crate::state::StoreResult<()> {
        self.inner.rollback_seal(realm_id, seal).await
    }
}

#[tokio::test]
async fn live_digest_suite_uses_genesis_until_a_transition_cell_exists() {
    let genesis_cell = CellRef::new(arkret_wire::null_subject_cell(
        arkret_wire::CellFamilyId::REALM_GENESIS_V1,
    ))
    .unwrap();
    let transition_cell = CellRef::new(arkret_wire::null_subject_cell(
        arkret_wire::CellFamilyId::REALM_DIGEST_SUITE_V1,
    ))
    .unwrap();
    let mut state = BTreeMap::from([(
        genesis_cell,
        CellState::Value(json!({"digest_algorithm": "sha256"})),
    )]);

    assert_eq!(live_digest_suite_from_state(&state).unwrap(), SUITE);

    state.insert(
        transition_cell,
        CellState::Value(Value::String("blake3".to_owned())),
    );
    assert_eq!(
        live_digest_suite_from_state(&state).unwrap(),
        arkret_canonical::DigestSuite::Blake3
    );
}

#[tokio::test]
async fn live_digest_suite_fails_closed_without_transition_or_genesis_state() {
    let error = live_digest_suite_from_state(&BTreeMap::new()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("omits both digest-suite and genesis cells")
    );
}

/// The shim these tests use hands `compute_state_root` a values-only view.
///
/// Every state map built here names a non-`cas_register` family; the membership
/// check inside rejects a CAS cell that arrives without its heads, so a test
/// that starts using one fails loudly instead of hashing the wrong preimage.
fn compute_state_root(cells: &BTreeMap<CellRef, CellState>) -> Result<Hash, crate::WireError> {
    super::compute_state_root(GovernanceView::values_only(cells), SUITE)
}

fn control_event_set_root(covered: &BTreeSet<Hash>) -> Result<Hash, SealReject> {
    super::control_event_set_root(covered, SUITE)
}

fn control_event_completeness_root(
    events: &[Event],
    covered: &BTreeSet<Hash>,
) -> Result<Hash, SealReject> {
    let events = events
        .iter()
        .cloned()
        .map(|event| (event, SUITE))
        .collect::<Vec<_>>();
    super::control_event_completeness_root(&events, covered, SUITE)
}

async fn effective_seal_view(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<EffectiveSealView, SealReject> {
    super::effective_seal_view(leaves, realm_id, seals, cells, registry, SUITE).await
}

#[allow(clippy::too_many_arguments)]
async fn verify_recovery_witness(
    event: &Event,
    effects: &[crate::ProjectionEffect],
    realm_id: &RealmId,
    pre_state: &BTreeMap<CellRef, CellState>,
    predecessor_closure: &BTreeSet<SealId>,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<(), ControlMoveReject> {
    super::verify_recovery_witness(
        event,
        effects,
        realm_id,
        pre_state,
        predecessor_closure,
        seals,
        cells,
        registry,
        SUITE,
    )
    .await
}

async fn apply_seal<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<SealEffect, SealReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String> + Copy,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    super::apply_seal_in_context(
        seal,
        events,
        seals,
        cells,
        registry,
        SealDigestSuites::standard(SUITE),
        |event, _| verify_proofs(event),
        |event, _| project_writes(event),
        EventSubmitContext::Standard,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn apply_seal_in_context<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    context: EventSubmitContext,
) -> Result<SealEffect, SealReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String> + Copy,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    super::apply_seal_in_context(
        seal,
        events,
        seals,
        cells,
        registry,
        SealDigestSuites::standard(SUITE),
        |event, _| verify_proofs(event),
        |event, _| project_writes(event),
        context,
    )
    .await
}

fn ackless_ingress() -> ControlProposalIngress {
    ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
        device_id: "ak:device:fixture".to_owned(),
        device_authorize_event_id: "ak:event:fixture".to_owned(),
        device_generation_ref: 1,
        seal_basis_digest: "sha256:fixture".to_owned(),
    })
}

fn raw_genesis_create() -> Event {
    arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.to_string(),
        ScopeRef::RealmGenesis,
        DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps".to_owned()).unwrap(),
        0,
        Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        json!({"object": {"digest_algorithm": "sha256"}}),
        Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
    )
    .unwrap()
}

fn realm() -> RealmId {
    raw_genesis_create().realm_id
}

fn seal_id(byte: u8) -> SealId {
    SealId::new(format!(
        "ak:seal:sha256:{}",
        format!("{byte:02x}").repeat(32)
    ))
    .unwrap()
}

fn move_id(byte: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn member_cell() -> CellRef {
    CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned()).unwrap()
}

/// A Control Move Event. `actor_seq` keeps siblings distinct so each one
/// hashes to its own `event_digest`.
fn control_move(
    actor_seq: u64,
    basis: SealBasis,
    prev_refs: Vec<EventId>,
    refs: Vec<EventRef>,
) -> Event {
    let created_at = Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap();
    let mut event = arkret_wire::test_support::raw_event_at(
        "ak.member.state",
        ScopeRef::Realm { realm_id: realm() },
        DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureps".to_owned()).unwrap(),
        actor_seq,
        Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        json!({"state": "join"}),
        created_at,
    )
    .unwrap();
    event.prev_refs = prev_refs;
    event.refs = refs;
    event.seal_basis = Some(basis);
    event
        .refresh_content_bound_identity_with_digest_suite(SUITE)
        .unwrap();
    event.proofs.push(
        ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#k1").unwrap(),
            event_digest: Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap()).unwrap(),
            signer_resolution_evidence_ref: Some(
                arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
            ),
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
        .into(),
    );
    event
}

fn genesis_create() -> Event {
    let mut event = raw_genesis_create();
    event.proofs.push(
        ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#k1").unwrap(),
            event_digest: Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap()).unwrap(),
            signer_resolution_evidence_ref: Some(
                arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
            ),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
        .into(),
    );
    event
}

fn digest_suite_cell() -> CellRef {
    CellRef::new(arkret_wire::null_subject_cell(
        arkret_wire::CellFamilyId::REALM_DIGEST_SUITE_V1,
    ))
    .unwrap()
}

fn digest_suite_set_op() -> LatticeOp {
    let mut op = LatticeOp::empty();
    op.op_type = LatticeOpType::Set;
    op.value = Some(json!("sha256"));
    op
}

fn state_with_digest_suite(
    extra: impl IntoIterator<Item = (CellRef, CellState)>,
) -> BTreeMap<CellRef, CellState> {
    let mut state = BTreeMap::from([(digest_suite_cell(), CellState::Value(json!("sha256")))]);
    state.extend(extra);
    state
}

fn hash(byte: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn capability_cell() -> CellRef {
    CellRef::new(
            "ak:cell:ak.component.capability.grant.v1:ak:grant:Aam-wkD4GZDuqJ92ccjIGHTOT3JazvV5Z0uaBH7S5eFX"
                .to_owned(),
        )
        .unwrap()
}

fn add_op(tag: &str, marker: &str) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Add,
        tag: Some(tag.to_owned()),
        value: Some(json!({ "marker": marker })),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    }
}

fn dummy_signature() -> SealSignature {
    SealSignature {
        verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#k1").unwrap(),
        payload_digest: hash(0xff),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

fn materialized_seal(id: SealId, covered: Vec<Hash>) -> Seal {
    let seed = u64::from_str_radix(&id.as_str()[15..17], 16).unwrap();
    let covered_set = covered.iter().cloned().collect::<BTreeSet<_>>();
    let mut seal = Seal {
        id,
        realm_id: realm(),
        predecessor_refs: Vec::new(),
        delta: Vec::new(),
        control_event_set_root: control_event_set_root(&covered_set).unwrap(),
        state_root: compute_state_root(&BTreeMap::new()).unwrap(),
        completeness_root: hash(0x33),
        notary_seq: seed,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: covered,
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(dummy_signature()),
        sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
    };
    seal.id = seal.derive_id(SUITE).unwrap();
    seal
}

#[tokio::test]
async fn control_event_set_root_uses_seal_merkle_domain_separation() {
    let mut one = BTreeSet::new();
    one.insert(move_id(0x11));
    let mut leaf_input = vec![0x00];
    leaf_input.extend([0x11; 32]);
    let expected_leaf = canonical::sha256_bytes(&leaf_input);
    assert_eq!(
        control_event_set_root(&one).unwrap().as_str(),
        format!("sha256:{}", hex::encode(expected_leaf))
    );

    let mut two = one;
    two.insert(move_id(0x22));
    let mut right_input = vec![0x00];
    right_input.extend([0x22; 32]);
    let expected_right = canonical::sha256_bytes(&right_input);
    let expected_root =
        canonical::sha256_bytes_from_slices(&[&[0x01], &expected_leaf, &expected_right]);
    assert_eq!(
        control_event_set_root(&two).unwrap().as_str(),
        format!("sha256:{}", hex::encode(expected_root))
    );
}

#[tokio::test]
async fn event_digest_set_inclusion_proof_covers_every_leaf_and_rejects_tampering() {
    let digests = [move_id(0x11), move_id(0x22), move_id(0x33)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let root = event_digest_set_root(&digests, SUITE).unwrap();
    for digest in &digests {
        let proof = event_digest_set_inclusion_proof(&digests, digest, SUITE).unwrap();
        assert!(
            verify_event_digest_set_inclusion_proof(&proof, &root, SUITE).unwrap(),
            "proof must cover {digest}"
        );
        let mut wrong_index = proof.clone();
        wrong_index.leaf_index = (wrong_index.leaf_index + 1) % wrong_index.leaf_count;
        assert!(!verify_event_digest_set_inclusion_proof(&wrong_index, &root, SUITE).unwrap());
    }
}

fn completeness_event(
    event_id: &str,
    actor_id: &str,
    verification_method: &str,
    actor_seq: u64,
) -> Event {
    serde_json::from_value(json!({
        "event_id": event_id,
        "kind": "ak.capability.grant",
        "realm_id": realm(),
        "scope_ref": {"kind": "realm", "realm_id": realm()},
        "actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": actor_id,
                "station_id": "ak:did_core:web:principal.example"
            }
        },
        "actor_seq": actor_seq,
        "created_at": "2026-07-26T00:00:00.000Z",
        "prev_refs": [],
        "payload": {},
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": verification_method,
            "event_digest": format!("sha256:{}", "a".repeat(64)),
            "created_at": "2026-07-26T00:00:00.000Z",
            "jws": "a..b"
        }]
    }))
    .unwrap()
}

#[tokio::test]
async fn completeness_root_is_actor_sequence_enveloped_and_requires_exact_coverage() {
    let alice = completeness_event(
        "ak:event:AR-4MwpAcHt7pmjO-Cab9s-33ymPZefvcpl666_jGxiY",
        "ak:did_core:webvh:z6mkfixturealice",
        "did:webvh:z6mkfixture:alice.example#device-1",
        7,
    );
    let bob = completeness_event(
        "ak:event:AUqzNZlfuL-7z087TbZhKOdYyKUNPAa2o_neyoFRh3o2",
        "ak:did_core:webvh:z6mkfixturebob",
        "did:webvh:z6mkfixture:bob.example#device-1",
        3,
    );
    let covered = [&alice, &bob]
        .into_iter()
        .map(|event| Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap()).unwrap())
        .collect::<BTreeSet<_>>();
    let forward = control_event_completeness_root(&[alice.clone(), bob.clone()], &covered).unwrap();
    let reverse = control_event_completeness_root(&[bob, alice.clone()], &covered).unwrap();
    assert_eq!(forward, reverse);
    assert_ne!(forward, control_event_set_root(&covered).unwrap());
    assert!(control_event_completeness_root(&[alice], &covered).is_err());
}

fn listed(actor_id: &str, actor_seq: u64, byte: u8) -> ListedControlEvent {
    ListedControlEvent {
        actor_id: ActorId::service(DidCoreId::new(actor_id.to_owned()).unwrap()),
        actor_seq,
        event_digest: move_id(byte),
    }
}

#[tokio::test]
async fn genesis_vector_recomputes_independent_seal_roots() {
    let events = [
        listed("ak:did_core:webvh:z6mkfixturealice", 1, 0x11),
        listed("ak:did_core:webvh:z6mkfixturealice", 2, 0x22),
    ];
    let covered = events
        .iter()
        .map(|event| event.event_digest.clone())
        .collect::<BTreeSet<_>>();
    let control = super::control_event_set_root(&covered, SUITE).unwrap();
    let completeness = control_event_completeness_root_from_listed(&events, SUITE).unwrap();
    assert_ne!(control, completeness);
}

#[tokio::test]
async fn predecessor_vector_recomputes_roots_over_the_cumulative_closure() {
    let predecessor = listed("ak:did_core:webvh:z6mkfixturealice", 7, 0x11);
    let successor = listed("ak:did_core:webvh:z6mkfixturealice", 9, 0x22);
    let cumulative = [predecessor, successor.clone()];
    let cumulative_covered = cumulative
        .iter()
        .map(|event| event.event_digest.clone())
        .collect::<BTreeSet<_>>();
    let delta_only = BTreeSet::from([successor.event_digest.clone()]);

    assert_ne!(
        super::control_event_set_root(&cumulative_covered, SUITE).unwrap(),
        super::control_event_set_root(&delta_only, SUITE).unwrap()
    );
    assert_ne!(
        control_event_completeness_root_from_listed(&cumulative, SUITE).unwrap(),
        control_event_completeness_root_from_listed(&[successor], SUITE).unwrap()
    );
}

#[tokio::test]
async fn multi_actor_vector_recomputes_one_completeness_leaf_per_actor() {
    let events = [
        listed("ak:did_core:webvh:z6mkfixturealice", 7, 0x11),
        listed("ak:did_core:webvh:z6mkfixturebob", 3, 0x22),
        listed("ak:did_core:webvh:z6mkfixturealice", 9, 0x33),
    ];
    let reversed = [events[2].clone(), events[1].clone(), events[0].clone()];
    let root = control_event_completeness_root_from_listed(&events, SUITE).unwrap();
    assert_eq!(
        root,
        control_event_completeness_root_from_listed(&reversed, SUITE).unwrap()
    );
    assert_ne!(
        root,
        control_event_completeness_root_from_listed(&events[..2], SUITE).unwrap()
    );
}

#[tokio::test]
async fn effective_state_at_filters_ops_by_seal_coverage() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let realm = realm();
    let cell = capability_cell();
    let move_a = move_id(0xaa);
    let move_b = move_id(0xbb);
    let seal_a = materialized_seal(seal_id(0xa1), vec![move_a.clone()]);
    let seal_b = materialized_seal(seal_id(0xb1), vec![move_b.clone()]);

    cells
        .append_sealed_effects(
            &realm,
            &seal_a.id,
            &[(
                cell.clone(),
                issued(SealedOp::new(move_a, add_op("a", "visible-at-a"))),
            )],
        )
        .await
        .unwrap();
    cells
        .append_sealed_effects(
            &realm,
            &seal_b.id,
            &[(
                cell.clone(),
                issued(SealedOp::new(move_b, add_op("b", "visible-at-b"))),
            )],
        )
        .await
        .unwrap();
    seals.put(&seal_a, SUITE).await.unwrap();
    seals.put(&seal_b, SUITE).await.unwrap();

    let state_a = effective_state_at(
        std::slice::from_ref(&seal_a.id),
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    let value_a = state_a
        .get(&cell)
        .and_then(|state| state.clone().into_value())
        .unwrap();
    assert_eq!(
        value_a,
        json!([{ "tag": "a", "value": { "marker": "visible-at-a" } }])
    );

    let state_b = effective_state_at(
        std::slice::from_ref(&seal_b.id),
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    let value_b = state_b
        .get(&cell)
        .and_then(|state| state.clone().into_value())
        .unwrap();
    assert_eq!(
        value_b,
        json!([{ "tag": "b", "value": { "marker": "visible-at-b" } }])
    );
}

#[tokio::test]
async fn effective_seal_view_is_leaf_order_independent() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let realm = realm();
    let move_a = move_id(0xaa);
    let move_b = move_id(0xbb);
    let seal_a = materialized_seal(seal_id(0xa1), vec![move_a.clone()]);
    let seal_b = materialized_seal(seal_id(0xb1), vec![move_b.clone()]);
    seals.put(&seal_b, SUITE).await.unwrap();
    seals.put(&seal_a, SUITE).await.unwrap();

    let first = effective_seal_view(
        &[seal_b.id.clone(), seal_a.id.clone()],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    let second = effective_seal_view(
        &[seal_a.id.clone(), seal_b.id.clone()],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();

    let mut expected_predecessors = vec![seal_a.id, seal_b.id];
    expected_predecessors.sort();
    assert_eq!(first.predecessor_refs, expected_predecessors);
    assert_eq!(first.covered_event_digests, vec![move_a, move_b]);
    assert_eq!(first.union_proof.len(), 2);
    assert_eq!(first.view_hash, second.view_hash);
    assert_eq!(first.state_root, second.state_root);
}

/// The wire order is `Seal.delta`'s order, and it is *not* apply order.
///
/// Pinned as an inequality on purpose: for two independent Moves apply order
/// is digest-descending and the wire order is ascending, so a service that
/// serves `SealEffect::accepted_event_digests` straight out of the reducer
/// hands a client the reverse of what `Seal.delta` says. Three clients
/// compared exactly that with `!=` against a `seal.delta` clone.
#[tokio::test]
async fn wire_accepted_digests_are_ascending_not_apply_order() {
    let basis = SealBasis {
        leaves: vec![seal_id(0x11)],
    };
    let first = control_move(1, basis.clone(), Vec::new(), Vec::new());
    let second = control_move(2, basis, Vec::new(), Vec::new());
    let apply_order = deterministic_order(vec![
        (control_event_digest(&first, SUITE).unwrap(), first.clone()),
        (
            control_event_digest(&second, SUITE).unwrap(),
            second.clone(),
        ),
    ])
    .into_iter()
    .map(|(digest, _)| digest)
    .collect::<Vec<_>>();

    let effect = SealEffect {
        seal: seal_id(0x22),
        accepted_event_digests: apply_order.clone(),
        post_state_root: move_id(0x33),
    };

    let mut ascending = apply_order.clone();
    ascending.sort();
    assert_eq!(effect.wire_accepted_event_digests(), ascending);
    // Concurrent Moves are applied greatest-digest-first, so the two orders
    // are reverses of each other here.
    assert_ne!(effect.wire_accepted_event_digests(), apply_order);
}

#[tokio::test]
async fn deterministic_order_respects_causality_then_digest_desc() {
    // Digests are content-derived, so the fixture picks the causal edge and
    // then asserts against the digests the Events actually hash to.
    let basis = SealBasis {
        leaves: vec![seal_id(0x11)],
    };
    let first = control_move(1, basis.clone(), Vec::new(), Vec::new());
    let second = control_move(2, basis.clone(), Vec::new(), Vec::new());
    let dependent = control_move(
        3,
        basis,
        Vec::new(),
        vec![EventRef::new(first.event_id.as_str(), "after")],
    );
    let entry = |event: &Event| (control_event_digest(event, SUITE).unwrap(), event.clone());

    let ordered = deterministic_order(vec![entry(&dependent), entry(&second), entry(&first)]);
    let ids: Vec<&str> = ordered
        .iter()
        .map(|(_, event)| event.event_id.as_str())
        .collect();

    // `dependent` cites `first`, so it can only appear once `first` has been
    // emitted; the two independent Moves are ordered by greatest digest.
    assert_eq!(ids[2], dependent.event_id.as_str());
    let (independent_first, independent_second) =
        if entry(&first).0.as_str() > entry(&second).0.as_str() {
            (first.event_id.as_str(), second.event_id.as_str())
        } else {
            (second.event_id.as_str(), first.event_id.as_str())
        };
    assert_eq!(ids[0], independent_first);
    assert_eq!(ids[1], independent_second);
}

#[tokio::test]
async fn deterministic_order_is_input_permutation_independent() {
    let basis = SealBasis {
        leaves: vec![seal_id(0x11)],
    };
    let entries: Vec<(Hash, Event)> = (1..=3)
        .map(|seq| {
            let event = control_move(seq, basis.clone(), Vec::new(), Vec::new());
            (control_event_digest(&event, SUITE).unwrap(), event)
        })
        .collect();
    let mut reversed = entries.clone();
    reversed.reverse();
    assert_eq!(
        deterministic_order(entries)
            .iter()
            .map(|(digest, _)| digest.clone())
            .collect::<Vec<_>>(),
        deterministic_order(reversed)
            .iter()
            .map(|(digest, _)| digest.clone())
            .collect::<Vec<_>>()
    );
}

/// A Seal whose `id` is the hash of its own canonical bytes, so
/// `apply_seal`'s `validate_id` gate passes.
fn signed_seal(
    predecessor_refs: Vec<SealId>,
    delta: Vec<Hash>,
    control_event_set_root: Hash,
    state_root: Hash,
    notary_seq: u64,
) -> Seal {
    let mut seal = Seal {
        id: seal_id(0x00),
        realm_id: realm(),
        predecessor_refs,
        delta,
        control_event_set_root,
        state_root,
        completeness_root: hash(0x33),
        notary_seq,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(dummy_signature()),
        sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
    };
    seal.id = seal.derive_id(SUITE).unwrap();
    seal
}

/// The `cas_register` heads a single-chain fixture ends on.
///
/// Section 6.2.1 gives a CAS cell a `{"heads":[…]}` leaf, so a Seal's declared
/// `state_root` cannot be computed from the value map alone.
///
/// These fixtures write each CAS cell from one linear chain, so the head is the
/// last covered Event whose projection touches it — which is what `apply_seal`
/// will derive from the signed bases. The projector is the fixture's own,
/// because several of these tests install a custom one; asking the registered
/// projector instead would silently find no writer and hand back an empty head
/// set. A fixture that grows a genuine concurrent branch disagrees here and
/// fails, which is the point: this reproduces the expectation rather than
/// copying the pipeline's answer.
fn expected_cas_heads(
    covered_events: &[Event],
    post_state: &BTreeMap<CellRef, CellState>,
    project: impl Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
) -> CasHeadsByCell {
    let mut out = CasHeadsByCell::new();
    for (cell, state) in post_state {
        // `fsm` is a causal register too (§9.3.1.5), so its leaf is the head
        // set as well; asking only about `cas_register` left every `fsm` cell
        // with a value-shaped leaf the pipeline no longer builds.
        if !arkret_wire::is_registered_causal_register_cell(cell.as_str()) {
            continue;
        }
        let CellState::Value(value) = state else {
            continue;
        };
        // Reproduce §9.3.1.7 item 4 rather than take the pipeline's answer: a
        // write supersedes the heads its own signed basis observed, so in these
        // single-chain fixtures a write **with** a basis replaces everything
        // accumulated so far and a basis-free anchor-unit write joins it. Two
        // anchor writes to one cell are therefore two heads — which is what the
        // pipeline derives, and what the old "last writer wins" shortcut hid.
        let mut heads: Vec<crate::lattice::cas_register::CasHead> = Vec::new();
        for event in covered_events {
            if !project(event).is_ok_and(|writes| writes.iter().any(|write| &write.cell_id == cell))
            {
                continue;
            }
            if event.seal_basis.is_some() {
                heads.clear();
            }
            heads.push(crate::lattice::cas_register::CasHead {
                move_id: control_event_digest(event, SUITE).unwrap(),
                value: value.clone(),
            });
        }
        heads.sort_by_key(|head| {
            EventId::from_event_digest(&head.move_id)
                .map(|id| id.token_bytes())
                .unwrap_or([0_u8; 33])
        });
        if !heads.is_empty() {
            out.insert(cell.clone(), heads);
        }
    }
    out
}

fn signed_seal_with_coverage(
    predecessor_refs: Vec<SealId>,
    delta: Vec<Hash>,
    covered_events: &[Event],
    post_state: &BTreeMap<CellRef, CellState>,
    notary_seq: u64,
) -> Seal {
    signed_seal_with_coverage_projected(
        predecessor_refs,
        delta,
        covered_events,
        post_state,
        notary_seq,
        fixture_writes,
    )
}

/// The writes these fixtures attribute to one covered Event.
///
/// `install_genesis` seeds `ak.component.realm.digest_suite.v1` through
/// `genesis_digest_suite_write` rather than the registered contract, so asking
/// the registered projector alone would find no writer for it and leave the
/// cell without the heads its §6.2.1 leaf needs. Both sources are consulted;
/// the genesis one only fires for `ak.realm.create`, so they cannot disagree.
fn fixture_writes(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    let mut writes = arkret_schema::project_registered_cell_writes(event, SUITE)
        .map_err(|error| error.to_string())
        .unwrap_or_default();
    if let Ok(genesis) = genesis_digest_suite_write(event) {
        writes.extend(genesis);
    }
    Ok(writes)
}

/// [`signed_seal_with_coverage`] for a fixture that installs its own projector.
fn signed_seal_with_coverage_projected(
    predecessor_refs: Vec<SealId>,
    delta: Vec<Hash>,
    covered_events: &[Event],
    post_state: &BTreeMap<CellRef, CellState>,
    notary_seq: u64,
    project: impl Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
) -> Seal {
    let covered = covered_events
        .iter()
        .map(|event| control_event_digest(event, SUITE))
        .collect::<Result<BTreeSet<_>, _>>()
        .unwrap();
    let mut seal = signed_seal(
        predecessor_refs,
        delta,
        control_event_set_root(&covered).unwrap(),
        super::compute_state_root(
            GovernanceView::new(
                post_state,
                &expected_cas_heads(covered_events, post_state, project),
            ),
            SUITE,
        )
        .unwrap(),
        notary_seq,
    );
    seal.covered_event_digests = covered.iter().cloned().collect();
    seal.completeness_root = control_event_completeness_root(covered_events, &covered).unwrap();
    seal.id = seal.derive_id(SUITE).unwrap();
    seal
}

/// A fixture projector plus the genesis digest-suite write.
///
/// `install_genesis` seeds `ak.component.realm.digest_suite.v1` outside the
/// registered contract, so a fixture that installs its own projector still owes
/// that cell a writer — otherwise the cell has a value and no head, and §6.2.1
/// cannot build its leaf. `fixture_writes` composes the same two sources for
/// the registered path.
fn with_genesis_digest_suite(
    project: impl Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
) -> impl Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> {
    move |event: &Event| {
        let mut writes = project(event).unwrap_or_default();
        if let Ok(genesis) = genesis_digest_suite_write(event) {
            writes.extend(genesis);
        }
        Ok(writes)
    }
}

fn ok_proofs(_: &Event) -> Result<(), String> {
    Ok(())
}

fn join_transition_write(_: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    let mut op = LatticeOp::empty();
    op.op_type = LatticeOpType::Transition;
    op.from = Some(json!("invited"));
    op.to = Some(json!("join"));
    Ok(vec![ProjectedCellWrite {
        cell_id: member_cell(),
        op: ProjectedOp::Direct(op),
    }])
}

fn genesis_digest_suite_write(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    if event.kind != arkret_wire::EventKind::RealmCreate {
        return Err("only Realm create initializes the digest suite".to_owned());
    }
    Ok(vec![ProjectedCellWrite {
        cell_id: digest_suite_cell(),
        op: ProjectedOp::Direct(digest_suite_set_op()),
    }])
}

fn bootstrap_member_transition_write(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    let mut op = LatticeOp::empty();
    op.op_type = LatticeOpType::Transition;
    let state = if event.actor_seq == 0 {
        ("leave", "join")
    } else {
        ("join", "join")
    };
    op.from = Some(json!(state.0));
    op.to = Some(json!(state.1));
    let mut writes = vec![ProjectedCellWrite {
        cell_id: member_cell(),
        op: ProjectedOp::Direct(op),
    }];
    if event.kind == arkret_wire::EventKind::RealmCreate {
        writes.push(ProjectedCellWrite {
            cell_id: digest_suite_cell(),
            op: ProjectedOp::Direct(digest_suite_set_op()),
        });
    }
    Ok(writes)
}

#[tokio::test]
async fn apply_seal_rejects_an_empty_first_root() {
    let seal = signed_seal(
        Vec::new(),
        Vec::new(),
        control_event_set_root(&BTreeSet::new()).unwrap(),
        compute_state_root(&BTreeMap::new()).unwrap(),
        0,
    );
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::new();
    let error = apply_seal(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        join_transition_write,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("complete non-empty Realm anchor")
    );
}

#[tokio::test]
async fn first_anchor_unit_can_apply_basisless_events_only_in_explicit_context() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .await
        .unwrap();
    let post_state = state_with_digest_suite([]);
    let seal = signed_seal_with_coverage(
        Vec::new(),
        vec![digest.clone()],
        std::slice::from_ref(&event),
        &post_state,
        0,
    );

    let standard_error = apply_seal(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        genesis_digest_suite_write,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        standard_error,
        SealReject::MissingSealBasis { .. } | SealReject::ControlMoveRejected { .. }
    ));

    let effect = apply_seal_in_context(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        genesis_digest_suite_write,
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap();
    assert_eq!(effect.accepted_event_digests, vec![digest]);
    assert_eq!(effect.post_state_root, seal.state_root);
}

#[tokio::test]
async fn prepared_seal_transition_is_store_immutable_until_commit() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .await
        .unwrap();
    let seal = signed_seal_with_coverage(
        Vec::new(),
        vec![digest.clone()],
        std::slice::from_ref(&event),
        &state_with_digest_suite([]),
        0,
    );

    let prepared = prepare_seal_in_context(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        SealDigestSuites::standard(SUITE),
        |event, _| ok_proofs(event),
        |event, _| genesis_digest_suite_write(event),
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap();

    assert_eq!(prepared.effect.accepted_event_digests, vec![digest.clone()]);
    assert_eq!(
        prepared.covered_event_digests,
        [digest.clone()].into_iter().collect()
    );
    assert!(seals.get(&seal.id).await.unwrap().is_none());
    assert!(cells.list_cells(&seal.realm_id).await.unwrap().is_empty());

    let committed = apply_seal_in_context(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        genesis_digest_suite_write,
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap();
    assert_eq!(committed.accepted_event_digests, vec![digest]);
}

#[tokio::test]
async fn seal_rejects_each_independently_recomputed_root_mismatch() {
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    let post_state = state_with_digest_suite([]);
    let valid = signed_seal_with_coverage(
        Vec::new(),
        vec![digest],
        std::slice::from_ref(&event),
        &post_state,
        0,
    );

    for (index, mut seal) in [valid.clone(), valid].into_iter().enumerate() {
        let expected_variant = if index == 0 {
            seal.control_event_set_root = hash(0x91);
            "control"
        } else {
            seal.completeness_root = hash(0x92);
            "completeness"
        };
        seal.id = seal.derive_id(SUITE).unwrap();
        let events = MemoryControlEventStore::default();
        events
            .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
            .await
            .unwrap();
        let error = apply_seal_in_context(
            &seal,
            &events,
            &MemorySealStore::default(),
            &MemoryCellStore::default(),
            &MemoryCellRegistry::default(),
            ok_proofs,
            genesis_digest_suite_write,
            EventSubmitContext::AnchorUnit,
        )
        .await
        .unwrap_err();
        match expected_variant {
            "control" => assert!(matches!(
                error,
                SealReject::ControlEventSetRootMismatch { .. }
            )),
            "completeness" => {
                assert!(matches!(error, SealReject::CompletenessRootMismatch { .. }))
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn apply_seal_validates_candidate_state_before_durable_visibility() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = SealGatedCellStore::default();
    let registry = MemoryCellRegistry::default();
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .await
        .unwrap();
    let post_state = state_with_digest_suite([]);
    let seal = signed_seal_with_coverage(
        Vec::new(),
        vec![digest.clone()],
        std::slice::from_ref(&event),
        &post_state,
        0,
    );

    let effect = apply_seal_in_context(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        genesis_digest_suite_write,
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap();

    assert_eq!(effect.accepted_event_digests, vec![digest.clone()]);
    assert_eq!(effect.post_state_root, seal.state_root);
    let stored = cells
        .inner
        .sealed_ops_for_cell(&realm(), &digest_suite_cell())
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].op.move_id, digest);
}

#[tokio::test]
async fn rejected_anchor_state_root_never_publishes_candidate_cell_ops() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .await
        .unwrap();
    let declared_post_state = state_with_digest_suite([(
        capability_cell(),
        CellState::Value(json!([{"marker": "not-derived"}])),
    )]);
    let seal = signed_seal_with_coverage(
        Vec::new(),
        vec![digest],
        std::slice::from_ref(&event),
        &declared_post_state,
        0,
    );

    let error = apply_seal_in_context(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        genesis_digest_suite_write,
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, SealReject::StateRootMismatch { .. }));
    assert!(cells.list_cells(&realm()).await.unwrap().is_empty());
    assert!(seals.get(&seal.id).await.unwrap().is_none());
}

#[tokio::test]
async fn anchor_unit_stages_create_projection_before_creator_binding_transition() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let mut registry = MemoryCellRegistry::new();
    registry.register_fsm(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        Some(json!("leave")),
        vec![
            (json!("leave"), json!("join")),
            (json!("join"), json!("join")),
        ],
        BottomMode::Reject,
    );
    let create = genesis_create();
    let create_digest = control_event_digest(&create, SUITE).unwrap();
    events
        .put_pending_with_ingress(&create, &ackless_ingress(), SUITE)
        .await
        .unwrap();

    let mut binding = control_move(
        1,
        SealBasis {
            leaves: vec![seal_id(0x01)],
        },
        vec![create.event_id.clone()],
        Vec::new(),
    );
    binding.seal_basis = None;
    binding.preconditions.push(Precondition {
        cell_id: member_cell(),
        predicate: Predicate {
            op: PredicateOp::HeadEq,
            value: Some(json!("join")),
            values: None,
            predicate_id: None,
        },
    });
    binding
        .refresh_content_bound_identity_with_digest_suite(SUITE)
        .unwrap();
    binding.proofs[0].as_producer_mut().unwrap().event_digest =
        Hash::new(binding.event_digest_with_digest_suite(SUITE).unwrap()).unwrap();
    let binding_digest = control_event_digest(&binding, SUITE).unwrap();
    events
        .put_pending_with_ingress(&binding, &ackless_ingress(), SUITE)
        .await
        .unwrap();

    let post_state = state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]);
    // `Seal.delta` is a canonical sorted, duplicate-free list — the staging
    // order the test is about lives in the Seal's covered set, not in this
    // wire field's order.
    let mut delta = vec![create_digest.clone(), binding_digest.clone()];
    delta.sort();
    let seal = signed_seal_with_coverage_projected(
        Vec::new(),
        delta.clone(),
        &[create, binding.clone()],
        &post_state,
        0,
        with_genesis_digest_suite(bootstrap_member_transition_write),
    );

    let effect = apply_seal_in_context(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        bootstrap_member_transition_write,
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap();
    // Acceptance order stays causal (create, then the binding that depends
    // on it) regardless of how `Seal.delta` sorts.
    assert_eq!(
        effect.accepted_event_digests,
        vec![create_digest, binding_digest]
    );
    assert_eq!(effect.post_state_root, seal.state_root);
}

#[tokio::test]
async fn anchor_unit_context_rejects_a_nonempty_predecessor_view() {
    let seal = signed_seal(
        vec![seal_id(0x01)],
        Vec::new(),
        control_event_set_root(&BTreeSet::new()).unwrap(),
        compute_state_root(&BTreeMap::new()).unwrap(),
        1,
    );
    let error = apply_seal_in_context(
        &seal,
        &MemoryControlEventStore::default(),
        &MemorySealStore::default(),
        &MemoryCellStore::default(),
        &MemoryCellRegistry::default(),
        ok_proofs,
        join_transition_write,
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("only valid for the first Seal"));
}

/// Install a fully replayable Genesis Seal and return the basis a
/// successor Control Move must declare.
async fn install_genesis(
    events: &MemoryControlEventStore,
    seals: &MemorySealStore,
    cells: &MemoryCellStore,
    registry: &MemoryCellRegistry,
) -> (Seal, SealBasis, Event, Hash) {
    let create = genesis_create();
    let anchor = control_event_digest(&create, SUITE).unwrap();
    events
        .put_pending_with_ingress(&create, &ackless_ingress(), SUITE)
        .await
        .unwrap();
    let post_state = state_with_digest_suite([]);
    let genesis = signed_seal_with_coverage(
        Vec::new(),
        vec![anchor.clone()],
        std::slice::from_ref(&create),
        &post_state,
        0,
    );
    apply_seal_in_context(
        &genesis,
        events,
        seals,
        cells,
        registry,
        ok_proofs,
        genesis_digest_suite_write,
        EventSubmitContext::AnchorUnit,
    )
    .await
    .unwrap();
    let basis = SealBasis {
        leaves: vec![genesis.id.clone()],
    };
    (genesis, basis, create, anchor)
}

#[tokio::test]
async fn apply_seal_applies_only_projector_derived_writes() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let events = MemoryControlEventStore::default();
    let registry = MemoryCellRegistry::default();
    let (genesis, basis, create, _) = install_genesis(&events, &seals, &cells, &registry).await;

    // The Event names no cell and no lattice op anywhere: the projector is
    // the sole source of the `invited -> join` write applied below.
    let event = control_move(1, basis, Vec::new(), Vec::new());
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .await
        .unwrap();

    let post_state = state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]);
    let seal = signed_seal_with_coverage_projected(
        vec![genesis.id],
        vec![digest.clone()],
        &[create, event.clone()],
        &post_state,
        2,
        with_genesis_digest_suite(join_transition_write),
    );

    let effect = apply_seal(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        join_transition_write,
    )
    .await
    .unwrap();
    assert_eq!(effect.accepted_event_digests, vec![digest.clone()]);
    assert_eq!(effect.post_state_root, seal.state_root);

    let ops = cells
        .sealed_ops_for_cell(&realm(), &member_cell())
        .await
        .unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].op.move_id, digest);
    assert_eq!(ops[0].issuer_id, event.actor_id);
    assert_eq!(events.covering_seals(&digest).await.unwrap(), vec![seal.id]);
}

#[tokio::test]
async fn apply_seal_rejects_a_projection_the_receiver_cannot_evaluate() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let events = MemoryControlEventStore::default();
    let registry = MemoryCellRegistry::default();
    let (genesis, basis, create, _) = install_genesis(&events, &seals, &cells, &registry).await;
    let event = control_move(1, basis, Vec::new(), Vec::new());
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .await
        .unwrap();

    // The declared root is irrelevant to what this pins — the projector below
    // rejects before any root is recomputed — but it still has to be buildable,
    // and §6.2.1 needs a head for the `fsm` cell to build its leaf.
    let seal = signed_seal_with_coverage_projected(
        vec![genesis.id],
        vec![digest],
        &[create, event],
        &state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]),
        2,
        with_genesis_digest_suite(join_transition_write),
    );

    let error = apply_seal(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        |_: &Event| Err("registry declares no contract for this kind".to_owned()),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SealReject::ControlMoveRejected { .. }));
}

#[tokio::test]
async fn seal_basis_leaf_outside_the_predecessor_closure_rejects() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let events = MemoryControlEventStore::default();
    let registry = MemoryCellRegistry::default();
    let (genesis, mut basis, create, _) = install_genesis(&events, &seals, &cells, &registry).await;
    // A concurrent Seal the receiving Seal does not descend from. Admitting
    // it would make acceptance depend on which leaves this receiver happens
    // to hold (§6.3 concurrent-leaf rule).
    basis.leaves = vec![seal_id(0xee)];
    let event = control_move(1, basis, Vec::new(), Vec::new());
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .await
        .unwrap();

    let seal = signed_seal_with_coverage_projected(
        vec![genesis.id],
        vec![digest],
        &[create, event],
        &state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]),
        2,
        with_genesis_digest_suite(join_transition_write),
    );

    let error = apply_seal(
        &seal,
        &events,
        &seals,
        &cells,
        &registry,
        ok_proofs,
        join_transition_write,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SealReject::SealBasisOutsideClosure { .. }));
}

#[tokio::test]
async fn predecessor_seal_closure_is_transitive() {
    let seals = MemorySealStore::default();
    let empty_control_root = control_event_set_root(&BTreeSet::new()).unwrap();
    let empty_state_root = compute_state_root(&BTreeMap::new()).unwrap();
    let genesis = signed_seal(
        Vec::new(),
        Vec::new(),
        empty_control_root.clone(),
        empty_state_root.clone(),
        1,
    );
    let middle = signed_seal(
        vec![genesis.id.clone()],
        Vec::new(),
        empty_control_root,
        empty_state_root,
        2,
    );
    seals.put(&genesis, SUITE).await.unwrap();
    seals.put(&middle, SUITE).await.unwrap();

    let closure = predecessor_seal_closure(std::slice::from_ref(&middle.id), &seals)
        .await
        .unwrap();
    assert_eq!(closure, BTreeSet::from([genesis.id, middle.id]));
}

#[tokio::test]
async fn effective_state_preserves_cross_seal_fsm_order() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let realm = realm();
    let cell =
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap();
    let join_id = move_id(0x01);
    let ban_id = move_id(0xff);
    let seal = materialized_seal(seal_id(0xa1), vec![join_id.clone(), ban_id.clone()]);
    let transition = |from: &str, to: &str| LatticeOp {
        op_type: LatticeOpType::Transition,
        tag: None,
        value: None,
        from: Some(json!(from)),
        to: Some(json!(to)),
        reason: None,
        issuer_seq: None,
    };

    // The order is causal, not positional: the ban write's own verified basis
    // observed the join write, so it supersedes it (§9.3.1.7 item 4). Before
    // §9.3.1.5 this was carried by the two ops' positions in the batch, which
    // is exactly the arrival dependence the algebra removes.
    cells
        .append_sealed_effects(
            &realm,
            &seal.id,
            &[
                (
                    cell.clone(),
                    issued(SealedOp::new(join_id.clone(), transition("invited", "join"))),
                ),
                (
                    cell.clone(),
                    issued(SealedOp::superseding(
                        ban_id,
                        transition("join", "ban"),
                        vec![join_id],
                    )),
                ),
            ],
        )
        .await
        .unwrap();
    seals.put(&seal, SUITE).await.unwrap();

    let state = effective_state_at(
        std::slice::from_ref(&seal.id),
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    assert_eq!(state.get(&cell), Some(&CellState::Value(json!("ban"))));
}

#[tokio::test]
async fn mv_register_seal_batches_distinguish_successors_from_siblings() {
    let cell = CellRef::new(
        "ak:cell:ak.component.profile.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
    )
    .unwrap();
    let set = |id, value| {
        issued(SealedOp::new(
            move_id(id),
            LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(json!(value)),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ))
    };
    let lattice = crate::lattice::MvRegister;

    let sequential = vec![vec![set(1, "open")], vec![set(2, "closed")]];
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &sequential),
        CellState::Value(json!("closed"))
    );

    let siblings = vec![vec![set(3, "open"), set(4, "closed")]];
    assert!(matches!(
        join_cell_seal_batches(&lattice, &cell, &siblings),
        CellState::Bottom(_)
    ));
}

/// A `cas_register` cell is joined over its whole covered history: heads are
/// derived from the identities each write superseded (§9.3.1.1), so truncating
/// to the last Seal batch would resurrect a write whose superseder was cut away.
#[tokio::test]
async fn cas_register_seal_batches_join_the_whole_history() {
    let cell = CellRef::new(
        "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
    )
    .unwrap();
    let set = |id, value: &str, saw: &[u8]| {
        issued(SealedOp::superseding(
            move_id(id),
            LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(json!(value)),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
            saw.iter().copied().map(move_id).collect(),
        ))
    };
    let lattice = crate::lattice::CasRegister;

    let sequential = vec![vec![set(1, "open", &[])], vec![set(2, "closed", &[1])]];
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &sequential),
        CellState::Value(json!("closed"))
    );

    // Dropping the earlier batch would leave op 2 as the only input. It still
    // reads "closed" there, so the assertion that actually pins "the whole
    // history is the input" is that op 1 is *present and superseded*, not
    // absent.
    let heads = crate::lattice::cas_register::cas_heads(
        &sequential
            .iter()
            .flatten()
            .map(|entry| entry.op.clone())
            .collect::<Vec<_>>(),
    )
    .expect("one head");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].move_id, move_id(2));

    let siblings = vec![vec![set(3, "open", &[]), set(4, "closed", &[])]];
    assert!(matches!(
        join_cell_seal_batches(&lattice, &cell, &siblings),
        CellState::Bottom(_)
    ));
}

struct RecoveryWitnessFixture {
    event: Event,
    effects: Vec<crate::ProjectionEffect>,
    pre_state: BTreeMap<CellRef, CellState>,
    predecessor_closure: BTreeSet<SealId>,
    seals: MemorySealStore,
    cells: MemoryCellStore,
    registry: MemoryCellRegistry,
    conflict_a_id: SealId,
    witness_id: SealId,
}

/// §9.5 splits by lattice, so the fixture has to as well.
async fn recovery_witness_fixture() -> RecoveryWitnessFixture {
    recovery_witness_fixture_for(crate::lattice::LatticeKind::CasRegister).await
}

async fn recovery_witness_fixture_for(
    target_lattice: crate::lattice::LatticeKind,
) -> RecoveryWitnessFixture {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let cas = target_lattice == crate::lattice::LatticeKind::CasRegister;
    let target = if cas {
        CellRef::new(
            "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap()
    } else {
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    };
    let grant_id = "ak:grant:Aam-wkD4GZDuqJ92ccjIGHTOT3JazvV5Z0uaBH7S5eFX";
    let target_move = move_id(0x41);
    let grant_move = move_id(0x42);
    let conflict_a_move = move_id(0x51);
    let conflict_b_move = move_id(0x52);
    let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap();
    let target_value = if cas {
        json!({"policy_revision": 7})
    } else {
        json!("join")
    };
    let grant_value = json!({
        "grant_id": grant_id,
        "subject": ActorId::account(arkret_wire::AccountId::new(
            actor,
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps".to_owned()).unwrap()
        )),
        "actions": ["ak.conflict.recovery"],
        "resources": [{"kind": "realm", "realm_id": realm()}]
    });

    let mut target_op = LatticeOp::empty();
    if cas {
        target_op.op_type = LatticeOpType::Set;
        target_op.value = Some(target_value.clone());
    } else {
        target_op.op_type = LatticeOpType::Transition;
        target_op.from = Some(json!("invited"));
        target_op.to = Some(json!("join"));
    }
    // The two writes that actually put the cell in `⊥`. They belong in the cell
    // store, not only in a hand-built `pre_state`: §9.5.1 proves a
    // `cas_register` target's conflict from the Move's *own signed basis*, so a
    // fixture whose store still shows one clean head would be asserting against
    // a divergence that does not exist in any view.
    let conflict_op = |value: Value| {
        let mut op = LatticeOp::empty();
        if cas {
            op.op_type = LatticeOpType::Set;
            op.value = Some(value);
        } else {
            op.op_type = LatticeOpType::Transition;
            op.from = Some(json!("join"));
            op.to = Some(value);
        }
        op
    };
    let mut grant_op = LatticeOp::empty();
    grant_op.op_type = LatticeOpType::Add;
    grant_op.tag = Some(grant_id.to_owned());
    grant_op.value = Some(grant_value.clone());

    let witness_state = BTreeMap::from([
        (target.clone(), CellState::Value(target_value)),
        (
            capability_cell(),
            CellState::Value(json!([{"tag": grant_id, "value": grant_value}])),
        ),
    ]);
    let mut witness =
        materialized_seal(seal_id(0x40), vec![target_move.clone(), grant_move.clone()]);
    witness.delta = vec![target_move.clone(), grant_move.clone()];
    // The witness view's target was written by `target_move`, so that identity
    // is its head (§6.2.1). This holds for `fsm` as well as `cas_register`
    // now that both are causal registers (§9.3.1.5) — before that, an `fsm`
    // target took a value-shaped leaf and needed no head here. The capability
    // cell is an `or_set` and keeps its value leaf either way.
    let witness_heads = CasHeadsByCell::from([(
        target.clone(),
        vec![crate::lattice::cas_register::CasHead {
            move_id: target_move.clone(),
            value: witness_state
                .get(&target)
                .and_then(|state| match state {
                    CellState::Value(value) => Some(value.clone()),
                    CellState::Bottom(_) => None,
                })
                .expect("witness target resolves to a value"),
        }],
    )]);
    witness.state_root =
        super::compute_state_root(GovernanceView::new(&witness_state, &witness_heads), SUITE)
            .unwrap();
    witness.id = witness.derive_id(SUITE).unwrap();
    let witness_id = witness.id.clone();
    cells
        .append_sealed_effects(
            &realm(),
            &witness_id,
            &[
                (
                    target.clone(),
                    issued(SealedOp::new(target_move.clone(), target_op)),
                ),
                (
                    capability_cell(),
                    issued(SealedOp::new(grant_move.clone(), grant_op)),
                ),
            ],
        )
        .await
        .unwrap();
    seals.put(&witness, SUITE).await.unwrap();

    let mut conflict_a = materialized_seal(
        conflict_a_id(),
        vec![
            target_move.clone(),
            grant_move.clone(),
            conflict_a_move.clone(),
        ],
    );
    conflict_a.predecessor_refs = vec![witness_id.clone()];
    conflict_a.delta = vec![conflict_a_move.clone()];
    conflict_a.state_root = witness.state_root.clone();
    conflict_a.sealed_at += chrono::Duration::seconds(1);
    conflict_a.id = conflict_a.derive_id(SUITE).unwrap();
    seals.put(&conflict_a, SUITE).await.unwrap();
    // Both causal registers read the store for their divergence:
    // §9.5.1 item 1 proves the conflict from the Move's own signed basis.
    // The `fsm` path is gated on the hand-built frozen `pre_state`, and
    // seeding the conflict into the store there would make a
    // witness-at-the-conflict-Seal fixture fail as `witness_invalid` before
    // it could reach the `post_conflict` check it exists to cover.
    cells
        .append_sealed_effects(
            &realm(),
            &conflict_a.id,
            &[(
                target.clone(),
                issued(
                    SealedOp::new(
                        conflict_a_move.clone(),
                        conflict_op(if cas { json!("open") } else { json!("leave") }),
                    )
                    .with_supersedes(vec![target_move.clone()]),
                ),
            )],
        )
        .await
        .unwrap();
    let mut conflict_b = materialized_seal(
        seal_id(0x52),
        vec![target_move.clone(), grant_move, conflict_b_move.clone()],
    );
    conflict_b.predecessor_refs = vec![witness_id.clone()];
    conflict_b.delta = vec![conflict_b_move.clone()];
    conflict_b.state_root = witness.state_root;
    conflict_b.sealed_at += chrono::Duration::seconds(1);
    conflict_b.id = conflict_b.derive_id(SUITE).unwrap();
    seals.put(&conflict_b, SUITE).await.unwrap();
    // Both causal registers read the store for their divergence:
    // §9.5.1 item 1 proves the conflict from the Move's own signed basis.
    // The `fsm` path is gated on the hand-built frozen `pre_state`, and
    // seeding the conflict into the store there would make a
    // witness-at-the-conflict-Seal fixture fail as `witness_invalid` before
    // it could reach the `post_conflict` check it exists to cover.
    cells
        .append_sealed_effects(
            &realm(),
            &conflict_b.id,
            &[(
                target.clone(),
                issued(
                    SealedOp::new(
                        conflict_b_move.clone(),
                        conflict_op(if cas { json!("closed") } else { json!("ban") }),
                    )
                    .with_supersedes(vec![target_move.clone()]),
                ),
            )],
        )
        .await
        .unwrap();

    let mut event = control_move(
        9,
        SealBasis {
            leaves: vec![conflict_a.id.clone(), conflict_b.id.clone()],
        },
        Vec::new(),
        vec![
            EventRef::new(grant_id, "recovery_capability"),
            EventRef::new(witness_id.as_str(), "state_witness"),
        ],
    );
    event.kind = "ak.conflict.recovery".into();
    let effects = vec![crate::ProjectionEffect::reset(
        target.clone(),
        LatticeOp {
            op_type: if cas {
                LatticeOpType::Set
            } else {
                LatticeOpType::Transition
            },
            tag: None,
            value: Some(json!({"policy_revision": 8})),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    )];
    let mut bottom = crate::Bottom::new(arkret_wire::BottomKind::Conflict, vec![target.clone()]);
    bottom.move_ids = vec![conflict_a_move, conflict_b_move];
    let pre_state = BTreeMap::from([
        (target, CellState::Bottom(bottom)),
        (
            capability_cell(),
            CellState::Value(json!([{"tag": grant_id, "value": grant_value}])),
        ),
    ]);
    let predecessor_closure =
        predecessor_seal_closure(&[conflict_a.id.clone(), conflict_b.id.clone()], &seals)
            .await
            .unwrap();

    RecoveryWitnessFixture {
        event,
        effects,
        pre_state,
        predecessor_closure,
        seals,
        cells,
        registry,
        conflict_a_id: conflict_a.id,
        witness_id: witness.id,
    }
}

fn conflict_a_id() -> SealId {
    seal_id(0x51)
}

async fn fsm_recovery_witness_fixture() -> RecoveryWitnessFixture {
    recovery_witness_fixture_for(crate::lattice::LatticeKind::Fsm).await
}

/// `fsm` recovery needs no `state_witness` either, now that it has identities.
///
/// The witness existed because `fsm` had no way to say which heads a recovery
/// replaced, so a proof of some prior value stood in for one. §9.3.1.5 gives it
/// the same supersession `cas_register` has, and 1610's ruling retires the
/// witness once those rules are in place. The three obligations that remain are
/// checked elsewhere and are not weakened by this: divergence in the Move's own
/// basis, an active capability, and `H_c(B) = H_c(P)` in `apply_seal`.
#[tokio::test]
async fn fsm_conflict_recovery_needs_no_witness() {
    let mut fixture = fsm_recovery_witness_fixture().await;
    fixture
        .event
        .refs
        .retain(|reference| reference.role != "state_witness");
    verify_recovery_witness(
        &fixture.event,
        &fixture.effects,
        &realm(),
        &fixture.pre_state,
        &fixture.predecessor_closure,
        &fixture.seals,
        &fixture.cells,
        &fixture.registry,
    )
    .await
    .unwrap();
}

/// §9.5.1: a `cas_register` recovery needs no witness at all. Its conflict comes
/// from its own signed basis and its authority from its capability path.
#[tokio::test]
async fn cas_conflict_recovery_needs_no_witness() {
    let mut fixture = recovery_witness_fixture().await;
    fixture
        .event
        .refs
        .retain(|reference| reference.role != "state_witness");
    verify_recovery_witness(
        &fixture.event,
        &fixture.effects,
        &realm(),
        &fixture.pre_state,
        &fixture.predecessor_closure,
        &fixture.seals,
        &fixture.cells,
        &fixture.registry,
    )
    .await
    .unwrap();
}

/// §9.5.1 item 1: the divergence must be visible in the Move's **own** signed
/// basis. A recovery authored against a view where the cell still resolved
/// cleanly is repairing something it never observed.
#[tokio::test]
async fn cas_conflict_recovery_rejects_a_basis_without_divergence() {
    let mut fixture = recovery_witness_fixture().await;
    // The witness Seal is the pre-conflict view: exactly one head, one value.
    let witness_leaf = fixture
        .predecessor_closure
        .iter()
        .find(|id| **id != conflict_a_id() && **id != seal_id(0x52))
        .cloned()
        .expect("the fixture closure contains the pre-conflict witness Seal");
    fixture.event.seal_basis = Some(SealBasis {
        leaves: vec![witness_leaf],
    });
    let error = verify_recovery_witness(
        &fixture.event,
        &fixture.effects,
        &realm(),
        &fixture.pre_state,
        &fixture.predecessor_closure,
        &fixture.seals,
        &fixture.cells,
        &fixture.registry,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error,
            ControlMoveReject::FailedPrecondition { ref reason, .. }
                if reason == arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM
        ),
        "unexpected reject: {error:?}"
    );
}

/// Retiring the witness does not retire the two proofs that were never it.
///
/// §9.5.1 items 1 and 2 are separate obligations: the divergence has to be
/// visible in the recovery's *own* signed basis, and the capability has to be
/// active against the frozen predecessor. A recovery authored against a view
/// where the cell still resolved cleanly is repairing something it never saw,
/// and being in `⊥` never excuses a revoked capability.
#[tokio::test]
async fn fsm_conflict_recovery_still_needs_divergence_and_an_active_capability() {
    let mut clean_basis = fsm_recovery_witness_fixture().await;
    // A basis that only covers the pre-conflict write: the cell resolves to a
    // single state there, so there is nothing to recover.
    clean_basis.event.seal_basis.as_mut().unwrap().leaves = vec![clean_basis.witness_id.clone()];
    let error = verify_recovery_witness(
        &clean_basis.event,
        &clean_basis.effects,
        &realm(),
        &clean_basis.pre_state,
        &clean_basis.predecessor_closure,
        &clean_basis.seals,
        &clean_basis.cells,
        &clean_basis.registry,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        ControlMoveReject::FailedPrecondition { reason, .. }
            if reason == arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM
    ));

    let mut revoked = fsm_recovery_witness_fixture().await;
    revoked.pre_state.remove(&capability_cell());
    let error = verify_recovery_witness(
        &revoked.event,
        &revoked.effects,
        &realm(),
        &revoked.pre_state,
        &revoked.predecessor_closure,
        &revoked.seals,
        &revoked.cells,
        &revoked.registry,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        ControlMoveReject::FailedPrecondition { reason, .. }
            if reason == arkret_wire::ReasonCode::RECOVERY_WITNESS_REVOKE_LAGGING
    ));
}

#[tokio::test]
async fn recovery_freshness_uses_the_realm_default_and_seven_day_ceiling() {
    assert_eq!(
        recovery_witness_freshness_window_ms(&BTreeMap::new()),
        DEFAULT_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS
    );
    let metadata = CellRef::new(arkret_wire::null_subject_cell(
        arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1,
    ))
    .unwrap();
    let state = BTreeMap::from([(
        metadata,
        CellState::Value(json!({"recovery_witness_freshness_window_ms": 999_999_999_i64})),
    )]);
    assert_eq!(
        recovery_witness_freshness_window_ms(&state),
        MAX_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS
    );
}

/// `event-auth-state-resolution.md` §9.5.1 — the recovery reset must produce a
/// cell that has actually **left** `⊥`, and it does so as an ordinary identity
/// write rather than by truncating the log.
///
/// Asserting the projected op's shape is not enough, and that is the exact gap
/// this covers: the reset used to project as a plain `set` and was fed into the
/// same join as the two concurrent branches that caused the `⊥`. The op-level
/// assertion stayed green while the cell never recovered.
///
/// §9.5.1 item 4 is the other half: a recovery supersedes **only the heads its
/// own basis observed**. A branch it never saw stays a head and still merges,
/// which is why this asserts a late sibling keeps the cell in conflict instead
/// of being silently swallowed by the reset.
#[tokio::test]
async fn a_recovery_reset_lifts_a_cas_register_cell_out_of_bottom() {
    let cell = CellRef::new(
        "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
    )
    .unwrap();
    let op = |value: &str, from: Option<&str>| LatticeOp {
        op_type: LatticeOpType::Set,
        tag: None,
        value: Some(json!(value)),
        from: from.map(|from| json!(from)),
        to: None,
        reason: None,
        issuer_seq: None,
    };
    let set = |id, value: &str, saw: &[u8]| {
        issued(SealedOp::superseding(
            move_id(id),
            op(value, None),
            saw.iter().copied().map(move_id).collect(),
        ))
    };
    let reset = |id, value: &str, saw: &[u8]| {
        issued(
            SealedOp::from_projection(
                move_id(id),
                &crate::ProjectionEffect::reset(cell.clone(), op(value, None)),
            )
            .with_supersedes(saw.iter().copied().map(move_id).collect()),
        )
    };
    let lattice = crate::lattice::CasRegister;

    let conflicted = vec![vec![set(1, "open", &[]), set(2, "closed", &[])]];
    assert!(
        matches!(
            join_cell_seal_batches(&lattice, &cell, &conflicted),
            CellState::Bottom(_)
        ),
        "precondition: concurrent cas_register writes put the cell in ⊥"
    );

    // §9.5.1 item 1: the recovery's signed basis showed both divergent heads,
    // so it supersedes both and becomes the cell's only head.
    let mut recovered = conflicted.clone();
    recovered.push(vec![reset(3, "closed", &[1, 2])]);
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &recovered),
        CellState::Value(json!("closed")),
        "the reset supersedes both conflicting branches and resolves the cell"
    );

    // The recovery is not a freeze: ordinary writes accepted after it still
    // supersede it, chaining off the recovered value.
    let mut superseded = recovered.clone();
    superseded.push(vec![set(4, "archived", &[3])]);
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &superseded),
        CellState::Value(json!("archived"))
    );

    // §9.5.1 item 4: a branch the recovery's basis never covered is not
    // swallowed by it. Truncating the log at the reset — which is what the
    // arrival-order `rposition` slice did — would have hidden this sibling and
    // reported a clean "closed".
    let mut late_sibling = recovered.clone();
    late_sibling.push(vec![set(6, "open", &[])]);
    assert!(
        matches!(
            join_cell_seal_batches(&lattice, &cell, &late_sibling),
            CellState::Bottom(_)
        ),
        "a late branch the recovery never observed still merges"
    );

    // A write that supersedes nothing does not recover the cell: it is just a
    // third concurrent head.
    let mut unmarked = conflicted;
    unmarked.push(vec![set(5, "closed", &[])]);
    assert!(matches!(
        join_cell_seal_batches(&lattice, &cell, &unmarked),
        CellState::Bottom(_)
    ));
}

/// The `fsm` half of the same obligation (§9.5.1 fsm additional admission).
///
/// This is the case that could not be written before: a recovery projected a
/// `set`, `fsm` accepts only `transition`, so an fsm cell in `⊥` had no escape
/// at all. The recovery now travels as a transition carrying only its `to` —
/// there is no single `from`, because it leaves both divergent heads at once.
#[tokio::test]
async fn a_recovery_reset_lifts_an_fsm_cell_out_of_bottom() {
    let cell =
        CellRef::new("ak:cell:ak.component.member.state.v1:did:web:alice.example".to_owned())
            .unwrap();
    let transition = |from: Option<&str>, to: &str| LatticeOp {
        op_type: LatticeOpType::Transition,
        tag: None,
        value: None,
        from: from.map(|from| json!(from)),
        to: Some(json!(to)),
        reason: None,
        issuer_seq: None,
    };
    let write = |id, from: &str, to: &str, saw: &[u8]| {
        issued(SealedOp::superseding(
            move_id(id),
            transition(Some(from), to),
            saw.iter().copied().map(move_id).collect(),
        ))
    };
    let recover = |id, to: &str, saw: &[u8]| {
        issued(
            SealedOp::from_projection(
                move_id(id),
                &crate::ProjectionEffect::reset(cell.clone(), transition(None, to)),
            )
            .with_supersedes(saw.iter().copied().map(move_id).collect()),
        )
    };
    let lattice = crate::lattice::Fsm::new(vec![
        (json!("leave"), json!("join")),
        (json!("leave"), json!("knock")),
        (json!("knock"), json!("join")),
        (json!("join"), json!("leave")),
        (json!("knock"), json!("leave")),
    ])
    .with_initial(json!("leave"));

    // Two concurrent transitions out of the registered initial state.
    let conflicted = vec![vec![
        write(0x21, "leave", "join", &[]),
        write(0x22, "leave", "knock", &[]),
    ]];
    assert!(
        matches!(
            join_cell_seal_batches(&lattice, &cell, &conflicted),
            CellState::Bottom(_)
        ),
        "precondition: concurrent fsm transitions put the cell in ⊥"
    );

    let mut recovered = conflicted;
    recovered.push(vec![recover(0x23, "join", &[0x21, 0x22])]);
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &recovered),
        CellState::Value(json!("join")),
        "the recovery supersedes both divergent heads and settles the cell"
    );

    // Not a freeze: an ordinary transition accepted afterwards chains off the
    // recovered state, which is only possible because the recovery is a head.
    let mut superseded = recovered.clone();
    superseded.push(vec![write(0x24, "join", "leave", &[0x23])]);
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &superseded),
        CellState::Value(json!("leave"))
    );

    // §9.5.1 item 4 / item 5: a branch outside the recovery's basis still
    // merges. Truncating the op log at the reset would have hidden it.
    let mut late_sibling = recovered;
    late_sibling.push(vec![write(0x25, "leave", "knock", &[])]);
    assert!(
        matches!(
            join_cell_seal_batches(&lattice, &cell, &late_sibling),
            CellState::Bottom(_)
        ),
        "a late branch the recovery never observed still merges"
    );
}

// ── R5: multi-Seal coverage, interleaved cells, recovery arrival order, forged heads ──

fn policy_cell(subject: &str) -> CellRef {
    CellRef::new(format!(
        "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp0000000000000000{subject}"
    ))
    .unwrap()
}

fn cas_set_op(value: Value, saw: &[u8]) -> LatticeOp {
    let _ = saw;
    LatticeOp {
        op_type: LatticeOpType::Set,
        tag: None,
        value: Some(value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    }
}

fn cas_write(id: u8, value: Value, saw: &[u8]) -> IssuedOp {
    issued(SealedOp::superseding(
        move_id(id),
        cas_set_op(value, saw),
        saw.iter().copied().map(move_id).collect(),
    ))
}

/// One Control Move can be covered by more than one Seal — that is why
/// `direct_covering_seal` refuses a singular lookup. The joined view is over the
/// *union* of covered Events, so the same write reached twice is still one head,
/// not two siblings that push the cell to `⊥`.
#[tokio::test]
async fn one_move_covered_by_two_seals_is_one_head_not_a_sibling_pair() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let realm = realm();
    let cell = policy_cell("aa");
    let shared = move_id(0x71);

    let seal_a = materialized_seal(seal_id(0xa1), vec![shared.clone()]);
    let seal_b = materialized_seal(seal_id(0xb1), vec![shared.clone()]);
    // The same op is recorded under both Seals: two notaries sealed one Move.
    for seal in [&seal_a, &seal_b] {
        cells
            .append_sealed_effects(
                &realm,
                &seal.id,
                &[(cell.clone(), cas_write(0x71, json!({"policy_revision": 1}), &[]))],
            )
            .await
            .unwrap();
        seals.put(seal, SUITE).await.unwrap();
    }

    let heads = effective_cas_heads_at(
        &[seal_a.id.clone(), seal_b.id.clone()],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    let cell_heads = heads.get(&cell).expect("the covered write is a head");
    assert_eq!(
        cell_heads.len(),
        1,
        "double coverage of one Move must not manufacture a second head"
    );
    assert_eq!(cell_heads[0].move_id, shared);

    let state = effective_state_at(
        &[seal_a.id.clone(), seal_b.id],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    assert_eq!(
        state.get(&cell).cloned(),
        Some(CellState::Value(json!({"policy_revision": 1}))),
        "one Move under two Seals settles, it does not go to bottom"
    );
}

/// The same identity carrying two *different* canonical effects is the §9.3.1.1
/// fail-closed case, and double Seal coverage is exactly where a store could
/// grow one without anybody noticing.
#[tokio::test]
async fn one_move_with_two_effects_across_seals_fails_closed() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let realm = realm();
    let cell = policy_cell("aa");
    let shared = move_id(0x71);

    let seal_a = materialized_seal(seal_id(0xa1), vec![shared.clone()]);
    let seal_b = materialized_seal(seal_id(0xb1), vec![shared.clone()]);
    cells
        .append_sealed_effects(
            &realm,
            &seal_a.id,
            &[(cell.clone(), cas_write(0x71, json!({"policy_revision": 1}), &[]))],
        )
        .await
        .unwrap();
    cells
        .append_sealed_effects(
            &realm,
            &seal_b.id,
            &[(cell.clone(), cas_write(0x71, json!({"policy_revision": 2}), &[]))],
        )
        .await
        .unwrap();
    seals.put(&seal_a, SUITE).await.unwrap();
    seals.put(&seal_b, SUITE).await.unwrap();

    let rejected = effective_cas_heads_at(
        &[seal_a.id, seal_b.id],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await;
    assert!(
        rejected.is_err(),
        "one identity with two effects must not be resolved by picking one"
    );
}

/// Two cells written in interleaved Seals keep independent head sets: a
/// `supersedes` set names Move identities, and a Move that superseded a write on
/// one cell must not retire a same-identity-adjacent write on another.
#[tokio::test]
async fn interleaved_multi_cell_writes_keep_independent_head_sets() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let realm = realm();
    let left = policy_cell("aa");
    let right = policy_cell("bb");

    // Seal 1: first write on each cell. Seal 2: a successor on `left` only.
    let seal_one = materialized_seal(seal_id(0xa1), vec![move_id(0x81), move_id(0x82)]);
    let seal_two = materialized_seal(seal_id(0xb1), vec![move_id(0x83)]);
    cells
        .append_sealed_effects(
            &realm,
            &seal_one.id,
            &[
                (left.clone(), cas_write(0x81, json!("left-1"), &[])),
                (right.clone(), cas_write(0x82, json!("right-1"), &[])),
            ],
        )
        .await
        .unwrap();
    cells
        .append_sealed_effects(
            &realm,
            &seal_two.id,
            &[(left.clone(), cas_write(0x83, json!("left-2"), &[0x81]))],
        )
        .await
        .unwrap();
    seals.put(&seal_one, SUITE).await.unwrap();
    seals.put(&seal_two, SUITE).await.unwrap();

    let heads = effective_cas_heads_at(
        &[seal_one.id.clone(), seal_two.id.clone()],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    assert_eq!(
        heads.get(&left).map(|h| h.iter().map(|head| head.move_id.clone()).collect::<Vec<_>>()),
        Some(vec![move_id(0x83)]),
        "the successor on `left` retires only its own cell's write"
    );
    assert_eq!(
        heads.get(&right).map(|h| h.iter().map(|head| head.move_id.clone()).collect::<Vec<_>>()),
        Some(vec![move_id(0x82)]),
        "`right` never saw a superseder, so its first write is still the head"
    );

    let state = effective_state_at(
        &[seal_one.id, seal_two.id],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .await
    .unwrap();
    assert_eq!(state.get(&left).cloned(), Some(CellState::Value(json!("left-2"))));
    assert_eq!(state.get(&right).cloned(), Some(CellState::Value(json!("right-1"))));
}

/// §9.5 drops every op at or before the last recovery reset, so the reset is a
/// property of the op set and not of the order it arrived in. The two arrival
/// orders are the ones a receiver actually sees — reset last after a
/// backfilled conflict, and reset first with the conflicting pair arriving
/// late — and they MUST agree.
#[tokio::test]
async fn a_recovery_reset_settles_the_same_state_in_either_arrival_order() {
    async fn view_after(
        order: [(&SealId, Vec<(CellRef, IssuedOp)>); 2],
        realm: &RealmId,
        cell: &CellRef,
        seals: &MemorySealStore,
    ) -> (CellState, Vec<Hash>) {
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let mut leaves = Vec::new();
        for (seal_id, effects) in order {
            cells
                .append_sealed_effects(realm, seal_id, &effects)
                .await
                .unwrap();
            leaves.push(seal_id.clone());
        }
        let state = effective_state_at(&leaves, realm, seals, &cells, &registry)
            .await
            .unwrap();
        let heads = effective_cas_heads_at(&leaves, realm, seals, &cells, &registry)
            .await
            .unwrap();
        (
            state.get(cell).cloned().expect("the cell is written"),
            heads
                .get(cell)
                .map(|h| h.iter().map(|head| head.move_id.clone()).collect())
                .unwrap_or_default(),
        )
    }

    let seals = MemorySealStore::default();
    let realm = realm();
    let cell = policy_cell("aa");

    // Two concurrent writes put the cell in `⊥`; the recovery lifts it out. For
    // `cas_register` the recovery is an ordinary identity write that supersedes
    // exactly the divergent heads its basis observed (§9.5.1) — the
    // `recovery_reset` flag truncates nothing on this lattice, which is what
    // makes the two arrival orders comparable at all.
    let conflict = vec![
        (cell.clone(), cas_write(0x91, json!("branch-a"), &[])),
        (cell.clone(), cas_write(0x92, json!("branch-b"), &[])),
    ];
    let mut reset_op = SealedOp::superseding(
        move_id(0x93),
        cas_set_op(json!("recovered"), &[]),
        vec![move_id(0x91), move_id(0x92)],
    );
    reset_op.recovery_reset = true;
    let reset = vec![(cell.clone(), issued(reset_op))];

    let conflict_seal = materialized_seal(seal_id(0xa1), vec![move_id(0x91), move_id(0x92)]);
    let reset_seal = materialized_seal(seal_id(0xb1), vec![move_id(0x93)]);
    seals.put(&conflict_seal, SUITE).await.unwrap();
    seals.put(&reset_seal, SUITE).await.unwrap();

    let reset_last = view_after(
        [
            (&conflict_seal.id, conflict.clone()),
            (&reset_seal.id, reset.clone()),
        ],
        &realm,
        &cell,
        &seals,
    )
    .await;
    let reset_first = view_after(
        [(&reset_seal.id, reset), (&conflict_seal.id, conflict)],
        &realm,
        &cell,
        &seals,
    )
    .await;

    assert_eq!(
        reset_last, reset_first,
        "a recovery reset is a property of the op set, not of arrival order"
    );
    assert_eq!(reset_last.0, CellState::Value(json!("recovered")));
    assert_eq!(reset_last.1, vec![move_id(0x93)]);
}

/// The §6.2.1 leaf of a substituted head set, spelled out so the forgery is the
/// bytes and not a helper's opinion of them.
fn forged_head_leaf(cell: &CellRef, heads: &[crate::lattice::cas_register::CasHead]) -> Hash {
    let entries = heads
        .iter()
        .map(|head| {
            json!({
                "event_id": EventId::from_event_digest(&head.move_id)
                    .unwrap()
                    .as_str(),
                "value": head.value,
            })
        })
        .collect::<Vec<_>>();
    crate::state::state_root::state_leaf_hash_from_state_object(cell, json!({"heads": entries}), SUITE)
        .unwrap()
}

/// A `state_root` inclusion proof commits the whole head set, not the settled
/// value. Substituting one head — dropping the released `null` write, say, or
/// re-labelling which Move wrote the surviving value — is exactly the forgery
/// that a value-only leaf would have accepted.
#[tokio::test]
async fn a_forged_head_set_does_not_verify_against_the_state_root() {
    let cell = policy_cell("aa");
    let state = BTreeMap::from([(cell.clone(), CellState::Value(json!("live")))]);
    let genuine = vec![
        crate::lattice::cas_register::CasHead {
            move_id: move_id(0x21),
            value: Value::Null,
        },
        crate::lattice::cas_register::CasHead {
            move_id: move_id(0x22),
            value: json!("live"),
        },
    ];
    let heads = CasHeadsByCell::from([(cell.clone(), genuine.clone())]);
    let root = super::compute_state_root(GovernanceView::new(&state, &heads), SUITE).unwrap();
    let proof =
        crate::state::state_inclusion_proof(GovernanceView::new(&state, &heads), &cell, SUITE).unwrap();
    assert!(
        crate::state::verify_state_inclusion_proof(
            &proof.leaf_digest,
            proof.leaf_index,
            proof.leaf_count,
            &proof.inclusion_proof,
            &root,
            SUITE,
        )
        .unwrap(),
        "the genuine head set verifies against its own root"
    );

    // Forgery 1: drop the released `null` head. The cell still reads "live", so
    // a value-shaped leaf would be unchanged.
    let dropped = vec![genuine[1].clone()];
    assert!(
        !crate::state::verify_state_inclusion_proof(
            &forged_head_leaf(&cell, &dropped),
            proof.leaf_index,
            proof.leaf_count,
            &proof.inclusion_proof,
            &root,
            SUITE,
        )
        .unwrap(),
        "dropping a released head must break the proof even though the value is unchanged"
    );

    // Forgery 2: keep both heads but re-attribute the surviving value to
    // another Move.
    let reattributed = vec![
        genuine[0].clone(),
        crate::lattice::cas_register::CasHead {
            move_id: move_id(0x23),
            value: json!("live"),
        },
    ];
    assert!(
        !crate::state::verify_state_inclusion_proof(
            &forged_head_leaf(&cell, &reattributed),
            proof.leaf_index,
            proof.leaf_count,
            &proof.inclusion_proof,
            &root,
            SUITE,
        )
        .unwrap(),
        "re-attributing a head must break the proof"
    );
}
