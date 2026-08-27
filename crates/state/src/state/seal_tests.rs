use arkret_wire::{DidCoreId, DidUrl};

/// Attach a fixed issuer to a sealed op. These fixtures exercise
/// non-ordered-log lattices, where the issuer is carried but unused.
fn issued(op: SealedOp) -> IssuedOp {
    IssuedOp {
        issuer: DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        op,
    }
}

use arkret_wire::ProducerEventProof;
use arkret_wire::event_envelope::{EventRef, ScopeRef};
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

impl CellStore for SealGatedCellStore {
    fn list_cells(&self, _realm_id: &RealmId) -> crate::state::StoreResult<Vec<CellRef>> {
        Ok(Vec::new())
    }

    fn sealed_ops_for_cell(
        &self,
        _realm_id: &RealmId,
        _cell: &CellRef,
    ) -> crate::state::StoreResult<Vec<IssuedOp>> {
        Ok(Vec::new())
    }

    fn sealed_op_batches_for_cell(
        &self,
        _realm_id: &RealmId,
        _cell: &CellRef,
    ) -> crate::state::StoreResult<Vec<(SealId, Vec<IssuedOp>)>> {
        Ok(Vec::new())
    }

    fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> crate::state::StoreResult<Option<CellState>> {
        self.inner.cached_state(realm_id, cell, view_hash)
    }

    fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> crate::state::StoreResult<()> {
        self.inner
            .put_cached_state(realm_id, cell, view_hash, state)
    }

    fn append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> crate::state::StoreResult<()> {
        self.inner.append_sealed_effects(realm_id, seal, new_ops)
    }

    fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> crate::state::StoreResult<()> {
        self.inner.rollback_seal(realm_id, seal)
    }
}

#[test]
fn live_digest_suite_uses_genesis_until_a_transition_cell_exists() {
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

#[test]
fn live_digest_suite_fails_closed_without_transition_or_genesis_state() {
    let error = live_digest_suite_from_state(&BTreeMap::new()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("omits both digest-suite and genesis cells")
    );
}

fn compute_state_root(cells: &BTreeMap<CellRef, CellState>) -> Result<Hash, crate::WireError> {
    super::compute_state_root(cells, SUITE)
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

fn effective_seal_view(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<EffectiveSealView, SealReject> {
    super::effective_seal_view(leaves, realm_id, seals, cells, registry, SUITE)
}

#[allow(clippy::too_many_arguments)]
fn verify_recovery_witness(
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
}

fn apply_seal<VerifyProofs, ProjectWrites>(
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
}

#[allow(clippy::too_many_arguments)]
fn apply_seal_in_context<VerifyProofs, ProjectWrites>(
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
            signer_resolution_evidence_digest: Some(
                Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
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
            signer_resolution_evidence_digest: Some(
                Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
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

#[test]
fn control_event_set_root_uses_seal_merkle_domain_separation() {
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

#[test]
fn event_digest_set_inclusion_proof_covers_every_leaf_and_rejects_tampering() {
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
        "actor_id": actor_id,
        "principal_server_id": "ak:did_core:web:principal.example",
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

#[test]
fn completeness_root_is_actor_sequence_enveloped_and_requires_exact_coverage() {
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

#[test]
fn effective_state_at_filters_ops_by_seal_coverage() {
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
        .unwrap();
    seals.put(&seal_a, SUITE).unwrap();
    seals.put(&seal_b, SUITE).unwrap();

    let state_a = effective_state_at(
        std::slice::from_ref(&seal_a.id),
        &realm,
        &seals,
        &cells,
        &registry,
    )
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

#[test]
fn effective_seal_view_is_leaf_order_independent() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let realm = realm();
    let move_a = move_id(0xaa);
    let move_b = move_id(0xbb);
    let seal_a = materialized_seal(seal_id(0xa1), vec![move_a.clone()]);
    let seal_b = materialized_seal(seal_id(0xb1), vec![move_b.clone()]);
    seals.put(&seal_b, SUITE).unwrap();
    seals.put(&seal_a, SUITE).unwrap();

    let first = effective_seal_view(
        &[seal_b.id.clone(), seal_a.id.clone()],
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .unwrap();
    let second = effective_seal_view(
        &[seal_a.id.clone(), seal_b.id.clone()],
        &realm,
        &seals,
        &cells,
        &registry,
    )
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
#[test]
fn wire_accepted_digests_are_ascending_not_apply_order() {
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

#[test]
fn deterministic_order_respects_causality_then_digest_desc() {
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

#[test]
fn deterministic_order_is_input_permutation_independent() {
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

fn signed_seal_with_coverage(
    predecessor_refs: Vec<SealId>,
    delta: Vec<Hash>,
    covered_events: &[Event],
    post_state: &BTreeMap<CellRef, CellState>,
    notary_seq: u64,
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
        compute_state_root(post_state).unwrap(),
        notary_seq,
    );
    seal.covered_event_digests = covered.iter().cloned().collect();
    seal.completeness_root = control_event_completeness_root(covered_events, &covered).unwrap();
    seal.id = seal.derive_id(SUITE).unwrap();
    seal
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
        cell: member_cell(),
        op: ProjectedOp::Direct(op),
    }])
}

fn genesis_digest_suite_write(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    if event.kind != arkret_wire::EventKind::RealmCreate {
        return Err("only Realm create initializes the digest suite".to_owned());
    }
    Ok(vec![ProjectedCellWrite {
        cell: digest_suite_cell(),
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
        cell: member_cell(),
        op: ProjectedOp::Direct(op),
    }];
    if event.kind == arkret_wire::EventKind::RealmCreate {
        writes.push(ProjectedCellWrite {
            cell: digest_suite_cell(),
            op: ProjectedOp::Direct(digest_suite_set_op()),
        });
    }
    Ok(writes)
}

#[test]
fn apply_seal_rejects_an_empty_first_root() {
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
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("complete non-empty Realm anchor")
    );
}

#[test]
fn first_anchor_unit_can_apply_basisless_events_only_in_explicit_context() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
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
    .unwrap();
    assert_eq!(effect.accepted_event_digests, vec![digest]);
    assert_eq!(effect.post_state_root, seal.state_root);
}

#[test]
fn apply_seal_validates_candidate_state_before_durable_visibility() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = SealGatedCellStore::default();
    let registry = MemoryCellRegistry::default();
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
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
    .unwrap();

    assert_eq!(effect.accepted_event_digests, vec![digest.clone()]);
    assert_eq!(effect.post_state_root, seal.state_root);
    let stored = cells
        .inner
        .sealed_ops_for_cell(&realm(), &digest_suite_cell())
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].op.move_id, digest);
}

#[test]
fn rejected_anchor_state_root_never_publishes_candidate_cell_ops() {
    let events = MemoryControlEventStore::default();
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let event = genesis_create();
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
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
    .unwrap_err();

    assert!(matches!(error, SealReject::StateRootMismatch { .. }));
    assert!(cells.list_cells(&realm()).unwrap().is_empty());
    assert!(seals.get(&seal.id).unwrap().is_none());
}

#[test]
fn anchor_unit_stages_create_projection_before_creator_binding_transition() {
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
        cell: member_cell(),
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
        .unwrap();

    let post_state = state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]);
    // `Seal.delta` is a canonical sorted, duplicate-free list — the staging
    // order the test is about lives in the Seal's covered set, not in this
    // wire field's order.
    let mut delta = vec![create_digest.clone(), binding_digest.clone()];
    delta.sort();
    let seal = signed_seal_with_coverage(
        Vec::new(),
        delta.clone(),
        &[create, binding.clone()],
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
        bootstrap_member_transition_write,
        EventSubmitContext::AnchorUnit,
    )
    .unwrap();
    // Acceptance order stays causal (create, then the binding that depends
    // on it) regardless of how `Seal.delta` sorts.
    assert_eq!(
        effect.accepted_event_digests,
        vec![create_digest, binding_digest]
    );
    assert_eq!(effect.post_state_root, seal.state_root);
}

#[test]
fn anchor_unit_context_rejects_a_nonempty_predecessor_view() {
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
    .unwrap_err();
    assert!(error.to_string().contains("only valid for the first Seal"));
}

/// Install a fully replayable Genesis Seal and return the basis a
/// successor Control Move must declare.
fn install_genesis(
    events: &MemoryControlEventStore,
    seals: &MemorySealStore,
    cells: &MemoryCellStore,
    registry: &MemoryCellRegistry,
) -> (Seal, SealBasis, Event, Hash) {
    let create = genesis_create();
    let anchor = control_event_digest(&create, SUITE).unwrap();
    events
        .put_pending_with_ingress(&create, &ackless_ingress(), SUITE)
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
    .unwrap();
    let basis = SealBasis {
        leaves: vec![genesis.id.clone()],
    };
    (genesis, basis, create, anchor)
}

#[test]
fn apply_seal_applies_only_projector_derived_writes() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let events = MemoryControlEventStore::default();
    let registry = MemoryCellRegistry::default();
    let (genesis, basis, create, _) = install_genesis(&events, &seals, &cells, &registry);

    // The Event names no cell and no lattice op anywhere: the projector is
    // the sole source of the `invited -> join` write applied below.
    let event = control_move(1, basis, Vec::new(), Vec::new());
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .unwrap();

    let post_state = state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]);
    let seal = signed_seal_with_coverage(
        vec![genesis.id],
        vec![digest.clone()],
        &[create, event.clone()],
        &post_state,
        2,
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
    .unwrap();
    assert_eq!(effect.accepted_event_digests, vec![digest.clone()]);
    assert_eq!(effect.post_state_root, seal.state_root);

    let ops = cells.sealed_ops_for_cell(&realm(), &member_cell()).unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].op.move_id, digest);
    assert_eq!(ops[0].issuer, event.actor_id);
    assert_eq!(events.covering_seals(&digest).unwrap(), vec![seal.id]);
}

#[test]
fn apply_seal_rejects_a_projection_the_receiver_cannot_evaluate() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let events = MemoryControlEventStore::default();
    let registry = MemoryCellRegistry::default();
    let (genesis, basis, create, _) = install_genesis(&events, &seals, &cells, &registry);
    let event = control_move(1, basis, Vec::new(), Vec::new());
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .unwrap();

    let seal = signed_seal_with_coverage(
        vec![genesis.id],
        vec![digest],
        &[create, event],
        &state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]),
        2,
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
    .unwrap_err();
    assert!(matches!(error, SealReject::ControlMoveRejected { .. }));
}

#[test]
fn seal_basis_leaf_outside_the_predecessor_closure_rejects() {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let events = MemoryControlEventStore::default();
    let registry = MemoryCellRegistry::default();
    let (genesis, mut basis, create, _) = install_genesis(&events, &seals, &cells, &registry);
    // A concurrent Seal the receiving Seal does not descend from. Admitting
    // it would make acceptance depend on which leaves this receiver happens
    // to hold (§6.3 concurrent-leaf rule).
    basis.leaves = vec![seal_id(0xee)];
    let event = control_move(1, basis, Vec::new(), Vec::new());
    let digest = control_event_digest(&event, SUITE).unwrap();
    events
        .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
        .unwrap();

    let seal = signed_seal_with_coverage(
        vec![genesis.id],
        vec![digest],
        &[create, event],
        &state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]),
        2,
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
    .unwrap_err();
    assert!(matches!(error, SealReject::SealBasisOutsideClosure { .. }));
}

#[test]
fn predecessor_seal_closure_is_transitive() {
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
    seals.put(&genesis, SUITE).unwrap();
    seals.put(&middle, SUITE).unwrap();

    let closure = predecessor_seal_closure(std::slice::from_ref(&middle.id), &seals).unwrap();
    assert_eq!(closure, BTreeSet::from([genesis.id, middle.id]));
}

#[test]
fn effective_state_preserves_cross_seal_fsm_order() {
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

    cells
        .append_sealed_effects(
            &realm,
            &seal.id,
            &[
                (
                    cell.clone(),
                    issued(SealedOp::new(join_id, transition("invited", "join"))),
                ),
                (
                    cell.clone(),
                    issued(SealedOp::new(ban_id, transition("join", "ban"))),
                ),
            ],
        )
        .unwrap();
    seals.put(&seal, SUITE).unwrap();

    let state = effective_state_at(
        std::slice::from_ref(&seal.id),
        &realm,
        &seals,
        &cells,
        &registry,
    )
    .unwrap();
    assert_eq!(state.get(&cell), Some(&CellState::Value(json!("ban"))));
}

#[test]
fn mv_register_seal_batches_distinguish_successors_from_siblings() {
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

/// A `cas_register` cell is joined over its whole covered history, so the
/// predecessors its chain walk binds to are still in the input.
#[test]
fn cas_register_seal_batches_join_the_whole_history() {
    let cell = CellRef::new(
        "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
    )
    .unwrap();
    let set = |id, value: &str, from: Option<&str>| {
        issued(SealedOp::new(
            move_id(id),
            LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(json!(value)),
                from: from.map(|from| json!(from)),
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ))
    };
    let lattice = crate::lattice::CasRegister;

    let sequential = vec![
        vec![set(1, "open", None)],
        vec![set(2, "closed", Some("open"))],
    ];
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &sequential),
        CellState::Value(json!("closed"))
    );

    let siblings = vec![vec![set(3, "open", None), set(4, "closed", None)]];
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
}

fn recovery_witness_fixture() -> RecoveryWitnessFixture {
    let seals = MemorySealStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::default();
    let target = CellRef::new(
        "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
    )
    .unwrap();
    let grant_id = "ak:grant:Aam-wkD4GZDuqJ92ccjIGHTOT3JazvV5Z0uaBH7S5eFX";
    let target_move = move_id(0x41);
    let grant_move = move_id(0x42);
    let conflict_a_move = move_id(0x51);
    let conflict_b_move = move_id(0x52);
    let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap();
    let target_value = json!({"policy_revision": 7});
    let grant_value = json!({
        "grant_id": grant_id,
        "subject": actor,
        "actions": ["ak.conflict.recovery"],
        "resources": [{"kind": "realm", "realm_id": realm()}]
    });

    let mut target_op = LatticeOp::empty();
    target_op.op_type = LatticeOpType::Set;
    target_op.value = Some(target_value.clone());
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
    witness.state_root = compute_state_root(&witness_state).unwrap();
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
        .unwrap();
    seals.put(&witness, SUITE).unwrap();

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
    seals.put(&conflict_a, SUITE).unwrap();
    let mut conflict_b = materialized_seal(
        seal_id(0x52),
        vec![target_move, grant_move, conflict_b_move.clone()],
    );
    conflict_b.predecessor_refs = vec![witness_id.clone()];
    conflict_b.delta = vec![conflict_b_move.clone()];
    conflict_b.state_root = witness.state_root;
    conflict_b.sealed_at += chrono::Duration::seconds(1);
    conflict_b.id = conflict_b.derive_id(SUITE).unwrap();
    seals.put(&conflict_b, SUITE).unwrap();

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
            op_type: LatticeOpType::Set,
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
        predecessor_seal_closure(&[conflict_a.id.clone(), conflict_b.id.clone()], &seals).unwrap();

    RecoveryWitnessFixture {
        event,
        effects,
        pre_state,
        predecessor_closure,
        seals,
        cells,
        registry,
        conflict_a_id: conflict_a.id,
    }
}

fn conflict_a_id() -> SealId {
    seal_id(0x51)
}

#[test]
fn conflict_recovery_accepts_a_sealed_pre_conflict_witness() {
    let fixture = recovery_witness_fixture();
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
    .unwrap();
}

#[test]
fn conflict_recovery_rejects_post_conflict_and_revoked_witnesses() {
    let mut post_conflict = recovery_witness_fixture();
    post_conflict
        .event
        .refs
        .iter_mut()
        .find(|reference| reference.role == "state_witness")
        .unwrap()
        .id = post_conflict.conflict_a_id.to_string();
    let error = verify_recovery_witness(
        &post_conflict.event,
        &post_conflict.effects,
        &realm(),
        &post_conflict.pre_state,
        &post_conflict.predecessor_closure,
        &post_conflict.seals,
        &post_conflict.cells,
        &post_conflict.registry,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ControlMoveReject::FailedPrecondition { reason, .. }
            if reason == arkret_wire::ReasonCode::RECOVERY_WITNESS_POST_CONFLICT
    ));

    let mut revoked = recovery_witness_fixture();
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
    .unwrap_err();
    assert!(matches!(
        error,
        ControlMoveReject::FailedPrecondition { reason, .. }
            if reason == arkret_wire::ReasonCode::RECOVERY_WITNESS_REVOKE_LAGGING
    ));
}

#[test]
fn recovery_freshness_uses_the_realm_default_and_seven_day_ceiling() {
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

/// `event-auth-state-resolution.md` §9.5 — the recovery reset must produce
/// a cell that has actually **left** `⊥`.
///
/// Asserting the projected op's shape is not enough, and that is the exact
/// gap this covers: the reset used to project as a plain `set` and was fed
/// into the same join as the two concurrent branches that caused the `⊥`.
/// The op-level assertion stayed green while the cell never recovered, so
/// `bottom=reject` cells were permanently dead and the only escape §9.5
/// defines did not exist.
#[test]
fn a_recovery_reset_lifts_a_cas_register_cell_out_of_bottom() {
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
    let set =
        |id, value: &str, from: Option<&str>| issued(SealedOp::new(move_id(id), op(value, from)));
    let reset = |id, value: &str| {
        issued(SealedOp::from_projection(
            move_id(id),
            &crate::ProjectionEffect::reset(cell.clone(), op(value, None)),
        ))
    };
    let lattice = crate::lattice::CasRegister;

    let conflicted = vec![vec![set(1, "open", None), set(2, "closed", None)]];
    assert!(
        matches!(
            join_cell_seal_batches(&lattice, &cell, &conflicted),
            CellState::Bottom(_)
        ),
        "precondition: concurrent cas_register writes put the cell in ⊥"
    );

    let mut recovered = conflicted.clone();
    recovered.push(vec![reset(3, "closed")]);
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &recovered),
        CellState::Value(json!("closed")),
        "the reset discards both conflicting branches and resolves the cell"
    );

    // The boundary is a floor, not a freeze: ordinary writes accepted after
    // the recovery still supersede it, chaining off the recovered value.
    let mut superseded = recovered.clone();
    superseded.push(vec![set(4, "archived", Some("closed"))]);
    assert_eq!(
        join_cell_seal_batches(&lattice, &cell, &superseded),
        CellState::Value(json!("archived"))
    );

    // And an unmarked op with the same shape must NOT recover the cell —
    // otherwise the gate would pass on a build where the reset marker was
    // dropped somewhere between projection and the op log.
    let mut unmarked = conflicted;
    unmarked.push(vec![set(5, "closed", None)]);
    assert!(matches!(
        join_cell_seal_batches(&lattice, &cell, &unmarked),
        CellState::Bottom(_)
    ));
}
