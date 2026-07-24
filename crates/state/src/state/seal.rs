//! Seal application and effective-view helpers.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use thiserror::Error;

use super::state_root::{compute_state_root, seal_merkle_root_from_leaf_data};
use super::store::{CellRegistry, CellStore, MoveStore, SealStore};
use super::verify::verify_move;
use crate::lattice::{CellState, SealedOp};
use crate::{CellRef, Hash, Move, MoveId, RealmId, Seal, SealId, canonical};

#[derive(Clone, Debug)]
pub struct SealEffect {
    pub seal: SealId,
    pub accepted_move_ids: Vec<MoveId>,
    pub rejected_moves: Vec<(MoveId, String)>,
    pub post_state_root: Hash,
}

#[derive(Debug, Error)]
pub enum SealReject {
    #[error("Seal structural / signature error: {0}")]
    Structural(String),

    #[error("Seal predecessor_refs contain unknown ids")]
    UnknownPredecessor,

    #[error("Seal.delta contains an event already covered by a predecessor")]
    DeltaAlreadyCovered,

    #[error("Move {move_id} referenced in delta but not in store")]
    MissingMove { move_id: String },

    #[error("Move {move_id} referenced in delta failed verification: {reason}")]
    MoveRejected { move_id: String, reason: String },

    #[error("declared control_event_set_root {declared} does not match recomputed {recomputed}")]
    ControlEventSetRootMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("covered_event_digests does not equal predecessor coverage plus delta")]
    CoveredSetMismatch,

    #[error("declared state_root {declared} does not match recomputed {recomputed}")]
    StateRootMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("store error: {0}")]
    Store(String),
}

impl From<super::store::StoreError> for SealReject {
    fn from(e: super::store::StoreError) -> Self {
        SealReject::Store(e.to_string())
    }
}

pub fn apply_seal<F>(
    seal: &Seal,
    moves: &dyn MoveStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    verify_jws: F,
) -> Result<SealEffect, SealReject>
where
    F: Fn(&[u8], &str, &str, &str) -> Result<(), String> + Copy,
{
    seal.validate_id()
        .map_err(|e| SealReject::Structural(format!("id: {e}")))?;
    seal.validate_structural()
        .map_err(|e| SealReject::Structural(e.to_string()))?;
    if !seals.predecessors_known(&seal.predecessor_refs)? {
        return Err(SealReject::UnknownPredecessor);
    }

    let pred_covered = union_predecessor_covered_events(&seal.predecessor_refs, seals)?;
    if seal.delta.iter().any(|m| pred_covered.contains(m)) {
        return Err(SealReject::DeltaAlreadyCovered);
    }

    let mut covered = pred_covered.clone();
    covered.extend(seal.delta.iter().cloned());
    if !seal.covered_event_digests.is_empty() {
        let declared: BTreeSet<MoveId> = seal.covered_event_digests.iter().cloned().collect();
        if declared != covered {
            return Err(SealReject::CoveredSetMismatch);
        }
    }
    let recomputed_control_root = control_event_set_root(&covered)?;
    if recomputed_control_root.as_str() != seal.control_event_set_root.as_str() {
        return Err(SealReject::ControlEventSetRootMismatch {
            declared: seal.control_event_set_root.as_str().to_owned(),
            recomputed: recomputed_control_root.as_str().to_owned(),
        });
    }

    let pre_state =
        effective_state_for_covered_events(&pred_covered, &seal.realm_id, cells, registry)?;

    let mut new_moves: Vec<Move> = Vec::with_capacity(seal.delta.len());
    for mid in &seal.delta {
        let m = moves.get(mid)?.ok_or_else(|| SealReject::MissingMove {
            move_id: mid.as_str().to_owned(),
        })?;
        new_moves.push(m);
    }
    let ordered = deterministic_order(new_moves);

    let mut accepted: Vec<Move> = Vec::with_capacity(ordered.len());
    for m in ordered {
        match verify_move(&m, &pre_state, registry, verify_jws) {
            Ok(()) => accepted.push(m),
            Err(reject) => {
                return Err(SealReject::MoveRejected {
                    move_id: m.id.as_str().to_owned(),
                    reason: reject.to_string(),
                });
            }
        }
    }

    let mut new_ops: Vec<(CellRef, SealedOp)> = Vec::new();
    for m in &accepted {
        for effect in &m.effects {
            new_ops.push((
                effect.cell.clone(),
                SealedOp::new(m.id.clone(), effect.op.clone()),
            ));
        }
    }
    cells.append_sealed_effects(&seal.realm_id, &seal.id, &new_ops)?;

    let post_state = effective_state_for_covered_events(&covered, &seal.realm_id, cells, registry)?;
    let recomputed_state = compute_state_root(&post_state)
        .map_err(|e| SealReject::Store(format!("state_root recompute failed: {e}")))?;
    if recomputed_state.as_str() != seal.state_root.as_str() {
        cells.rollback_seal(&seal.realm_id, &seal.id)?;
        return Err(SealReject::StateRootMismatch {
            declared: seal.state_root.as_str().to_owned(),
            recomputed: recomputed_state.as_str().to_owned(),
        });
    }

    seals.put(seal)?;
    for m in &accepted {
        moves.mark_sealed(&m.id, &seal.id)?;
    }

    Ok(SealEffect {
        seal: seal.id.clone(),
        accepted_move_ids: accepted.iter().map(|m| m.id.clone()).collect(),
        rejected_moves: Vec::new(),
        post_state_root: recomputed_state,
    })
}

pub fn effective_seal_view(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<EffectiveSealView, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let union_proof = leaf_union_proof(&sorted, seals)?;
    let covered = union_covered_from_proof(&union_proof);
    let covered_event_digests: Vec<MoveId> = covered.iter().cloned().collect();
    let control_event_set_root = control_event_set_root(&covered)?;
    let post_state = effective_state_at(&sorted, realm_id, seals, cells, registry)?;
    let state_root = compute_state_root(&post_state)
        .map_err(|e| SealReject::Store(format!("state_root: {e}")))?;
    let view_hash = joined_control_view_hash(
        &sorted,
        &covered_event_digests,
        &control_event_set_root,
        &state_root,
    )?;

    Ok(EffectiveSealView {
        predecessor_refs: sorted,
        covered_event_digests,
        control_event_set_root,
        state_root,
        union_proof,
        view_hash,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveSealView {
    pub predecessor_refs: Vec<SealId>,
    pub covered_event_digests: Vec<MoveId>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub union_proof: Vec<SealLeafUnionProof>,
    pub view_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealLeafUnionProof {
    pub leaf: SealId,
    pub covered_event_digests: Vec<MoveId>,
    pub control_event_set_root: Hash,
}

pub fn union_predecessor_covered_events(
    predecessor_refs: &[SealId],
    seals: &dyn SealStore,
) -> Result<BTreeSet<MoveId>, SealReject> {
    let mut out = BTreeSet::new();
    for predecessor in predecessor_refs {
        collect_covered_events(predecessor, seals, &mut out)?;
    }
    Ok(out)
}

pub fn leaf_union_proof(
    leaves: &[SealId],
    seals: &dyn SealStore,
) -> Result<Vec<SealLeafUnionProof>, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    sorted
        .into_iter()
        .map(|leaf| {
            let mut covered = BTreeSet::new();
            collect_covered_events(&leaf, seals, &mut covered)?;
            let covered_event_digests: Vec<MoveId> = covered.iter().cloned().collect();
            let control_event_set_root = control_event_set_root(&covered)?;
            Ok(SealLeafUnionProof {
                leaf,
                covered_event_digests,
                control_event_set_root,
            })
        })
        .collect()
}

fn union_covered_from_proof(proof: &[SealLeafUnionProof]) -> BTreeSet<MoveId> {
    proof
        .iter()
        .flat_map(|leaf| leaf.covered_event_digests.iter().cloned())
        .collect()
}

fn collect_covered_events(
    seal_id: &SealId,
    seals: &dyn SealStore,
    out: &mut BTreeSet<MoveId>,
) -> Result<(), SealReject> {
    let seal = seals
        .get(seal_id)?
        .ok_or_else(|| SealReject::Store(format!("predecessor {seal_id} not in store")))?;
    if !seal.covered_event_digests.is_empty() {
        out.extend(seal.covered_event_digests);
        return Ok(());
    }
    for predecessor in &seal.predecessor_refs {
        collect_covered_events(predecessor, seals, out)?;
    }
    out.extend(seal.delta);
    Ok(())
}

pub fn control_event_set_root(covered: &BTreeSet<MoveId>) -> Result<Hash, SealReject> {
    let leaves: Result<Vec<Vec<u8>>, SealReject> = covered
        .iter()
        .map(|m| {
            let digest = m.as_str().strip_prefix("sha256:").ok_or_else(|| {
                SealReject::Structural(format!("unsupported control event digest suite: {m}"))
            })?;
            hex::decode(digest).map_err(|e| {
                SealReject::Structural(format!("invalid control event digest {m}: {e}"))
            })
        })
        .collect();
    seal_merkle_root_from_leaf_data(&leaves?)
        .map_err(|e| SealReject::Store(format!("control_event_set_root: {e}")))
}

pub fn effective_state_at(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let covered = union_predecessor_covered_events(leaves, seals)?;
    effective_state_for_covered_events(&covered, realm_id, cells, registry)
}

fn effective_state_for_covered_events(
    covered: &BTreeSet<MoveId>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let mut out = BTreeMap::new();
    for cell in cells.list_cells(realm_id)? {
        let ops: Vec<SealedOp> = cells
            .sealed_ops_for_cell(realm_id, &cell)?
            .into_iter()
            .filter(|op| covered.contains(&op.move_id))
            .collect();
        if ops.is_empty() {
            continue;
        }
        let binding = registry.resolve(realm_id, &cell)?;
        let state = binding.lattice.join(&cell, &ops);
        out.insert(cell, state);
    }
    Ok(out)
}

pub fn deterministic_order(mut moves: Vec<Move>) -> Vec<Move> {
    let mut out = Vec::with_capacity(moves.len());
    while !moves.is_empty() {
        let mut ready = Vec::new();
        let remaining_ids: BTreeSet<String> =
            moves.iter().map(|m| m.id.as_str().to_owned()).collect();
        let mut blocked = Vec::new();
        for m in moves {
            if move_causal_dependencies(&m)
                .iter()
                .any(|dep| remaining_ids.contains(dep))
            {
                blocked.push(m);
            } else {
                ready.push(m);
            }
        }
        if ready.is_empty() {
            blocked.sort_by(concurrent_move_order);
            out.extend(blocked);
            break;
        }
        ready.sort_by(concurrent_move_order);
        out.extend(ready);
        moves = blocked;
    }
    out
}

fn concurrent_move_order(a: &Move, b: &Move) -> std::cmp::Ordering {
    b.id.as_str()
        .cmp(a.id.as_str())
        .then_with(|| a.hlc.as_str().cmp(b.hlc.as_str()))
        .then_with(|| a.issuer.as_str().cmp(b.issuer.as_str()))
}

fn move_causal_dependencies(m: &Move) -> Vec<String> {
    m.refs
        .iter()
        .filter(|reference| {
            matches!(
                reference.role.as_str(),
                "after" | "parent_move" | "recovery_capability"
            )
        })
        .map(|reference| reference.id.clone())
        .collect()
}

fn joined_control_view_hash(
    leaves: &[SealId],
    covered_event_digests: &[MoveId],
    control_event_set_root: &Hash,
    state_root: &Hash,
) -> Result<Hash, SealReject> {
    let json = serde_json::json!({
        "schema": "ak.schema.joined_control_view.v1",
        "leaves": leaves.iter().map(|leaf| leaf.as_str()).collect::<Vec<_>>(),
        "covered_event_digests": covered_event_digests
            .iter()
            .map(|event| event.as_str())
            .collect::<Vec<_>>(),
        "control_event_set_root": control_event_set_root.as_str(),
        "state_root": state_root.as_str(),
    });
    let bytes = canonical::canonical_json_bytes(&json)
        .map_err(|e| SealReject::Store(format!("joined_control_view_hash: {e}")))?;
    Hash::new(canonical::sha256_digest(&bytes))
        .map_err(|e| SealReject::Structural(format!("invalid joined control view hash: {e}")))
}

pub fn view_hash(leaves: &[SealId]) -> Result<Hash, crate::Error> {
    let mut sorted: Vec<&str> = leaves.iter().map(|a| a.as_str()).collect();
    sorted.sort();
    let json: Value = serde_json::to_value(&sorted)?;
    let bytes = canonical::canonical_json_bytes(&json)?;
    Hash::new(canonical::sha256_digest(&bytes))
        .map_err(|e| crate::Error::Protocol(format!("invalid view_hash: {e}")))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::lattice::SealedOp;
    use crate::state::store::memory::{MemoryCellRegistry, MemoryCellStore, MemorySealStore};
    use crate::state::store::{CellStore, SealStore};
    use crate::{
        Did, Hlc, LatticeOp, LatticeOpType, MoveSignature, NotarySig, SealBasis, SealKind,
        SemanticRef,
    };

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn seal_id(byte: u8) -> SealId {
        SealId::new(format!(
            "ak:seal:sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn capability_cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.capability.grant.v1:ak:grant:0196410c-0000-7000-8000-000000000000"
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

    fn dummy_signature() -> MoveSignature {
        MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:notary.example#k1".to_owned(),
            payload_digest: hash(0xff),
            created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
    }

    fn materialized_seal(id: SealId, covered: Vec<MoveId>) -> Seal {
        Seal {
            id,
            realm_id: realm(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root: hash(0x22),
            state_root: hash(0x77),
            completeness_root: hash(0x33),
            notary_seq: 1,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: covered,
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(dummy_signature()),
            sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: SealKind::Normal,
        }
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

    fn move_for_order(byte: u8, refs: Vec<SemanticRef>) -> Move {
        Move {
            id: move_id(byte),
            issuer: Did::new("did:webvh:z6mkfixture:issuer.example".to_owned()).unwrap(),
            realm_id: realm(),
            preconditions: Vec::new(),
            effects: Vec::new(),
            seal_basis: SealBasis {
                leaves: vec![seal_id(0x11)],
                control_event_set_root: hash(0x22),
                state_root: hash(0x33),
            },
            refs,
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            sig: dummy_signature(),
        }
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
                    SealedOp::new(move_a, add_op("a", "visible-at-a")),
                )],
            )
            .unwrap();
        cells
            .append_sealed_effects(
                &realm,
                &seal_b.id,
                &[(
                    cell.clone(),
                    SealedOp::new(move_b, add_op("b", "visible-at-b")),
                )],
            )
            .unwrap();
        seals.put(&seal_a).unwrap();
        seals.put(&seal_b).unwrap();

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
        seals.put(&seal_b).unwrap();
        seals.put(&seal_a).unwrap();

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

        assert_eq!(first.predecessor_refs, vec![seal_a.id, seal_b.id]);
        assert_eq!(first.covered_event_digests, vec![move_a, move_b]);
        assert_eq!(first.union_proof.len(), 2);
        assert_eq!(first.view_hash, second.view_hash);
        assert_eq!(first.state_root, second.state_root);
    }

    #[test]
    fn deterministic_order_respects_causality_then_digest_desc() {
        let low = move_for_order(0x10, Vec::new());
        let mid = move_for_order(0x20, Vec::new());
        let high_depends_on_low = move_for_order(
            0xf0,
            vec![SemanticRef {
                id: low.id.as_str().to_owned(),
                role: "after".to_owned(),
                critical: true,
            }],
        );

        let ordered =
            deterministic_order(vec![high_depends_on_low.clone(), mid.clone(), low.clone()]);
        let ids = ordered
            .iter()
            .map(|m| m.id.as_str().to_owned())
            .collect::<Vec<_>>();

        assert_eq!(ids[0], mid.id.as_str());
        assert_eq!(ids[1], low.id.as_str());
        assert_eq!(ids[2], high_depends_on_low.id.as_str());
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
                        SealedOp::new(join_id, transition("invited", "join")),
                    ),
                    (
                        cell.clone(),
                        SealedOp::new(ban_id, transition("join", "ban")),
                    ),
                ],
            )
            .unwrap();
        seals.put(&seal).unwrap();

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
}
