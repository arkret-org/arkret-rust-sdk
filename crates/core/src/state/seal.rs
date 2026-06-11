//! Seal application and effective-view helpers.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::state_root::compute_state_root;
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
    if seal.predecessor_refs.is_empty() && !seal.delta.is_empty() {
        return Err(SealReject::Structural(
            "Genesis Seal MUST have delta=[]; predecessor_refs=[] with non-empty delta is invalid"
                .to_owned(),
        ));
    }
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

    let pre_state = effective_state_at(&seal.predecessor_refs, &seal.realm_id, cells, registry)?;

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

    let post_state = effective_state_at(
        std::slice::from_ref(&seal.id),
        &seal.realm_id,
        cells,
        registry,
    )
    .unwrap_or_else(|_| compute_post_state_direct(&seal.realm_id, cells, registry));
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
    let covered = union_predecessor_covered_events(&sorted, seals)?;
    let covered_event_digests: Vec<MoveId> = covered.iter().cloned().collect();
    let control_event_set_root = control_event_set_root(&covered)?;
    let post_state = effective_state_at(&sorted, realm_id, cells, registry)?;
    let state_root = compute_state_root(&post_state)
        .map_err(|e| SealReject::Store(format!("state_root: {e}")))?;

    Ok(EffectiveSealView {
        predecessor_refs: sorted,
        covered_event_digests,
        control_event_set_root,
        state_root,
    })
}

#[derive(Clone, Debug)]
pub struct EffectiveSealView {
    pub predecessor_refs: Vec<SealId>,
    pub covered_event_digests: Vec<MoveId>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
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
    let leaves: Result<Vec<Hash>, SealReject> = covered
        .iter()
        .map(|m| {
            Hash::new(m.as_str().to_owned())
                .map_err(|e| SealReject::Structural(format!("invalid control event digest: {e}")))
        })
        .collect();
    crate::snapshot::merkle_root_from_hashes(leaves?)
        .map_err(|e| SealReject::Store(format!("control_event_set_root: {e}")))
}

pub fn effective_state_at(
    _leaves: &[SealId],
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let mut out = BTreeMap::new();
    for cell in cells.list_cells(realm_id)? {
        let ops = cells.sealed_ops_for_cell(realm_id, &cell)?;
        let binding = registry.resolve(realm_id, &cell)?;
        let state = binding.lattice.join(&cell, &ops);
        out.insert(cell, state);
    }
    Ok(out)
}

fn compute_post_state_direct(
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> BTreeMap<CellRef, CellState> {
    let mut out = BTreeMap::new();
    let Ok(cell_list) = cells.list_cells(realm_id) else {
        return out;
    };
    for cell in cell_list {
        let Ok(ops) = cells.sealed_ops_for_cell(realm_id, &cell) else {
            continue;
        };
        let Ok(binding) = registry.resolve(realm_id, &cell) else {
            continue;
        };
        out.insert(cell.clone(), binding.lattice.join(&cell, &ops));
    }
    out
}

pub fn deterministic_order(mut moves: Vec<Move>) -> Vec<Move> {
    moves.sort_by(|a, b| {
        a.hlc
            .as_str()
            .cmp(b.hlc.as_str())
            .then_with(|| a.issuer.as_str().cmp(b.issuer.as_str()))
            .then_with(|| a.id.as_str().cmp(b.id.as_str()))
    });
    moves
}

pub fn view_hash(leaves: &[SealId]) -> Result<Hash, crate::Error> {
    let mut sorted: Vec<&str> = leaves.iter().map(|a| a.as_str()).collect();
    sorted.sort();
    let json: Value = serde_json::to_value(&sorted)?;
    let bytes = canonical::canonical_json_bytes(&json)?;
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Hash::new(format!("sha256:{hex}"))
        .map_err(|e| crate::Error::Protocol(format!("invalid view_hash: {e}")))
}
