//! `apply_anchor` and `effective_anchor_view` per spec §4.1 / §4.3.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Anchor, AnchorId, CellRef, Hash, Move, MoveId, SpaceId, canonical,
    lattice::{AnchoredOp, CellState},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::state_root::compute_state_root;
use super::store::{AnchorStore, CellRegistry, CellStore, MoveStore};
use super::verify::verify_move;

/// Result of a successful `apply_anchor`.
#[derive(Clone, Debug)]
pub struct AnchorEffect {
    pub anchor: AnchorId,
    pub accepted_move_ids: Vec<MoveId>,
    pub rejected_moves: Vec<(MoveId, String)>,
    pub post_state_root: Hash,
}

#[derive(Debug, Error)]
pub enum AnchorReject {
    #[error("Anchor structural / signature error: {0}")]
    Structural(String),

    #[error("Anchor predecessor_refs contain unknown ids")]
    UnknownPredecessor,

    #[error("Anchor.frontier is not a superset of predecessor frontier union")]
    FrontierNotMonotonic,

    #[error("Move {move_id} referenced in frontier but not in store")]
    MissingMove { move_id: String },

    #[error("declared state_root {declared} does not match recomputed {recomputed}")]
    StateRootMismatch { declared: String, recomputed: String },

    #[error("store error: {0}")]
    Store(String),
}

impl From<super::store::StoreError> for AnchorReject {
    fn from(e: super::store::StoreError) -> Self {
        AnchorReject::Store(e.to_string())
    }
}

/// Apply an Anchor end-to-end (spec §4.3).
///
/// `verify_jws` is a caller-supplied closure (signature pluggability —
/// see [`verify_move`]).
pub fn apply_anchor<F>(
    a: &Anchor,
    moves: &dyn MoveStore,
    anchors: &dyn AnchorStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    verify_jws: F,
) -> Result<AnchorEffect, AnchorReject>
where
    F: Fn(&[u8], &str, &str, &str) -> Result<(), String> + Copy,
{
    // Step 1: structural + id round-trip.
    a.validate_id().map_err(|e| AnchorReject::Structural(format!("id: {e}")))?;
    a.validate_structural().map_err(|e| AnchorReject::Structural(e.to_string()))?;
    if a.predecessor_refs.is_empty() && !a.frontier.is_empty() {
        return Err(AnchorReject::Structural(
            "Genesis Anchor MUST have frontier=[]; predecessor_refs=[] with non-empty frontier is invalid"
                .to_owned(),
        ));
    }

    // Step 2: predecessors known.
    if !anchors.predecessors_known(&a.predecessor_refs)? {
        return Err(AnchorReject::UnknownPredecessor);
    }

    // Step 3: frontier monotonicity vs predecessor frontier union.
    let pred_union = union_predecessor_frontiers(&a.predecessor_refs, anchors)?;
    let frontier_set: BTreeSet<MoveId> = a.frontier.iter().cloned().collect();
    if !pred_union.iter().all(|m| frontier_set.contains(m)) {
        return Err(AnchorReject::FrontierNotMonotonic);
    }

    // Step 4: pre_state from predecessor view.
    let pre_state = effective_state_at(&a.predecessor_refs, &a.realm_id, cells, registry)?;

    // Step 5: deterministic_order over new Moves; verify each.
    let new_move_ids: Vec<MoveId> =
        a.frontier.iter().filter(|m| !pred_union.contains(m)).cloned().collect();
    let mut new_moves: Vec<Move> = Vec::with_capacity(new_move_ids.len());
    for mid in &new_move_ids {
        let m = moves
            .get(mid)?
            .ok_or_else(|| AnchorReject::MissingMove { move_id: mid.as_str().to_owned() })?;
        new_moves.push(m);
    }
    let ordered = deterministic_order(new_moves);

    let mut accepted: Vec<Move> = Vec::with_capacity(ordered.len());
    let mut rejected: Vec<(MoveId, String)> = Vec::new();
    for m in ordered {
        match verify_move(&m, &pre_state, registry, verify_jws) {
            Ok(()) => accepted.push(m),
            Err(reject) => rejected.push((m.id.clone(), reject.to_string())),
        }
    }

    // Step 6: append accepted effects atomically.
    let mut new_ops: Vec<(CellRef, AnchoredOp)> = Vec::new();
    for m in &accepted {
        for effect in &m.effects {
            let aop = AnchoredOp::new(m.id.clone(), effect.op.clone());
            new_ops.push((effect.cell.clone(), aop));
        }
    }
    cells.append_anchored_effects(&a.realm_id, &a.id, &new_ops)?;

    // Step 7: recompute state_root, compare against declared.
    let post_state = effective_state_at(std::slice::from_ref(&a.id), &a.realm_id, cells, registry)
        .unwrap_or_else(|_| {
            // If post-state computation fails (e.g. we just appended; the new Anchor
            // isn't yet in AnchorStore), recompute directly from the cell store
            // contents — equivalent to "all anchored ops applied so far".
            compute_post_state_direct(&a.realm_id, cells, registry)
        });
    let recomputed = compute_state_root(&post_state)
        .map_err(|e| AnchorReject::Store(format!("state_root recompute failed: {e}")))?;
    if recomputed.as_str() != a.state_root.as_str() {
        // Roll back step 6.
        cells.rollback_anchor(&a.realm_id, &a.id)?;
        return Err(AnchorReject::StateRootMismatch {
            declared: a.state_root.as_str().to_owned(),
            recomputed: recomputed.as_str().to_owned(),
        });
    }

    // Step 8: persist Anchor + mark accepted Moves anchored.
    anchors.put(a)?;
    for m in &accepted {
        moves.mark_anchored(&m.id, &a.id)?;
    }

    Ok(AnchorEffect {
        anchor: a.id.clone(),
        accepted_move_ids: accepted.iter().map(|m| m.id.clone()).collect(),
        rejected_moves: rejected,
        post_state_root: recomputed,
    })
}

/// Spec §4.1 deterministic effective Anchor view from a leaf set.
///
/// Returns predecessor_refs (sorted by id), the union frontier, and the
/// state_root recomputed under that view. Pure function — does not write
/// any Anchor object.
pub fn effective_anchor_view(
    leaves: &[AnchorId],
    space_id: &SpaceId,
    anchors: &dyn AnchorStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<EffectiveAnchorView, AnchorReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));

    let mut frontier_set: BTreeSet<MoveId> = BTreeSet::new();
    for leaf in &sorted {
        let anchor = anchors
            .get(leaf)?
            .ok_or_else(|| AnchorReject::Store(format!("leaf {leaf} not in store")))?;
        for m in &anchor.frontier {
            frontier_set.insert(m.clone());
        }
    }
    let frontier: Vec<MoveId> = frontier_set.into_iter().collect();

    let post_state = effective_state_at(&sorted, space_id, cells, registry)?;
    let state_root = compute_state_root(&post_state)
        .map_err(|e| AnchorReject::Store(format!("state_root: {e}")))?;

    Ok(EffectiveAnchorView { predecessor_refs: sorted, frontier, state_root })
}

/// Materialized result of [`effective_anchor_view`].
#[derive(Clone, Debug)]
pub struct EffectiveAnchorView {
    pub predecessor_refs: Vec<AnchorId>,
    pub frontier: Vec<MoveId>,
    pub state_root: Hash,
}

/// Compute the union of predecessor Anchors' frontiers.
pub fn union_predecessor_frontiers(
    predecessor_refs: &[AnchorId],
    anchors: &dyn AnchorStore,
) -> Result<BTreeSet<MoveId>, AnchorReject> {
    let mut out = BTreeSet::new();
    for p in predecessor_refs {
        let anchor = anchors
            .get(p)?
            .ok_or_else(|| AnchorReject::Store(format!("predecessor {p} not in store")))?;
        for m in &anchor.frontier {
            out.insert(m.clone());
        }
    }
    Ok(out)
}

/// Compute the per-cell effective state under the given Anchor leaf view.
///
/// In v1 we ignore the `leaves` list and read directly from the
/// `CellStore`'s persisted `cell_log` — every Move that has been anchored
/// is in the log, and the runtime ensures the log only contains effects
/// from successfully-validated Anchors. Future versions may filter by
/// reachability when DAG branches diverge.
pub fn effective_state_at(
    _leaves: &[AnchorId],
    space_id: &SpaceId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, AnchorReject> {
    let mut out = BTreeMap::new();
    for cell in cells.list_cells(space_id)? {
        let ops = cells.anchored_ops_for_cell(space_id, &cell)?;
        let binding = registry.resolve(space_id, &cell)?;
        let state = binding.lattice.join(&cell, &ops);
        out.insert(cell, state);
    }
    Ok(out)
}

/// Same as `effective_state_at` but bypasses the AnchorStore — used as
/// fallback inside `apply_anchor` step 7 when the new Anchor isn't yet
/// committed but its effects have already been appended.
fn compute_post_state_direct(
    space_id: &SpaceId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> BTreeMap<CellRef, CellState> {
    let mut out = BTreeMap::new();
    let Ok(cell_list) = cells.list_cells(space_id) else {
        return out;
    };
    for cell in cell_list {
        let Ok(ops) = cells.anchored_ops_for_cell(space_id, &cell) else {
            continue;
        };
        let Ok(binding) = registry.resolve(space_id, &cell) else {
            continue;
        };
        out.insert(cell.clone(), binding.lattice.join(&cell, &ops));
    }
    out
}

/// Deterministic ordering of Moves within an Anchor batch.
///
/// Per spec §4.3, the per-Move verifier walks new Moves in a deterministic
/// order so all conformant implementations produce the same accept /
/// reject decision. The order is `(hlc, issuer, id)` ascending.
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

/// Compute a stable hash over an ordered set of Anchor leaf ids — used
/// as the cache key for per-view effective-state caches.
pub fn view_hash(leaves: &[AnchorId]) -> Result<Hash, crate::Error> {
    let mut sorted: Vec<&str> = leaves.iter().map(|a| a.as_str()).collect();
    sorted.sort();
    let json: Value = serde_json::to_value(&sorted)?;
    let bytes = canonical::canonical_json_bytes(&json)?;
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Hash::new(format!("sha256:{hex}"))
        .map_err(|e| crate::Error::Protocol(format!("invalid view_hash: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnchorerSig, Hlc, MoveSignature, lattice::CellState};
    use serde_json::json;

    use crate::state::store::memory::{
        MemoryAnchorStore, MemoryCellRegistry, MemoryCellStore, MemoryMoveStore,
    };

    fn space() -> SpaceId {
        SpaceId::new("cx:space:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn cell_member() -> CellRef {
        CellRef::new("cx:cell:cx.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    fn build_move(from: &str, to: &str) -> Move {
        let body = json!({
            "issuer": "did:web:admin.example",
            "space_id": space().as_str(),
            "preconditions": [],
            "effects": [{
                "cell": cell_member().as_str(),
                "op": { "kind": "transition", "from": from, "to": to }
            }],
            "anchor_ref": format!("cx:anchor:sha256:{}", "aa".repeat(32)),
            "refs": [],
            "hlc": format!("0189c4d2af00-0000-{:08x}", from.len() * 100 + to.len())
        });
        let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
        let payload_digest = canonical::sha256_digest(&body_bytes);
        let id_hex: String =
            Sha256::digest(&body_bytes).iter().map(|b| format!("{b:02x}")).collect();
        let mut full = body.as_object().unwrap().clone();
        full.insert("id".into(), Value::String(format!("sha256:{id_hex}")));
        full.insert(
            "sig".into(),
            json!({
                "alg": "EdDSA",
                "verification_method": "did:web:admin.example#k1",
                "payload_digest": payload_digest,
                "created_at": "2026-05-08T00:00:00Z",
                "jws": "AAAA.BBBB.CCCC"
            }),
        );
        serde_json::from_value(Value::Object(full)).unwrap()
    }

    fn build_anchor(
        predecessors: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
    ) -> Anchor {
        let sig = MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:anchorer.example#k1".to_owned(),
            payload_digest: Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap(),
            created_at: chrono::Utc::now(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        };
        let mut a = Anchor {
            id: AnchorId::new(format!("cx:anchor:sha256:{}", "00".repeat(32))).unwrap(),
            realm_id: space(),
            predecessor_refs: predecessors,
            frontier,
            state_root,
            previous_state_root: None,
            previous_digest_algorithm: None,
            anchorer_signature: AnchorerSig::Single(sig),
            anchored_at: chrono::Utc::now(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: crate::AnchorKind::Normal,
        };
        a.id = a.derive_id().unwrap();
        a
    }

    fn ok_jws(_: &[u8], _: &str, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn deterministic_order_sorts_by_hlc_then_id() {
        let m1 = build_move("invited", "join");
        let m2 = build_move("join", "leave");
        // m2 has longer hlc trailing hex; deterministic_order sorts by hlc.
        let ordered = deterministic_order(vec![m2.clone(), m1.clone()]);
        assert_eq!(ordered[0].hlc.as_str(), m1.hlc.as_str().min(m2.hlc.as_str()));
    }

    #[test]
    fn view_hash_is_order_independent() {
        let a = AnchorId::new(format!("cx:anchor:sha256:{}", "11".repeat(32))).unwrap();
        let b = AnchorId::new(format!("cx:anchor:sha256:{}", "22".repeat(32))).unwrap();
        let h1 = view_hash(&[a.clone(), b.clone()]).unwrap();
        let h2 = view_hash(&[b, a]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn view_hash_distinguishes_different_leaf_sets() {
        let a = AnchorId::new(format!("cx:anchor:sha256:{}", "11".repeat(32))).unwrap();
        let b = AnchorId::new(format!("cx:anchor:sha256:{}", "22".repeat(32))).unwrap();
        let h1 = view_hash(std::slice::from_ref(&a)).unwrap();
        let h2 = view_hash(&[a, b]).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn empty_predecessor_frontier_union_is_empty() {
        let store = MemoryAnchorStore::default();
        let result = union_predecessor_frontiers(&[], &store).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn apply_anchor_genesis_then_successor_with_one_move_succeeds() {
        let moves = MemoryMoveStore::default();
        let anchors = MemoryAnchorStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::new();

        let m = build_move("invited", "join");
        moves.put_pending(&m).unwrap();

        let empty_root = Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap();
        let genesis = build_anchor(vec![], vec![], empty_root.clone());
        let genesis_effect =
            apply_anchor(&genesis, &moves, &anchors, &cells, &registry, ok_jws).unwrap();
        assert!(genesis_effect.accepted_move_ids.is_empty());
        assert_eq!(genesis_effect.post_state_root, empty_root);

        // Compute expected state_root: after this Move, member.state = "join" via FSM.
        let mut expected = BTreeMap::new();
        expected.insert(cell_member(), CellState::Value(json!("join")));
        let expected_root = compute_state_root(&expected).unwrap();

        let a = build_anchor(vec![genesis.id.clone()], vec![m.id.clone()], expected_root.clone());
        let effect = apply_anchor(&a, &moves, &anchors, &cells, &registry, ok_jws).unwrap();

        assert_eq!(effect.accepted_move_ids, vec![m.id]);
        assert!(effect.rejected_moves.is_empty());
        assert_eq!(effect.post_state_root, expected_root);
        assert_eq!(anchors.list_leaves(&space()).unwrap(), vec![a.id]);
    }

    #[test]
    fn apply_anchor_rejects_non_empty_frontier_without_genesis_predecessor() {
        let moves = MemoryMoveStore::default();
        let anchors = MemoryAnchorStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::new();

        let m = build_move("invited", "join");
        moves.put_pending(&m).unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(cell_member(), CellState::Value(json!("join")));
        let expected_root = compute_state_root(&expected).unwrap();

        let a = build_anchor(vec![], vec![m.id], expected_root);
        let err = apply_anchor(&a, &moves, &anchors, &cells, &registry, ok_jws).unwrap_err();
        match err {
            AnchorReject::Structural(reason) => assert!(reason.contains("frontier=[]")),
            other => panic!("expected Structural reject, got {other:?}"),
        }
    }

    #[test]
    fn apply_anchor_unknown_predecessor_rejected() {
        let moves = MemoryMoveStore::default();
        let anchors = MemoryAnchorStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::new();

        let bad_pred = AnchorId::new(format!("cx:anchor:sha256:{}", "ee".repeat(32))).unwrap();
        let a = build_anchor(
            vec![bad_pred],
            vec![],
            Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap(),
        );
        let err = apply_anchor(&a, &moves, &anchors, &cells, &registry, ok_jws).unwrap_err();
        assert!(matches!(err, AnchorReject::UnknownPredecessor));
    }

    #[test]
    fn apply_anchor_state_root_mismatch_rolls_back() {
        let moves = MemoryMoveStore::default();
        let anchors = MemoryAnchorStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::new();

        let m = build_move("invited", "join");
        moves.put_pending(&m).unwrap();

        let empty_root = Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap();
        let genesis = build_anchor(vec![], vec![], empty_root);
        apply_anchor(&genesis, &moves, &anchors, &cells, &registry, ok_jws).unwrap();

        // Wrong state_root: claim it's still empty, even though the Move changes the cell.
        let wrong_root = Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap();
        let a = build_anchor(vec![genesis.id], vec![m.id], wrong_root);
        let err = apply_anchor(&a, &moves, &anchors, &cells, &registry, ok_jws).unwrap_err();
        match err {
            AnchorReject::StateRootMismatch { .. } => {}
            other => panic!("expected StateRootMismatch, got {other:?}"),
        }
        // Cell store rolled back to the genesis-empty baseline.
        assert!(cells.list_cells(&space()).unwrap().is_empty());
    }

    #[test]
    fn effective_anchor_view_orders_predecessors() {
        let anchors = MemoryAnchorStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::new();

        let genesis = build_anchor(
            vec![],
            vec![],
            Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap(),
        );
        anchors.put(&genesis).unwrap();

        // Two successor leaves share the Genesis Anchor as predecessor.
        let m1 = build_move("invited", "join");
        let m2 = build_move("join", "leave");
        let a1 = build_anchor(
            vec![genesis.id.clone()],
            vec![m1.id.clone()],
            Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap(),
        );
        let a2 = build_anchor(
            vec![genesis.id],
            vec![m2.id.clone()],
            Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap(),
        );
        anchors.put(&a1).unwrap();
        anchors.put(&a2).unwrap();

        let view = effective_anchor_view(
            &[a2.id.clone(), a1.id.clone()],
            &space(),
            &anchors,
            &cells,
            &registry,
        )
        .unwrap();
        // Predecessor refs sorted ascending by id.
        let ids: Vec<&str> = view.predecessor_refs.iter().map(|a| a.as_str()).collect();
        let mut expected = vec![a1.id.as_str(), a2.id.as_str()];
        expected.sort();
        assert_eq!(ids, expected);
        // Frontier is union (both moves).
        assert!(view.frontier.contains(&m1.id));
        assert!(view.frontier.contains(&m2.id));
    }
}
