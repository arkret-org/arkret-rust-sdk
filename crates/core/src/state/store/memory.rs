//! In-memory implementations of the four store traits.
//!
//! These are the test backbone: they let SDK unit tests exercise
//! `verify_move` / `apply_anchor` / `state_root` end-to-end without a
//! database. Production servers (soland) implement durable backends
//! against the same trait surface.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::{
    Anchor, AnchorId, CellRef, Hash, Move, MoveId, SpaceId,
    lattice::{
        AnchoredOp, CasRegister, CellState, Counter, Fsm, Lattice, LatticeKind, MvRegister, OrSet,
        OrderedLog,
    },
};
use serde_json::{Value, json};

use super::{
    AnchorStore, AnchoredMoveRecord, BottomMode, CellLatticeBinding, CellRegistry, CellStore,
    MoveStore, StoreError, StoreResult,
};

/// In-memory `MoveStore`.
#[derive(Default)]
pub struct MemoryMoveStore {
    inner: Mutex<MemoryMoveStoreInner>,
}

#[derive(Default)]
struct MemoryMoveStoreInner {
    /// All known Moves keyed by id.
    moves: BTreeMap<String, Move>,
    /// Anchor membership: move_id → anchor id (None means pending).
    anchored: BTreeMap<String, AnchorId>,
    /// Insertion order so list_pending is deterministic.
    insertion_order: Vec<String>,
}

impl MoveStore for MemoryMoveStore {
    fn put_pending(&self, m: &Move) -> StoreResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let id = m.id.as_str().to_owned();
        if !inner.moves.contains_key(&id) {
            inner.insertion_order.push(id.clone());
        }
        inner.moves.entry(id).or_insert_with(|| m.clone());
        Ok(())
    }

    fn mark_anchored(&self, id: &MoveId, anchor: &AnchorId) -> StoreResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.moves.contains_key(id.as_str()) {
            return Err(StoreError::NotFound(format!("Move {id} not in store")));
        }
        inner.anchored.insert(id.as_str().to_owned(), anchor.clone());
        Ok(())
    }

    fn get(&self, id: &MoveId) -> StoreResult<Option<Move>> {
        Ok(self.inner.lock().unwrap().moves.get(id.as_str()).cloned())
    }

    fn list_pending_for_anchorer(
        &self,
        space_id: &SpaceId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<Move>> {
        let inner = self.inner.lock().unwrap();
        let cursor_str = cursor.map(|c| c.as_str().to_owned());
        let mut started = cursor_str.is_none();
        let mut out = Vec::new();
        for id in &inner.insertion_order {
            if !started {
                if Some(id.as_str()) == cursor_str.as_deref() {
                    started = true;
                }
                continue;
            }
            if let Some(m) = inner.moves.get(id)
                && m.space_id == *space_id
                && !inner.anchored.contains_key(id)
            {
                out.push(m.clone());
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn list_anchored(
        &self,
        space_id: &SpaceId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<AnchoredMoveRecord>> {
        let inner = self.inner.lock().unwrap();
        let cursor_str = cursor.map(|c| c.as_str().to_owned());
        let mut started = cursor_str.is_none();
        let mut out = Vec::new();
        for id in &inner.insertion_order {
            if !started {
                if Some(id.as_str()) == cursor_str.as_deref() {
                    started = true;
                }
                continue;
            }
            if let (Some(m), Some(a)) = (inner.moves.get(id), inner.anchored.get(id))
                && m.space_id == *space_id
            {
                out.push(AnchoredMoveRecord { move_value: m.clone(), anchor: a.clone() });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }
}

/// In-memory `AnchorStore`.
#[derive(Default)]
pub struct MemoryAnchorStore {
    inner: Mutex<MemoryAnchorStoreInner>,
}

#[derive(Default)]
struct MemoryAnchorStoreInner {
    anchors: BTreeMap<String, Anchor>,
    /// space_id → leaves (anchors with no successor)
    leaves: BTreeMap<String, Vec<AnchorId>>,
    /// space_id → genesis anchor (first put with empty predecessors)
    genesis: BTreeMap<String, AnchorId>,
}

impl AnchorStore for MemoryAnchorStore {
    fn put(&self, a: &Anchor) -> StoreResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let space = a.space_id.as_str().to_owned();
        let id_str = a.id.as_str().to_owned();
        inner.anchors.insert(id_str, a.clone());

        // Genesis: first anchor with empty predecessors.
        if a.predecessor_refs.is_empty() {
            inner.genesis.entry(space.clone()).or_insert_with(|| a.id.clone());
        }

        // Leaf set: remove all of `a.predecessor_refs` from leaves; add `a` as a new leaf.
        let leaves = inner.leaves.entry(space).or_default();
        leaves.retain(|leaf| !a.predecessor_refs.iter().any(|p| p == leaf));
        if !leaves.iter().any(|l| l == &a.id) {
            leaves.push(a.id.clone());
        }
        Ok(())
    }

    fn get(&self, id: &AnchorId) -> StoreResult<Option<Anchor>> {
        Ok(self.inner.lock().unwrap().anchors.get(id.as_str()).cloned())
    }

    fn list_leaves(&self, space_id: &SpaceId) -> StoreResult<Vec<AnchorId>> {
        Ok(self.inner.lock().unwrap().leaves.get(space_id.as_str()).cloned().unwrap_or_default())
    }

    fn predecessors_known(&self, refs: &[AnchorId]) -> StoreResult<bool> {
        let inner = self.inner.lock().unwrap();
        Ok(refs.iter().all(|r| inner.anchors.contains_key(r.as_str())))
    }

    fn genesis(&self, space_id: &SpaceId) -> StoreResult<Option<AnchorId>> {
        Ok(self.inner.lock().unwrap().genesis.get(space_id.as_str()).cloned())
    }

    fn successors(&self, space_id: &SpaceId, anchor_id: &AnchorId) -> StoreResult<Vec<AnchorId>> {
        let inner = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for anchor in inner.anchors.values() {
            if anchor.space_id.as_str() != space_id.as_str() {
                continue;
            }
            if anchor.predecessor_refs.iter().any(|p| p == anchor_id) {
                out.push(anchor.id.clone());
            }
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }

    fn prune_predecessor(
        &self,
        space_id: &SpaceId,
        anchor_id: &AnchorId,
    ) -> StoreResult<Vec<AnchorId>> {
        let mut inner = self.inner.lock().unwrap();
        // Snapshot the parents of the pruned anchor before removing it.
        let parents: Vec<AnchorId> = inner
            .anchors
            .get(anchor_id.as_str())
            .map(|a| a.predecessor_refs.clone())
            .ok_or_else(|| StoreError::NotFound(format!("anchor {anchor_id} not in store")))?;

        // Successor anchors whose predecessor_refs reference the pruned id.
        let successor_ids: Vec<String> = inner
            .anchors
            .values()
            .filter(|a| {
                a.space_id.as_str() == space_id.as_str()
                    && a.predecessor_refs.iter().any(|p| p == anchor_id)
            })
            .map(|a| a.id.as_str().to_owned())
            .collect();

        if successor_ids.is_empty() {
            return Err(StoreError::Conflict(format!(
                "anchor {anchor_id} has no successors; can't prune a leaf via prune_predecessor"
            )));
        }

        // Rewire each successor: remove the pruned id, splice in the parents.
        // Dedup so a successor that previously referenced both pruned and
        // a grandparent doesn't end up with the same predecessor twice.
        for sid in &successor_ids {
            if let Some(succ) = inner.anchors.get_mut(sid) {
                let mut new_refs: Vec<AnchorId> =
                    succ.predecessor_refs.iter().filter(|p| *p != anchor_id).cloned().collect();
                for parent in &parents {
                    if !new_refs.iter().any(|p| p == parent) {
                        new_refs.push(parent.clone());
                    }
                }
                new_refs.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                succ.predecessor_refs = new_refs;
            }
        }

        // Remove the pruned anchor itself.
        inner.anchors.remove(anchor_id.as_str());

        // Pruned anchor can't have been a leaf (we checked above) and its
        // parents already had their successor-rewiring done before this
        // anchor existed, so the leaf set is unaffected. Nothing to do
        // with `leaves`.

        // Genesis: if we pruned the genesis (which only makes sense if a
        // child compaction replaces it), forget the genesis pointer — the
        // caller MUST set a new one explicitly when relevant.
        let space = space_id.as_str();
        if inner.genesis.get(space).is_some_and(|g| g.as_str() == anchor_id.as_str()) {
            inner.genesis.remove(space);
        }

        let rewired: Vec<AnchorId> =
            successor_ids.into_iter().filter_map(|s| AnchorId::new(s).ok()).collect();
        Ok(rewired)
    }
}

/// In-memory `CellStore`.
#[derive(Default)]
pub struct MemoryCellStore {
    inner: Mutex<MemoryCellStoreInner>,
}

#[derive(Default)]
struct MemoryCellStoreInner {
    /// (space, cell) → ordered AnchoredOp list
    cell_log: BTreeMap<(String, String), Vec<AnchoredOp>>,
    /// (space, cell, view_hash) → CellState
    cache: BTreeMap<(String, String, String), CellState>,
    /// anchor → ops it appended (used for rollback)
    anchor_ops: BTreeMap<String, Vec<(String, AnchoredOp)>>, // (space, cell), op
}

impl CellStore for MemoryCellStore {
    fn list_cells(&self, space_id: &SpaceId) -> StoreResult<Vec<CellRef>> {
        let inner = self.inner.lock().unwrap();
        let mut cells = Vec::new();
        for (space, cell) in inner.cell_log.keys() {
            if space == space_id.as_str() {
                cells.push(
                    CellRef::new(cell.clone()).map_err(|e| StoreError::Backend(e.to_string()))?,
                );
            }
        }
        Ok(cells)
    }

    fn anchored_ops_for_cell(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
    ) -> StoreResult<Vec<AnchoredOp>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .cell_log
            .get(&(space_id.as_str().to_owned(), cell.as_str().to_owned()))
            .cloned()
            .unwrap_or_default())
    }

    fn cached_state(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<CellState>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .cache
            .get(&(
                space_id.as_str().to_owned(),
                cell.as_str().to_owned(),
                view_hash.as_str().to_owned(),
            ))
            .cloned())
    }

    fn put_cached_state(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> StoreResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.cache.insert(
            (space_id.as_str().to_owned(), cell.as_str().to_owned(), view_hash.as_str().to_owned()),
            state.clone(),
        );
        Ok(())
    }

    fn append_anchored_effects(
        &self,
        space_id: &SpaceId,
        anchor: &AnchorId,
        new_ops: &[(CellRef, AnchoredOp)],
    ) -> StoreResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let mut applied: Vec<(String, AnchoredOp)> = Vec::with_capacity(new_ops.len());
        for (cell, op) in new_ops {
            let key = (space_id.as_str().to_owned(), cell.as_str().to_owned());
            inner.cell_log.entry(key.clone()).or_default().push(op.clone());
            applied.push((cell.as_str().to_owned(), op.clone()));
        }
        inner.anchor_ops.insert(anchor.as_str().to_owned(), applied);
        // Cache invalidation: clear cache entries for cells touched by this anchor.
        let touched: std::collections::BTreeSet<_> = new_ops
            .iter()
            .map(|(c, _)| (space_id.as_str().to_owned(), c.as_str().to_owned()))
            .collect();
        inner.cache.retain(|(s, c, _), _| !touched.contains(&(s.clone(), c.clone())));
        Ok(())
    }

    fn rollback_anchor(&self, space_id: &SpaceId, anchor: &AnchorId) -> StoreResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let Some(applied) = inner.anchor_ops.remove(anchor.as_str()) else {
            return Ok(()); // no-op if nothing to roll back
        };
        for (cell_str, op) in applied {
            let key = (space_id.as_str().to_owned(), cell_str);
            if let Some(log) = inner.cell_log.get_mut(&key) {
                // Remove the op from the tail; if it's not at the tail (concurrent
                // writes), search and remove the first match.
                if let Some(pos) = log.iter().rposition(|x| x == &op) {
                    log.remove(pos);
                }
                if log.is_empty() {
                    inner.cell_log.remove(&key);
                }
            }
        }
        Ok(())
    }
}

/// In-memory `CellRegistry` with hand-wired cell_family → Lattice mappings.
///
/// Production registry will load mappings from the spec
/// `event-kind-registry.json` `cell_family` / `lattice` / `bottom`
/// fields. This memory version covers the cell families exercised by
/// SDK tests and the move-anchor-lattice fixture.
pub struct MemoryCellRegistry {
    bindings: BTreeMap<String, BindingDescriptor>,
}

#[derive(Clone)]
struct BindingDescriptor {
    kind: LatticeKind,
    bottom_mode: BottomMode,
    fsm_initial: Option<Value>,
    fsm_transitions: Vec<(Value, Value)>,
}

impl Default for MemoryCellRegistry {
    fn default() -> Self {
        let mut bindings = BTreeMap::new();

        // Membership FSM (per spec event-auth-state-resolution.md §5).
        bindings.insert(
            "cx.component.member.state.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::Fsm,
                bottom_mode: BottomMode::Reject,
                fsm_initial: Some(json!("invited")),
                fsm_transitions: vec![
                    (json!("invited"), json!("join")),
                    (json!("join"), json!("leave")),
                    (json!("join"), json!("ban")),
                    (json!("leave"), json!("join")),
                    (json!("invited"), json!("leave")),
                ],
            },
        );

        // Capability grant or-set.
        bindings.insert(
            "cx.component.capability.grant.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrSet,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Consent or-set (cx.component.consent.grant.v1) — spec consent-model §3.1.
        bindings.insert(
            "cx.component.consent.grant.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrSet,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Anchorer cell — cas-register, bottom=reject.
        bindings.insert(
            "cx.component.anchorer.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Generic Space policy — cas-register, bottom=reject (spec §5 example).
        bindings.insert(
            "cx.component.space.policy.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Soft display state — mv-register, bottom=expose.
        bindings.insert(
            "cx.component.space.title.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::MvRegister,
                bottom_mode: BottomMode::Expose,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Counter (audit / quota counters).
        bindings.insert(
            "cx.component.metric.counter.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::Counter,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Audit log / message log — ordered-log.
        bindings.insert(
            "cx.component.audit.log.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrderedLog,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // MLS commit Move target cells (spec §10).
        // mls_epoch: cas-register, bottom=reject (racing commits fail closed).
        bindings.insert(
            "cx.component.mls_epoch.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );
        // key_schedule: cas-register, bottom=reject (one schedule per epoch).
        bindings.insert(
            "cx.component.key_schedule.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );
        // covered_frontier: or-set, bottom=expose (governance frontiers
        // accumulate; lag exposes multi-head to projection but doesn't
        // block governance Moves).
        bindings.insert(
            "cx.component.covered_frontier.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrSet,
                bottom_mode: BottomMode::Expose,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        Self { bindings }
    }
}

impl MemoryCellRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an additional binding (test fixtures / Space-level overrides).
    pub fn register(
        &mut self,
        cell_family: impl Into<String>,
        kind: LatticeKind,
        bottom_mode: BottomMode,
    ) {
        self.bindings.insert(
            cell_family.into(),
            BindingDescriptor { kind, bottom_mode, fsm_initial: None, fsm_transitions: vec![] },
        );
    }

    pub fn register_fsm(
        &mut self,
        cell_family: impl Into<String>,
        initial: Option<Value>,
        transitions: Vec<(Value, Value)>,
        bottom_mode: BottomMode,
    ) {
        self.bindings.insert(
            cell_family.into(),
            BindingDescriptor {
                kind: LatticeKind::Fsm,
                bottom_mode,
                fsm_initial: initial,
                fsm_transitions: transitions,
            },
        );
    }
}

impl CellRegistry for MemoryCellRegistry {
    fn resolve(&self, _space_id: &SpaceId, cell: &CellRef) -> StoreResult<CellLatticeBinding> {
        // Parse "cx:cell:<family>:<subject>" — family is between the 2nd and 3rd colons.
        let cell_id = crate::CellId::parse(cell.as_str())
            .map_err(|e| StoreError::Backend(format!("invalid cell ref: {e}")))?;
        let family = cell_id.component();
        let descriptor = self
            .bindings
            .get(family)
            .ok_or_else(|| StoreError::NotFound(format!("unknown cell family: {family}")))?;
        let lattice: Box<dyn Lattice> = match descriptor.kind {
            LatticeKind::OrSet => Box::new(OrSet),
            LatticeKind::MvRegister => Box::new(MvRegister),
            LatticeKind::CasRegister => Box::new(CasRegister),
            LatticeKind::Fsm => {
                let mut fsm = Fsm::new(descriptor.fsm_transitions.clone());
                if let Some(initial) = descriptor.fsm_initial.clone() {
                    fsm = fsm.with_initial(initial);
                }
                Box::new(fsm)
            }
            LatticeKind::Counter => Box::new(Counter),
            LatticeKind::OrderedLog => Box::new(OrderedLog),
        };
        Ok(CellLatticeBinding { lattice, bottom_mode: descriptor.bottom_mode })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnchorerSig, Hlc, LatticeOp, LatticeOpType, MoveSignature};
    use chrono::{TimeZone, Utc};

    fn space() -> SpaceId {
        SpaceId::new("cx:space:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn anchor_id(byte: u8) -> AnchorId {
        AnchorId::new(format!("cx:anchor:sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn cell_member() -> CellRef {
        CellRef::new("cx:cell:cx.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    fn dummy_move(id: MoveId) -> Move {
        let body = serde_json::json!({
            "issuer": "did:web:admin.example",
            "space_id": space().as_str(),
            "preconditions": [],
            "effects": [{
                "cell": cell_member().as_str(),
                "op": { "kind": "transition", "from": "invited", "to": "join" }
            }],
            "anchor_ref": format!("cx:anchor:sha256:{}", "aa".repeat(32)),
            "refs": [],
            "hlc": "0189c4d2af00-0000-aabbccdd"
        });
        let body_bytes = crate::canonical::canonical_json_bytes(&body).unwrap();
        let payload_digest = crate::canonical::sha256_digest(&body_bytes);
        let mut full = body.as_object().unwrap().clone();
        full.insert("id".into(), Value::String(id.as_str().to_owned()));
        full.insert(
            "sig".into(),
            serde_json::json!({
                "alg": "EdDSA",
                "verification_method": "did:web:admin.example#k1",
                "payload_digest": payload_digest,
                "created_at": "2026-05-08T00:00:00Z",
                "jws": "AAAA.BBBB.CCCC"
            }),
        );
        serde_json::from_value(Value::Object(full)).unwrap()
    }

    fn dummy_anchor(id: AnchorId, predecessors: Vec<AnchorId>, frontier: Vec<MoveId>) -> Anchor {
        let sig = MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:anchorer.example#k1".to_owned(),
            payload_digest: hash(0xff),
            created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        };
        Anchor {
            id,
            space_id: space(),
            predecessor_refs: predecessors,
            frontier,
            state_root: hash(0x77),
            anchorer_sig: AnchorerSig::Single(sig),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: crate::AnchorKind::Normal,
        }
    }

    #[test]
    fn move_store_put_and_anchor_idempotent() {
        let store = MemoryMoveStore::default();
        let m1 = dummy_move(move_id(0x01));
        store.put_pending(&m1).unwrap();
        store.put_pending(&m1).unwrap(); // idempotent
        assert_eq!(store.get(&m1.id).unwrap().unwrap().id, m1.id);

        let anchor = anchor_id(0xaa);
        store.mark_anchored(&m1.id, &anchor).unwrap();
        store.mark_anchored(&m1.id, &anchor).unwrap(); // idempotent
    }

    #[test]
    fn move_store_lists_pending_by_insertion_order() {
        let store = MemoryMoveStore::default();
        let m1 = dummy_move(move_id(0x01));
        let m2 = dummy_move(move_id(0x02));
        store.put_pending(&m1).unwrap();
        store.put_pending(&m2).unwrap();

        let pending = store.list_pending_for_anchorer(&space(), None, 10).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, m1.id);
        assert_eq!(pending[1].id, m2.id);

        store.mark_anchored(&m1.id, &anchor_id(0xaa)).unwrap();
        let pending = store.list_pending_for_anchorer(&space(), None, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, m2.id);
    }

    #[test]
    fn anchor_store_tracks_genesis_and_leaves() {
        let store = MemoryAnchorStore::default();
        let g = dummy_anchor(anchor_id(0xa0), vec![], vec![move_id(0x01)]);
        store.put(&g).unwrap();
        assert_eq!(store.genesis(&space()).unwrap().unwrap(), g.id);
        assert_eq!(store.list_leaves(&space()).unwrap(), vec![g.id.clone()]);

        let child = dummy_anchor(anchor_id(0xa1), vec![g.id], vec![move_id(0x02)]);
        store.put(&child).unwrap();
        assert_eq!(store.list_leaves(&space()).unwrap(), vec![child.id]);
    }

    #[test]
    fn anchor_store_successors_lists_direct_children() {
        // genesis ─► child_a ─► leaf_x
        //          ▲
        // genesis ─┴► child_b
        let store = MemoryAnchorStore::default();
        let g = dummy_anchor(anchor_id(0xa0), vec![], vec![move_id(0x01)]);
        let child_a = dummy_anchor(anchor_id(0xa1), vec![g.id.clone()], vec![move_id(0x02)]);
        let child_b = dummy_anchor(anchor_id(0xa2), vec![g.id.clone()], vec![move_id(0x03)]);
        let leaf_x = dummy_anchor(anchor_id(0xa3), vec![child_a.id.clone()], vec![move_id(0x04)]);
        store.put(&g).unwrap();
        store.put(&child_a).unwrap();
        store.put(&child_b).unwrap();
        store.put(&leaf_x).unwrap();

        // genesis has two direct children.
        let succ = store.successors(&space(), &g.id).unwrap();
        assert_eq!(succ.len(), 2);
        assert!(succ.contains(&child_a.id));
        assert!(succ.contains(&child_b.id));

        // child_b is a leaf — no successors.
        assert!(store.successors(&space(), &child_b.id).unwrap().is_empty());
    }

    #[test]
    fn anchor_store_prune_predecessor_rewires_through() {
        // g ─► a ─► b (leaf). Pruning `a` rewires b's predecessor to g.
        let store = MemoryAnchorStore::default();
        let g = dummy_anchor(anchor_id(0xb0), vec![], vec![move_id(0x01)]);
        let a = dummy_anchor(anchor_id(0xb1), vec![g.id.clone()], vec![move_id(0x02)]);
        let b = dummy_anchor(anchor_id(0xb2), vec![a.id.clone()], vec![move_id(0x03)]);
        store.put(&g).unwrap();
        store.put(&a).unwrap();
        store.put(&b).unwrap();

        let rewired = store.prune_predecessor(&space(), &a.id).unwrap();
        assert_eq!(rewired, vec![b.id.clone()]);

        // `a` is gone.
        assert!(store.get(&a.id).unwrap().is_none());
        // `b` now points to `g`.
        let b_after = store.get(&b.id).unwrap().unwrap();
        assert_eq!(b_after.predecessor_refs, vec![g.id]);
    }

    #[test]
    fn anchor_store_prune_predecessor_rejects_leaf() {
        let store = MemoryAnchorStore::default();
        let g = dummy_anchor(anchor_id(0xc0), vec![], vec![move_id(0x01)]);
        store.put(&g).unwrap();
        // g is a leaf — can't prune.
        let err = store.prune_predecessor(&space(), &g.id).unwrap_err();
        assert!(format!("{err}").contains("no successors"));
    }

    #[test]
    fn anchor_store_prune_predecessor_dedups_when_grandparent_already_referenced() {
        // diamond: g ─► a ─► c; g ─► c. Pruning `a` shouldn't double-add g.
        let store = MemoryAnchorStore::default();
        let g = dummy_anchor(anchor_id(0xd0), vec![], vec![move_id(0x01)]);
        let a = dummy_anchor(anchor_id(0xd1), vec![g.id.clone()], vec![move_id(0x02)]);
        let c =
            dummy_anchor(anchor_id(0xd2), vec![g.id.clone(), a.id.clone()], vec![move_id(0x03)]);
        store.put(&g).unwrap();
        store.put(&a).unwrap();
        store.put(&c).unwrap();

        store.prune_predecessor(&space(), &a.id).unwrap();
        let c_after = store.get(&c.id).unwrap().unwrap();
        // c.predecessor_refs has just one entry: g.
        assert_eq!(c_after.predecessor_refs, vec![g.id]);
    }

    #[test]
    fn anchor_store_predecessor_check() {
        let store = MemoryAnchorStore::default();
        let a = dummy_anchor(anchor_id(0xa0), vec![], vec![]);
        store.put(&a).unwrap();
        assert!(store.predecessors_known(&[a.id]).unwrap());
        assert!(!store.predecessors_known(&[anchor_id(0xee)]).unwrap());
        assert!(store.predecessors_known(&[]).unwrap()); // empty = trivially known
    }

    #[test]
    fn cell_store_append_and_list() {
        let store = MemoryCellStore::default();
        let op = AnchoredOp::new(
            move_id(0x01),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        );
        store
            .append_anchored_effects(&space(), &anchor_id(0xaa), &[(cell_member(), op.clone())])
            .unwrap();

        let cells = store.list_cells(&space()).unwrap();
        assert_eq!(cells.len(), 1);
        let ops = store.anchored_ops_for_cell(&space(), &cell_member()).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], op);
    }

    #[test]
    fn cell_store_rollback_undoes_append() {
        let store = MemoryCellStore::default();
        let op = AnchoredOp::new(
            move_id(0x01),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        );
        let anchor = anchor_id(0xaa);
        store.append_anchored_effects(&space(), &anchor, &[(cell_member(), op)]).unwrap();
        store.rollback_anchor(&space(), &anchor).unwrap();
        assert!(store.anchored_ops_for_cell(&space(), &cell_member()).unwrap().is_empty());
        assert!(store.list_cells(&space()).unwrap().is_empty());
    }

    #[test]
    fn cell_store_cache_round_trip_and_invalidation() {
        let store = MemoryCellStore::default();
        let view = hash(0x33);
        store
            .put_cached_state(&space(), &cell_member(), &view, &CellState::Value(json!("x")))
            .unwrap();
        assert_eq!(
            store.cached_state(&space(), &cell_member(), &view).unwrap(),
            Some(CellState::Value(json!("x")))
        );
        // append should invalidate cache.
        let op = AnchoredOp::new(
            move_id(0x05),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        );
        store.append_anchored_effects(&space(), &anchor_id(0xab), &[(cell_member(), op)]).unwrap();
        assert!(store.cached_state(&space(), &cell_member(), &view).unwrap().is_none());
    }

    #[test]
    fn cell_registry_resolves_known_families() {
        let reg = MemoryCellRegistry::new();
        let binding = reg.resolve(&space(), &cell_member()).unwrap();
        assert_eq!(binding.lattice.kind(), LatticeKind::Fsm);
        assert_eq!(binding.bottom_mode, BottomMode::Reject);
    }

    #[test]
    fn cell_registry_unknown_family_fails_closed() {
        let reg = MemoryCellRegistry::new();
        let weird = CellRef::new("cx:cell:cx.component.future.unknown.v1:x".to_owned()).unwrap();
        let err = reg.resolve(&space(), &weird).unwrap_err();
        assert!(format!("{err}").contains("unknown cell family"));
    }

    #[test]
    fn cell_registry_or_set_and_cas_lattices_resolve() {
        let reg = MemoryCellRegistry::new();
        let consent =
            CellRef::new("cx:cell:cx.component.consent.grant.v1:cx.consent.x".to_owned()).unwrap();
        assert_eq!(reg.resolve(&space(), &consent).unwrap().lattice.kind(), LatticeKind::OrSet);

        let policy =
            CellRef::new("cx:cell:cx.component.space.policy.v1:cx.space.x".to_owned()).unwrap();
        assert_eq!(
            reg.resolve(&space(), &policy).unwrap().lattice.kind(),
            LatticeKind::CasRegister
        );
    }
}
