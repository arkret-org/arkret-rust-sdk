//! In-memory implementations of the four store traits.
//!
//! These are the test backbone: they let SDK unit tests exercise
//! `verify_move` / `apply_seal` / `state_root` end-to-end without a
//! database. Production servers (soland) implement durable backends
//! against the same trait surface.

// Lock policy: recover from poisoning instead of panicking. These stores
// hold plain data (no torn multi-step invariants across a panic point), so
// `PoisonError::into_inner` is safe and keeps one panicked writer from
// cascading panics into every later caller.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use serde_json::{Value, json};

use super::{
    BottomMode, CellLatticeBinding, CellRegistry, CellStore, MoveStore, SealStore,
    SealedMoveRecord, StoreError, StoreResult,
};
use crate::lattice::{
    CasRegister, CellState, Counter, Fsm, Lattice, LatticeKind, MvRegister, OrSet, OrderedLog,
    ordered_log::IssuedOp,
};
use crate::{CellRef, Hash, Move, MoveId, RealmId, Seal, SealId};

/// In-memory `MoveStore`.
#[derive(Default)]
pub struct MemoryMoveStore {
    inner: Mutex<MemoryMoveStoreInner>,
}

#[derive(Default)]
struct MemoryMoveStoreInner {
    /// All known Moves keyed by id.
    moves: BTreeMap<String, Move>,
    /// Seal membership: move_id → seal id (None means pending).
    sealed: BTreeMap<String, SealId>,
    /// Insertion order so list_pending is deterministic.
    insertion_order: Vec<String>,
}

impl MoveStore for MemoryMoveStore {
    fn put_pending(&self, m: &Move) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = m.id.as_str().to_owned();
        if !inner.moves.contains_key(&id) {
            inner.insertion_order.push(id.clone());
        }
        inner.moves.entry(id).or_insert_with(|| m.clone());
        Ok(())
    }

    fn mark_sealed(&self, id: &MoveId, seal: &SealId) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.moves.contains_key(id.as_str()) {
            return Err(StoreError::NotFound(format!("Move {id} not in store")));
        }
        inner.sealed.insert(id.as_str().to_owned(), seal.clone());
        Ok(())
    }

    fn get(&self, id: &MoveId) -> StoreResult<Option<Move>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .moves
            .get(id.as_str())
            .cloned())
    }

    fn list_pending_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<Move>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                && m.realm_id == *realm_id
                && !inner.sealed.contains_key(id)
            {
                out.push(m.clone());
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn list_sealed(
        &self,
        realm_id: &RealmId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<SealedMoveRecord>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            if let (Some(m), Some(a)) = (inner.moves.get(id), inner.sealed.get(id))
                && m.realm_id == *realm_id
            {
                out.push(SealedMoveRecord {
                    move_value: m.clone(),
                    seal: a.clone(),
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }
}

/// In-memory `SealStore`.
#[derive(Default)]
pub struct MemorySealStore {
    inner: Mutex<MemorySealStoreInner>,
}

#[derive(Default)]
struct MemorySealStoreInner {
    seals: BTreeMap<String, Seal>,
    /// realm_id → leaves (seals with no successor)
    leaves: BTreeMap<String, Vec<SealId>>,
    /// realm_id → genesis seal (first put with empty predecessors)
    genesis: BTreeMap<String, SealId>,
}

impl MemorySealStoreInner {
    fn put(&mut self, seal: &Seal) {
        let realm = seal.realm_id.as_str().to_owned();
        let id_str = seal.id.as_str().to_owned();
        self.seals.insert(id_str, seal.clone());

        if seal.predecessor_refs.is_empty() {
            self.genesis
                .entry(realm.clone())
                .or_insert_with(|| seal.id.clone());
        }

        let leaves = self.leaves.entry(realm).or_default();
        leaves.retain(|leaf| !seal.predecessor_refs.iter().any(|p| p == leaf));
        if !leaves.iter().any(|leaf| leaf == &seal.id) {
            leaves.push(seal.id.clone());
        }
    }

    fn frontier_matches(&self, realm_id: &RealmId, expected_leaves: &[SealId]) -> bool {
        let current: BTreeSet<&str> = self
            .leaves
            .get(realm_id.as_str())
            .into_iter()
            .flatten()
            .map(SealId::as_str)
            .collect();
        let expected: BTreeSet<&str> = expected_leaves.iter().map(SealId::as_str).collect();
        current == expected
    }
}

impl SealStore for MemorySealStore {
    fn put(&self, seal: &Seal) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.put(seal);
        Ok(())
    }

    fn put_if_frontier(&self, seal: &Seal, expected_leaves: &[SealId]) -> StoreResult<bool> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.frontier_matches(&seal.realm_id, expected_leaves) {
            return Ok(false);
        }
        inner.put(seal);
        Ok(true)
    }

    fn get(&self, id: &SealId) -> StoreResult<Option<Seal>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seals
            .get(id.as_str())
            .cloned())
    }

    fn list_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .leaves
            .get(realm_id.as_str())
            .cloned()
            .unwrap_or_default())
    }

    fn predecessors_known(&self, refs: &[SealId]) -> StoreResult<bool> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(refs.iter().all(|r| inner.seals.contains_key(r.as_str())))
    }

    fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .genesis
            .get(realm_id.as_str())
            .cloned())
    }

    fn successors(&self, realm_id: &RealmId, seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::new();
        for seal in inner.seals.values() {
            if seal.realm_id.as_str() != realm_id.as_str() {
                continue;
            }
            if seal.predecessor_refs.iter().any(|p| p == seal_id) {
                out.push(seal.id.clone());
            }
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }

    fn prune_predecessor(&self, realm_id: &RealmId, seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Snapshot the parents of the pruned seal before removing it.
        let parents: Vec<SealId> = inner
            .seals
            .get(seal_id.as_str())
            .map(|a| a.predecessor_refs.clone())
            .ok_or_else(|| StoreError::NotFound(format!("seal {seal_id} not in store")))?;

        // Successor seals whose predecessor_refs reference the pruned id.
        let successor_ids: Vec<String> = inner
            .seals
            .values()
            .filter(|a| {
                a.realm_id.as_str() == realm_id.as_str()
                    && a.predecessor_refs.iter().any(|p| p == seal_id)
            })
            .map(|a| a.id.as_str().to_owned())
            .collect();

        if successor_ids.is_empty() {
            return Err(StoreError::Conflict(format!(
                "seal {seal_id} has no successors; can't prune a leaf via prune_predecessor"
            )));
        }

        // Rewire each successor: remove the pruned id, splice in the parents.
        // Dedup so a successor that previously referenced both pruned and
        // a grandparent doesn't end up with the same predecessor twice.
        for sid in &successor_ids {
            if let Some(succ) = inner.seals.get_mut(sid) {
                let mut new_refs: Vec<SealId> = succ
                    .predecessor_refs
                    .iter()
                    .filter(|p| *p != seal_id)
                    .cloned()
                    .collect();
                for parent in &parents {
                    if !new_refs.iter().any(|p| p == parent) {
                        new_refs.push(parent.clone());
                    }
                }
                new_refs.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                succ.predecessor_refs = new_refs;
            }
        }

        // Remove the pruned seal itself.
        inner.seals.remove(seal_id.as_str());

        // Pruned seal can't have been a leaf (we checked above) and its
        // parents already had their successor-rewiring done before this
        // seal existed, so the leaf set is unaffected. Nothing to do
        // with `leaves`.

        // Genesis: if we pruned the genesis (which only makes sense if a
        // child compaction replaces it), forget the genesis pointer — the
        // caller MUST set a new one explicitly when relevant.
        let realm = realm_id.as_str();
        if inner
            .genesis
            .get(realm)
            .is_some_and(|g| g.as_str() == seal_id.as_str())
        {
            inner.genesis.remove(realm);
        }

        let rewired: Vec<SealId> = successor_ids
            .into_iter()
            .filter_map(|s| SealId::new(s).ok())
            .collect();
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
    /// (realm, cell) -> ordered SealedOp list
    cell_log: BTreeMap<(String, String), Vec<IssuedOp>>,
    /// (realm, cell, view_hash) -> CellState
    cache: BTreeMap<(String, String, String), CellState>,
    /// seal → ops it appended (used for rollback)
    seal_ops: BTreeMap<String, Vec<(String, IssuedOp)>>, // (realm, cell), op
}

impl CellStore for MemoryCellStore {
    fn list_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cells = Vec::new();
        for (realm, cell) in inner.cell_log.keys() {
            if realm == realm_id.as_str() {
                cells.push(
                    CellRef::new(cell.clone()).map_err(|e| StoreError::Backend(e.to_string()))?,
                );
            }
        }
        Ok(cells)
    }

    fn sealed_ops_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<IssuedOp>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(inner
            .cell_log
            .get(&(realm_id.as_str().to_owned(), cell.as_str().to_owned()))
            .cloned()
            .unwrap_or_default())
    }

    fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<CellState>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(inner
            .cache
            .get(&(
                realm_id.as_str().to_owned(),
                cell.as_str().to_owned(),
                view_hash.as_str().to_owned(),
            ))
            .cloned())
    }

    fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.cache.insert(
            (
                realm_id.as_str().to_owned(),
                cell.as_str().to_owned(),
                view_hash.as_str().to_owned(),
            ),
            state.clone(),
        );
        Ok(())
    }

    fn append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut applied: Vec<(String, IssuedOp)> = Vec::with_capacity(new_ops.len());
        for (cell, op) in new_ops {
            let key = (realm_id.as_str().to_owned(), cell.as_str().to_owned());
            inner
                .cell_log
                .entry(key.clone())
                .or_default()
                .push(op.clone());
            applied.push((cell.as_str().to_owned(), op.clone()));
        }
        inner.seal_ops.insert(seal.as_str().to_owned(), applied);
        // Cache invalidation: clear cache entries for cells touched by this seal.
        let touched: BTreeSet<_> = new_ops
            .iter()
            .map(|(c, _)| (realm_id.as_str().to_owned(), c.as_str().to_owned()))
            .collect();
        inner
            .cache
            .retain(|(s, c, _), _| !touched.contains(&(s.clone(), c.clone())));
        Ok(())
    }

    fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(applied) = inner.seal_ops.remove(seal.as_str()) else {
            return Ok(()); // no-op if nothing to roll back
        };
        for (cell_str, op) in applied {
            let key = (realm_id.as_str().to_owned(), cell_str);
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
/// SDK tests and the move-seal-lattice fixture.
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
            "ak.component.member.state.v1".to_owned(),
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
            "ak.component.capability.grant.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrSet,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Consent or-set (ak.component.consent.grant.v1) — spec consent-model §3.1.
        bindings.insert(
            "ak.component.consent.grant.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrSet,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Notary cell — cas-register, bottom=reject.
        bindings.insert(
            "ak.component.notary.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Generic Realm policy — cas-register, bottom=reject (spec §5 example).
        bindings.insert(
            "ak.component.realm.policy.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Soft display state — mv-register, bottom=expose.
        bindings.insert(
            "ak.component.Realm.title.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::MvRegister,
                bottom_mode: BottomMode::Expose,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Counter (audit / quota counters).
        bindings.insert(
            "ak.component.metric.counter.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::Counter,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Audit log / message log — ordered-log.
        bindings.insert(
            "ak.component.audit.log.v1".to_owned(),
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
            "ak.component.mls_epoch.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );
        // key_schedule: cas-register, bottom=reject (one schedule per epoch).
        bindings.insert(
            "ak.component.key_schedule.v1".to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );
        // covered_seals: or-set, bottom=expose (governance seal heads
        // accumulate; lag exposes multi-head to projection but doesn't
        // block governance Moves).
        bindings.insert(
            "ak.component.covered_seals.v1".to_owned(),
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

    /// Register an additional binding (test fixtures / Realm-level overrides).
    pub fn register(
        &mut self,
        cell_family: impl Into<String>,
        kind: LatticeKind,
        bottom_mode: BottomMode,
    ) {
        self.bindings.insert(
            cell_family.into(),
            BindingDescriptor {
                kind,
                bottom_mode,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
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
    fn resolve(&self, _realm_id: &RealmId, cell: &CellRef) -> StoreResult<CellLatticeBinding> {
        // Parse "ak:cell:<family>:<subject>" — family is between the 2nd and 3rd colons.
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
        Ok(CellLatticeBinding {
            lattice,
            bottom_mode: descriptor.bottom_mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::lattice::SealedOp;

    fn issued(op: SealedOp) -> IssuedOp {
        IssuedOp {
            issuer: crate::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
            op,
        }
    }

    use std::sync::{Arc, Barrier};

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{Hlc, LatticeOp, LatticeOpType, MoveSignature, NotarySig};

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn seal_id(byte: u8) -> SealId {
        SealId::new(format!(
            "ak:seal:sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn cell_member() -> CellRef {
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    fn dummy_move(id: MoveId) -> Move {
        let body = serde_json::json!({
            "issuer": "did:webvh:z6mkfixture:admin.example",
            "realm_id": realm().as_str(),
            "preconditions": [],
            "effects": [{
                "cell": cell_member().as_str(),
                "op": { "kind": "transition", "from": "invited", "to": "join" }
            }],
            "seal_basis": {
                "leaves": [format!("ak:seal:sha256:{}", "aa".repeat(32))],
                "control_event_set_root": format!("sha256:{}", "22".repeat(32)),
                "state_root": format!("sha256:{}", "33".repeat(32))
            },
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
                "verification_method": "did:webvh:z6mkfixture:admin.example#k1",
                "payload_digest": payload_digest,
                "created_at": "2026-05-08T00:00:00.000Z",
                "jws": "AAAA.BBBB.CCCC"
            }),
        );
        serde_json::from_value(Value::Object(full)).unwrap()
    }

    fn dummy_seal(id: SealId, predecessors: Vec<SealId>, delta: Vec<MoveId>) -> Seal {
        let sig = MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:notary.example#k1".to_owned(),
            payload_digest: hash(0xff),
            created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        };
        Seal {
            id,
            realm_id: realm(),
            predecessor_refs: predecessors,
            delta,
            control_event_set_root: hash(0x22),
            state_root: hash(0x77),
            completeness_root: hash(0x33),
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(sig),
            sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: crate::SealKind::Normal,
        }
    }

    #[test]
    fn move_store_put_and_seal_idempotent() {
        let store = MemoryMoveStore::default();
        let m1 = dummy_move(move_id(0x01));
        store.put_pending(&m1).unwrap();
        store.put_pending(&m1).unwrap(); // idempotent
        assert_eq!(store.get(&m1.id).unwrap().unwrap().id, m1.id);

        let seal = seal_id(0xaa);
        store.mark_sealed(&m1.id, &seal).unwrap();
        store.mark_sealed(&m1.id, &seal).unwrap(); // idempotent
    }

    #[test]
    fn move_store_lists_pending_by_insertion_order() {
        let store = MemoryMoveStore::default();
        let m1 = dummy_move(move_id(0x01));
        let m2 = dummy_move(move_id(0x02));
        store.put_pending(&m1).unwrap();
        store.put_pending(&m2).unwrap();

        let pending = store.list_pending_for_notary(&realm(), None, 10).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, m1.id);
        assert_eq!(pending[1].id, m2.id);

        store.mark_sealed(&m1.id, &seal_id(0xaa)).unwrap();
        let pending = store.list_pending_for_notary(&realm(), None, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, m2.id);
    }

    #[test]
    fn seal_store_tracks_genesis_and_leaves() {
        let store = MemorySealStore::default();
        let g = dummy_seal(seal_id(0xa0), vec![], vec![move_id(0x01)]);
        store.put(&g).unwrap();
        assert_eq!(store.genesis(&realm()).unwrap().unwrap(), g.id);
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![g.id.clone()]);

        let child = dummy_seal(seal_id(0xa1), vec![g.id], vec![move_id(0x02)]);
        store.put(&child).unwrap();
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![child.id]);
    }

    #[test]
    fn seal_store_put_if_frontier_accepts_exact_set() {
        let store = MemorySealStore::default();
        let genesis = dummy_seal(seal_id(0xe0), vec![], vec![move_id(0x01)]);
        assert!(store.put_if_frontier(&genesis, &[]).unwrap());

        let left = dummy_seal(seal_id(0xe1), vec![genesis.id.clone()], vec![move_id(0x02)]);
        store.put(&left).unwrap();
        let right = dummy_seal(seal_id(0xe2), vec![genesis.id], vec![move_id(0x03)]);
        store.put(&right).unwrap();

        let joined = dummy_seal(
            seal_id(0xe3),
            vec![left.id.clone(), right.id.clone()],
            vec![move_id(0x04)],
        );
        assert!(
            store
                .put_if_frontier(&joined, &[right.id.clone(), left.id, right.id])
                .unwrap()
        );
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![joined.id]);
    }

    #[test]
    fn seal_store_put_if_frontier_rejects_stale_set_without_mutation() {
        let store = MemorySealStore::default();
        let genesis = dummy_seal(seal_id(0xf0), vec![], vec![move_id(0x01)]);
        store.put(&genesis).unwrap();
        let stale = dummy_seal(seal_id(0xf1), vec![genesis.id.clone()], vec![move_id(0x02)]);

        assert!(!store.put_if_frontier(&stale, &[seal_id(0xff)]).unwrap());
        assert!(store.get(&stale.id).unwrap().is_none());
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![genesis.id]);
    }

    #[test]
    fn seal_store_put_if_frontier_allows_only_one_concurrent_writer() {
        let store = Arc::new(MemorySealStore::default());
        let genesis = dummy_seal(seal_id(0x90), vec![], vec![move_id(0x01)]);
        store.put(&genesis).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let writers: Vec<_> = [
            dummy_seal(seal_id(0x91), vec![genesis.id.clone()], vec![move_id(0x02)]),
            dummy_seal(seal_id(0x92), vec![genesis.id.clone()], vec![move_id(0x03)]),
        ]
        .into_iter()
        .map(|candidate| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let expected = genesis.id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let inserted = store.put_if_frontier(&candidate, &[expected]).unwrap();
                (candidate.id, inserted)
            })
        })
        .collect();

        barrier.wait();
        let outcomes: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|(_, inserted)| *inserted).count(), 1);

        let winner = outcomes
            .iter()
            .find_map(|(id, inserted)| inserted.then_some(id.clone()))
            .unwrap();
        let loser = outcomes
            .iter()
            .find_map(|(id, inserted)| (!inserted).then_some(id.clone()))
            .unwrap();
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![winner]);
        assert!(store.get(&loser).unwrap().is_none());
    }

    #[test]
    fn seal_store_successors_lists_direct_children() {
        // genesis ─► child_a ─► leaf_x
        //          ▲
        // genesis ─┴► child_b
        let store = MemorySealStore::default();
        let g = dummy_seal(seal_id(0xa0), vec![], vec![move_id(0x01)]);
        let child_a = dummy_seal(seal_id(0xa1), vec![g.id.clone()], vec![move_id(0x02)]);
        let child_b = dummy_seal(seal_id(0xa2), vec![g.id.clone()], vec![move_id(0x03)]);
        let leaf_x = dummy_seal(seal_id(0xa3), vec![child_a.id.clone()], vec![move_id(0x04)]);
        store.put(&g).unwrap();
        store.put(&child_a).unwrap();
        store.put(&child_b).unwrap();
        store.put(&leaf_x).unwrap();

        // genesis has two direct children.
        let succ = store.successors(&realm(), &g.id).unwrap();
        assert_eq!(succ.len(), 2);
        assert!(succ.contains(&child_a.id));
        assert!(succ.contains(&child_b.id));

        // child_b is a leaf — no successors.
        assert!(store.successors(&realm(), &child_b.id).unwrap().is_empty());
    }

    #[test]
    fn seal_store_prune_predecessor_rewires_through() {
        // g ─► a ─► b (leaf). Pruning `a` rewires b's predecessor to g.
        let store = MemorySealStore::default();
        let g = dummy_seal(seal_id(0xb0), vec![], vec![move_id(0x01)]);
        let a = dummy_seal(seal_id(0xb1), vec![g.id.clone()], vec![move_id(0x02)]);
        let b = dummy_seal(seal_id(0xb2), vec![a.id.clone()], vec![move_id(0x03)]);
        store.put(&g).unwrap();
        store.put(&a).unwrap();
        store.put(&b).unwrap();

        let rewired = store.prune_predecessor(&realm(), &a.id).unwrap();
        assert_eq!(rewired, vec![b.id.clone()]);

        // `a` is gone.
        assert!(store.get(&a.id).unwrap().is_none());
        // `b` now points to `g`.
        let b_after = store.get(&b.id).unwrap().unwrap();
        assert_eq!(b_after.predecessor_refs, vec![g.id]);
    }

    #[test]
    fn seal_store_prune_predecessor_rejects_leaf() {
        let store = MemorySealStore::default();
        let g = dummy_seal(seal_id(0xc0), vec![], vec![move_id(0x01)]);
        store.put(&g).unwrap();
        // g is a leaf — can't prune.
        let err = store.prune_predecessor(&realm(), &g.id).unwrap_err();
        assert!(format!("{err}").contains("no successors"));
    }

    #[test]
    fn seal_store_prune_predecessor_dedups_when_grandparent_already_referenced() {
        // diamond: g ─► a ─► c; g ─► c. Pruning `a` shouldn't double-add g.
        let store = MemorySealStore::default();
        let g = dummy_seal(seal_id(0xd0), vec![], vec![move_id(0x01)]);
        let a = dummy_seal(seal_id(0xd1), vec![g.id.clone()], vec![move_id(0x02)]);
        let c = dummy_seal(
            seal_id(0xd2),
            vec![g.id.clone(), a.id.clone()],
            vec![move_id(0x03)],
        );
        store.put(&g).unwrap();
        store.put(&a).unwrap();
        store.put(&c).unwrap();

        store.prune_predecessor(&realm(), &a.id).unwrap();
        let c_after = store.get(&c.id).unwrap().unwrap();
        // c.predecessor_refs has just one entry: g.
        assert_eq!(c_after.predecessor_refs, vec![g.id]);
    }

    #[test]
    fn seal_store_predecessor_check() {
        let store = MemorySealStore::default();
        let a = dummy_seal(seal_id(0xa0), vec![], vec![]);
        store.put(&a).unwrap();
        assert!(store.predecessors_known(&[a.id]).unwrap());
        assert!(!store.predecessors_known(&[seal_id(0xee)]).unwrap());
        assert!(store.predecessors_known(&[]).unwrap()); // empty = trivially known
    }

    #[test]
    fn cell_store_append_and_list() {
        let store = MemoryCellStore::default();
        let op = SealedOp::new(
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
            .append_sealed_effects(&realm(), &seal_id(0xaa), &[(cell_member(), issued(op.clone()))])
            .unwrap();

        let cells = store.list_cells(&realm()).unwrap();
        assert_eq!(cells.len(), 1);
        let ops = store.sealed_ops_for_cell(&realm(), &cell_member()).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, op);
    }

    #[test]
    fn cell_store_rollback_undoes_append() {
        let store = MemoryCellStore::default();
        let op = SealedOp::new(
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
        let seal = seal_id(0xaa);
        store
            .append_sealed_effects(&realm(), &seal, &[(cell_member(), issued(op))])
            .unwrap();
        store.rollback_seal(&realm(), &seal).unwrap();
        assert!(
            store
                .sealed_ops_for_cell(&realm(), &cell_member())
                .unwrap()
                .is_empty()
        );
        assert!(store.list_cells(&realm()).unwrap().is_empty());
    }

    #[test]
    fn cell_store_cache_round_trip_and_invalidation() {
        let store = MemoryCellStore::default();
        let view = hash(0x33);
        store
            .put_cached_state(
                &realm(),
                &cell_member(),
                &view,
                &CellState::Value(json!("x")),
            )
            .unwrap();
        assert_eq!(
            store.cached_state(&realm(), &cell_member(), &view).unwrap(),
            Some(CellState::Value(json!("x")))
        );
        // append should invalidate cache.
        let op = SealedOp::new(
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
        store
            .append_sealed_effects(&realm(), &seal_id(0xab), &[(cell_member(), issued(op))])
            .unwrap();
        assert!(
            store
                .cached_state(&realm(), &cell_member(), &view)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cell_registry_resolves_known_families() {
        let reg = MemoryCellRegistry::new();
        let binding = reg.resolve(&realm(), &cell_member()).unwrap();
        assert_eq!(binding.lattice.kind(), LatticeKind::Fsm);
        assert_eq!(binding.bottom_mode, BottomMode::Reject);
    }

    #[test]
    fn cell_registry_unknown_family_fails_closed() {
        let reg = MemoryCellRegistry::new();
        let weird = CellRef::new("ak:cell:ak.component.future.unknown.v1:x".to_owned()).unwrap();
        let err = reg.resolve(&realm(), &weird).unwrap_err();
        assert!(format!("{err}").contains("unknown cell family"));
    }

    #[test]
    fn cell_registry_or_set_and_cas_lattices_resolve() {
        let reg = MemoryCellRegistry::new();
        let consent =
            CellRef::new("ak:cell:ak.component.consent.grant.v1:ak.consent.x".to_owned()).unwrap();
        assert_eq!(
            reg.resolve(&realm(), &consent).unwrap().lattice.kind(),
            LatticeKind::OrSet
        );

        let policy =
            CellRef::new("ak:cell:ak.component.realm.policy.v1:ak.realm.x".to_owned()).unwrap();
        assert_eq!(
            reg.resolve(&realm(), &policy).unwrap().lattice.kind(),
            LatticeKind::CasRegister
        );
    }
}
