//! Store trait contracts for the Move/Seal/Lattice runtime.
//!
//! Four traits cleanly partitioned by what they own:
//!
//! - [`MoveStore`] — pending + sealed Move log, addressed by `MoveId`.
//! - [`SealStore`] — Seal DAG, addressed by `SealId`, plus leaf-set queries.
//! - [`CellStore`] — per-cell sealed op log + per-view effective state cache.
//! - [`CellRegistry`] — `cell_family` → `Lattice` instance + `bottom` mode mapping.
//!
//! All four ship with [`memory`] backends used by tests / SDK harness.
//! Production servers (soland, third-party) implement durable backends
//! against the same trait surface.

pub mod memory;

use thiserror::Error;

use crate::lattice::{CellState, Lattice, SealedOp};
use crate::{CellRef, Hash, Move, MoveId, RealmId, Seal, SealId};

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),
}

/// Sealed Move record: a Move that has been included in some
/// Seal.frontier. Carries the Seal id back-reference for audit and
/// deterministic ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMoveRecord {
    pub move_value: Move,
    pub seal: SealId,
}

/// Pending + sealed Move log.
pub trait MoveStore: Send + Sync {
    /// Stash a Move that passed local format / signature pre-check.
    /// Re-`put_pending` of the same id MUST be idempotent.
    fn put_pending(&self, m: &Move) -> StoreResult<()>;

    /// Promote a previously-pending Move to sealed under `seal`.
    /// Re-anchoring the same Move under the same Seal id is idempotent.
    fn mark_sealed(&self, id: &MoveId, seal: &SealId) -> StoreResult<()>;

    fn get(&self, id: &MoveId) -> StoreResult<Option<Move>>;

    /// Pending Move list for the notary worker, oldest first.
    fn list_pending_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<Move>>;

    /// Sealed Move list for federation backfill / audit replay.
    fn list_sealed(
        &self,
        realm_id: &RealmId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<SealedMoveRecord>>;
}

/// Seal DAG.
pub trait SealStore: Send + Sync {
    fn put(&self, a: &Seal) -> StoreResult<()>;

    /// Atomically insert `seal` only when the Realm's current leaf set is
    /// exactly `expected_leaves`.
    ///
    /// Equality is set equality: ordering and duplicate entries do not affect
    /// the comparison. The frontier read, comparison, and insert MUST execute
    /// in one transaction or lock domain. Implementations MUST NOT compose
    /// this operation from [`SealStore::list_leaves`] followed by
    /// [`SealStore::put`], because that admits two writers from the same stale
    /// frontier.
    ///
    /// Returns `true` when the Seal was inserted and `false` when the expected
    /// frontier was stale. A `false` result MUST leave the store unchanged.
    fn put_if_frontier(&self, seal: &Seal, expected_leaves: &[SealId]) -> StoreResult<bool>;

    fn get(&self, id: &SealId) -> StoreResult<Option<Seal>>;

    /// Current leaf set for a Realm (Seals with no successor).
    fn list_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>>;

    /// Whether all `refs` have been seen by this store.
    fn predecessors_known(&self, refs: &[SealId]) -> StoreResult<bool>;

    /// The Realm's genesis Seal, if any. Each Realm has at most one.
    fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>>;

    /// Direct successors of `seal_id` — every Seal `S` for which
    /// `S.predecessor_refs.contains(seal_id)`. Used by the MAL-11
    /// compaction pipeline to find what to rewire when pruning a
    /// historical Seal. Default implementation returns
    /// `StoreError::Backend("unsupported")` so existing backends that
    /// haven't migrated still compile; production backends MUST override
    /// once they need compaction.
    fn successors(&self, _realm_id: &RealmId, _seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        Err(StoreError::Backend(
            "SealStore::successors not implemented for this backend".to_owned(),
        ))
    }

    /// MAL-11: drop `seal_id` from the DAG and rewire its direct
    /// successors so their `predecessor_refs` point through to
    /// `seal_id`'s parents instead. The caller MUST have validated that
    /// pruning is safe (downstream witnessed by a compaction Seal,
    /// `CompactionPolicy` accepts the candidate, etc.) — the trait only
    /// performs the structural rewrite.
    ///
    /// Returns the list of successor Seal ids that were rewired so the
    /// caller can re-derive their `id` if the receiver wants
    /// content-addressed correctness (in practice MAL-11 keeps the
    /// successor ids stable because rewriting `predecessor_refs` would
    /// invalidate the signature — see `event-auth-state-resolution.md`
    /// §6.4 prune semantics: pruning is metadata-only, ids stay).
    ///
    /// Default impl returns `Err(unsupported)` so backends that haven't
    /// migrated still compile.
    fn prune_predecessor(
        &self,
        _realm_id: &RealmId,
        _seal_id: &SealId,
    ) -> StoreResult<Vec<SealId>> {
        Err(StoreError::Backend(
            "SealStore::prune_predecessor not implemented for this backend".to_owned(),
        ))
    }
}

/// Per-cell sealed op log + per-view effective-state cache.
pub trait CellStore: Send + Sync {
    /// All cells with at least one effect in this Realm. Used for
    /// `state_root` enumeration.
    fn list_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>>;

    /// All sealed ops applying to this cell, in deterministic order.
    fn sealed_ops_for_cell(&self, realm_id: &RealmId, cell: &CellRef)
    -> StoreResult<Vec<SealedOp>>;

    /// Cached effective state. `None` means the runtime must recompute.
    fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<CellState>>;

    fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> StoreResult<()>;

    /// `apply_seal` write-back: extend the per-cell op log atomically
    /// with one Seal's worth of effects.
    fn append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
        new_ops: &[(CellRef, SealedOp)],
    ) -> StoreResult<()>;

    /// Roll back a previously-`append_sealed_effects` call when the
    /// computed state_root failed to match `Seal.state_root`.
    fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> StoreResult<()>;
}

/// Resolved Lattice binding for a cell: the Lattice impl + the cell's
/// declared `bottom` mode (reject vs expose).
pub struct CellLatticeBinding {
    pub lattice: Box<dyn Lattice>,
    pub bottom_mode: BottomMode,
}

impl std::fmt::Debug for CellLatticeBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellLatticeBinding")
            .field("lattice_kind", &self.lattice.kind())
            .field("bottom_mode", &self.bottom_mode)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BottomMode {
    Reject,
    Expose,
}

/// `cell_family` → `Lattice` instance mapping.
pub trait CellRegistry: Send + Sync {
    fn resolve(&self, realm_id: &RealmId, cell: &CellRef) -> StoreResult<CellLatticeBinding>;
}
