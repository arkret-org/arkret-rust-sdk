//! Store trait contracts for the Move/Anchor/Lattice runtime.
//!
//! Four traits cleanly partitioned by what they own:
//!
//! - [`MoveStore`] — pending + anchored Move log, addressed by `MoveId`.
//! - [`AnchorStore`] — Anchor DAG, addressed by `AnchorId`, plus leaf-set queries.
//! - [`CellStore`] — per-cell anchored op log + per-view effective state cache.
//! - [`CellRegistry`] — `cell_family` → `Lattice` instance + `bottom` mode mapping.
//!
//! All four ship with [`memory`] backends used by tests / SDK harness.
//! Production servers (soland, third-party) implement durable backends
//! against the same trait surface.

pub mod memory;

use crate::{
    Anchor, AnchorId, CellRef, Hash, Move, MoveId, SpaceId,
    lattice::{AnchoredOp, CellState, Lattice},
};
use thiserror::Error;

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

/// Anchored Move record: a Move that has been included in some
/// Anchor.frontier. Carries the Anchor id back-reference for audit and
/// deterministic ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchoredMoveRecord {
    pub move_value: Move,
    pub anchor: AnchorId,
}

/// Pending + anchored Move log.
pub trait MoveStore: Send + Sync {
    /// Stash a Move that passed local format / signature pre-check.
    /// Re-`put_pending` of the same id MUST be idempotent.
    fn put_pending(&self, m: &Move) -> StoreResult<()>;

    /// Promote a previously-pending Move to anchored under `anchor`.
    /// Re-anchoring the same Move under the same Anchor id is idempotent.
    fn mark_anchored(&self, id: &MoveId, anchor: &AnchorId) -> StoreResult<()>;

    fn get(&self, id: &MoveId) -> StoreResult<Option<Move>>;

    /// Pending Move list for the anchorer worker, oldest first.
    fn list_pending_for_anchorer(
        &self,
        space_id: &SpaceId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<Move>>;

    /// Anchored Move list for federation backfill / audit replay.
    fn list_anchored(
        &self,
        space_id: &SpaceId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<AnchoredMoveRecord>>;
}

/// Anchor DAG.
pub trait AnchorStore: Send + Sync {
    fn put(&self, a: &Anchor) -> StoreResult<()>;

    fn get(&self, id: &AnchorId) -> StoreResult<Option<Anchor>>;

    /// Current leaf set for a Space (Anchors with no successor).
    fn list_leaves(&self, space_id: &SpaceId) -> StoreResult<Vec<AnchorId>>;

    /// Whether all `refs` have been seen by this store.
    fn predecessors_known(&self, refs: &[AnchorId]) -> StoreResult<bool>;

    /// The Space's genesis Anchor, if any. Each Space has at most one.
    fn genesis(&self, space_id: &SpaceId) -> StoreResult<Option<AnchorId>>;

    /// Direct successors of `anchor_id` — every Anchor `S` for which
    /// `S.predecessor_refs.contains(anchor_id)`. Used by the MAL-11
    /// compaction pipeline to find what to rewire when pruning a
    /// historical Anchor. Default implementation returns
    /// `StoreError::Backend("unsupported")` so existing backends that
    /// haven't migrated still compile; production backends MUST override
    /// once they need compaction.
    fn successors(&self, _space_id: &SpaceId, _anchor_id: &AnchorId) -> StoreResult<Vec<AnchorId>> {
        Err(StoreError::Backend(
            "AnchorStore::successors not implemented for this backend".to_owned(),
        ))
    }

    /// MAL-11: drop `anchor_id` from the DAG and rewire its direct
    /// successors so their `predecessor_refs` point through to
    /// `anchor_id`'s parents instead. The caller MUST have validated that
    /// pruning is safe (downstream witnessed by a compaction Anchor,
    /// `CompactionPolicy` accepts the candidate, etc.) — the trait only
    /// performs the structural rewrite.
    ///
    /// Returns the list of successor Anchor ids that were rewired so the
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
        _space_id: &SpaceId,
        _anchor_id: &AnchorId,
    ) -> StoreResult<Vec<AnchorId>> {
        Err(StoreError::Backend(
            "AnchorStore::prune_predecessor not implemented for this backend".to_owned(),
        ))
    }
}

/// Per-cell anchored op log + per-view effective-state cache.
pub trait CellStore: Send + Sync {
    /// All cells with at least one effect in this Space. Used for
    /// `state_root` enumeration.
    fn list_cells(&self, space_id: &SpaceId) -> StoreResult<Vec<CellRef>>;

    /// All anchored ops applying to this cell, in deterministic order.
    fn anchored_ops_for_cell(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
    ) -> StoreResult<Vec<AnchoredOp>>;

    /// Cached effective state. `None` means the runtime must recompute.
    fn cached_state(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<CellState>>;

    fn put_cached_state(
        &self,
        space_id: &SpaceId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> StoreResult<()>;

    /// `apply_anchor` write-back: extend the per-cell op log atomically
    /// with one Anchor's worth of effects.
    fn append_anchored_effects(
        &self,
        space_id: &SpaceId,
        anchor: &AnchorId,
        new_ops: &[(CellRef, AnchoredOp)],
    ) -> StoreResult<()>;

    /// Roll back a previously-`append_anchored_effects` call when the
    /// computed state_root failed to match `Anchor.state_root`.
    fn rollback_anchor(&self, space_id: &SpaceId, anchor: &AnchorId) -> StoreResult<()>;
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
    fn resolve(&self, space_id: &SpaceId, cell: &CellRef) -> StoreResult<CellLatticeBinding>;
}
