//! Store trait contracts for the control-plane Event / Seal / Lattice runtime.
//!
//! Four traits cleanly partitioned by what they own:
//!
//! - [`ControlEventStore`] — pending + sealed control-plane Event log, addressed by `Hash` (the
//!   canonical `event_digest`).
//! - [`SealStore`] — Seal DAG, addressed by `SealId`, plus leaf-set queries.
//! - [`CellStore`] — per-cell sealed op log + per-view effective state cache.
//! - [`CellRegistry`] — `cell_family` → `Lattice` instance + `bottom` mode mapping.
//!
//! All four ship with [`memory`] backends used by tests / SDK harness.
//! Production servers (soland, third-party) implement durable backends
//! against the same trait surface.

pub mod memory;

use arkret_wire::event_envelope::Event;
use arkret_wire::{ControlProposalDecision, ControlProposalReceipt};
use thiserror::Error;

use crate::lattice::ordered_log::IssuedOp;
use crate::lattice::{CellState, Lattice};
use crate::{CellRef, Hash, RealmId, Seal, SealId};

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

/// The canonical `event_digest` of a control-plane Event.
///
/// This — not `event_id` — is the store key, because it is the value
/// `Seal.delta[]` / `Seal.covered_event_digests[]` list and the value the
/// Merkle roots commit to. Keying on `event_id` would let the two variants
/// of an equivocated id share one slot, which is exactly the case
/// `event-auth-state-resolution.md` §6.3.2 requires to stay distinguishable.
pub fn control_event_digest(event: &Event) -> StoreResult<Hash> {
    let digest = event
        .event_digest()
        .map_err(|error| StoreError::Backend(format!("event_digest: {error}")))?;
    Hash::new(digest).map_err(|error| StoreError::Backend(format!("invalid event_digest: {error}")))
}

/// Sealed control-plane Event record: an Event that has been covered by
/// some accepted Seal. Carries the Seal id back-reference for audit and
/// deterministic ordering.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedControlEventRecord {
    pub event: Event,
    pub seal: SealId,
    pub proposal_receipt: Option<ControlProposalReceipt>,
    pub decisions: Vec<ControlProposalDecision>,
    pub decision_overdue: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingControlEventRecord {
    pub event: Event,
    pub proposal_receipt: Option<ControlProposalReceipt>,
    pub decisions: Vec<ControlProposalDecision>,
}

/// Pending + sealed control-plane Event log.
///
/// A Control Move is an [`Event`] carrying `seal_basis`
/// (`event-auth-state-resolution.md` §5); there is no separate Move object,
/// so this store holds Events and keys them by [`control_event_digest`].
pub trait ControlEventStore: Send + Sync {
    /// Stash a control-plane Event that passed local format / proof
    /// pre-check. Re-`put_pending` of the same digest MUST be idempotent.
    fn put_pending(&self, event: &Event) -> StoreResult<()> {
        self.put_pending_with_receipt(event, None)
    }

    /// Atomically bind the first proposal receipt to the pending Event.
    ///
    /// Replays may omit the receipt or provide the byte-identical stored
    /// value. A different receipt for the same digest is a conflict because it
    /// would move the already-committed deadlines.
    fn put_pending_with_receipt(
        &self,
        event: &Event,
        proposal_receipt: Option<&ControlProposalReceipt>,
    ) -> StoreResult<()>;

    /// Promote a previously-pending Event to sealed under `seal`.
    /// Re-anchoring the same Event under the same Seal id is idempotent.
    fn mark_sealed(&self, event_digest: &Hash, seal: &Seal) -> StoreResult<()>;

    fn get(&self, event_digest: &Hash) -> StoreResult<Option<Event>>;

    fn proposal_receipt(&self, event_digest: &Hash) -> StoreResult<Option<ControlProposalReceipt>>;

    fn record_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
    ) -> StoreResult<()>;

    fn list_pending_records(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlEventRecord>>;

    /// Canonical Realm ids with at least one pending Control Move.
    ///
    /// This is the reconciliation source after process restart or a lost
    /// in-memory wakeup. Results MUST be sorted and unique.
    fn list_pending_realms(&self, limit: usize) -> StoreResult<Vec<RealmId>>;

    /// Pending control-plane Event list for the notary worker, oldest first.
    fn list_pending_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<Event>>;

    /// Sealed control-plane Event list for federation backfill / audit replay.
    fn list_sealed(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>>;

    fn list_retained_faults(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>>;
}

/// Seal DAG.
pub trait SealStore: Send + Sync {
    /// Acquire a bounded, fenced signing lease for one `(Realm, signer slot)`.
    ///
    /// `single_did`, `threshold`, and mixed-primary coordinators use one
    /// Realm-wide slot. `open_set` uses the signer DID as the slot so distinct
    /// authorized signers can create concurrent leaves without racing
    /// themselves across replicas.
    fn try_claim_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> StoreResult<Option<u64>>;

    fn release_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        fence: u64,
    ) -> StoreResult<bool>;

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
    ///
    /// The issuer travels with the op because `ordered_log` keys its slots by
    /// `(cell, actor_id, issuer_seq)` (`event-auth-state-resolution.md` 9.3.1).
    /// A store that dropped it would force every join back onto a synthetic
    /// issuer, merging distinct actors into one sub-chain and writing that
    /// synthetic DID into the `state_root` leaf.
    fn sealed_ops_for_cell(&self, realm_id: &RealmId, cell: &CellRef)
    -> StoreResult<Vec<IssuedOp>>;

    /// Sealed operations grouped by the Seal batch that accepted them, in
    /// Seal acceptance order.
    ///
    /// The batch boundary is consensus-significant for registers: writes in
    /// one Seal share the frozen predecessor view and are concurrent siblings,
    /// while a write in a successor Seal causally replaces the prior head.
    fn sealed_op_batches_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<(SealId, Vec<IssuedOp>)>>;

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
        new_ops: &[(CellRef, IssuedOp)],
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
    /// The registered lattice cannot produce Bottom. Encountering one is an
    /// implementation invariant failure and callers must fail closed.
    Inert,
}

/// `cell_family` → `Lattice` instance mapping.
pub trait CellRegistry: Send + Sync {
    fn resolve(&self, realm_id: &RealmId, cell: &CellRef) -> StoreResult<CellLatticeBinding>;
}
