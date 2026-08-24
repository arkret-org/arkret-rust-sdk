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
use arkret_wire::{ControlProposalAck, ControlProposalDecision, ControlProposalDecisionPolicy};
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
pub fn control_event_digest(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> StoreResult<Hash> {
    let digest = event
        .event_digest_with_digest_suite(digest_suite)
        .map_err(|error| StoreError::Backend(format!("event_digest: {error}")))?;
    Hash::new(digest).map_err(|error| StoreError::Backend(format!("invalid event_digest: {error}")))
}

/// Sealed control-plane Event record: an Event that has been covered by
/// one or more accepted Seals. Carries every direct Seal back-reference for audit and
/// deterministic ordering.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedControlEventRecord {
    pub event: Event,
    /// Trusted Realm digest suite used to key this exact accepted Event.
    pub digest_suite: arkret_canonical::DigestSuite,
    pub covering_seals: Vec<SealId>,
    pub control_proposal_ack: Option<ControlProposalAck>,
    pub decisions: Vec<ControlProposalDecision>,
    pub decision_overdue: bool,
    /// The ingress class this Move was admitted under
    /// (`event-auth-state-resolution.md` §7.2).
    pub ingress_class: ControlProposalIngressClass,
}

/// Stable references the first admission of an Ack-less authority-authored
/// human self-principal PCR Move was proven against.
///
/// Reads replay these references instead of re-judging the Move against
/// read-time current device generations or notary policy: the class binds the
/// exact producer device fragment, the accepted `ak.device.authorize` Event
/// the device authorization was resolved from, the device generation that
/// authorization was bound to, and the digest of the Event's signed Seal
/// basis at admission.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcklessSelfPrincipalIngress {
    /// Device fragment (`ak:device:<id>`) of the Event's sole producer proof.
    pub device_id: String,
    /// The accepted `ak.device.authorize` Event id the producer device
    /// authorization was resolved against at admission.
    pub device_authorize_event_id: String,
    /// The device generation the authorization was bound to at admission.
    pub device_generation_ref: u64,
    /// `canonical_sha256` of the Event's signed Seal basis at admission.
    pub seal_basis_digest: String,
}

/// How one pending Control Move was admitted at durable ingress
/// (`event-auth-state-resolution.md` §7.2).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum ControlProposalIngressClass {
    /// The ordinary rail: the Move is bound to the canonical Control
    /// Proposal Ack stored on the same row. The Ack is the unique normative
    /// carrier of the authority set ref, so the class deliberately stores no
    /// second copy.
    AckRequired,
    /// The one Ack-less exception: an authority-authored human
    /// self-principal PCR Move.
    AcklessSelfPrincipal(AcklessSelfPrincipalIngress),
}

/// Ingress binding of one pending Control Move: the admission class plus the
/// data that class requires. `AckRequired` carries its Ack, so a pending row
/// missing a mandatory Ack is unrepresentable at the store boundary.
#[derive(Clone, Debug, PartialEq)]
pub enum ControlProposalIngress {
    AckRequired(ControlProposalAck),
    AcklessSelfPrincipal(AcklessSelfPrincipalIngress),
}

impl ControlProposalIngress {
    #[must_use]
    pub fn class(&self) -> ControlProposalIngressClass {
        match self {
            Self::AckRequired(_) => ControlProposalIngressClass::AckRequired,
            Self::AcklessSelfPrincipal(class) => {
                ControlProposalIngressClass::AcklessSelfPrincipal(class.clone())
            }
        }
    }

    #[must_use]
    pub fn ack(&self) -> Option<&ControlProposalAck> {
        match self {
            Self::AckRequired(ack) => Some(ack),
            Self::AcklessSelfPrincipal(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingControlEventRecord {
    pub event: Event,
    /// Trusted Realm digest suite used to key this exact accepted Event.
    pub digest_suite: arkret_canonical::DigestSuite,
    pub control_proposal_ack: Option<ControlProposalAck>,
    pub decisions: Vec<ControlProposalDecision>,
    /// The ingress class this Move was admitted under
    /// (`event-auth-state-resolution.md` §7.2).
    pub ingress_class: ControlProposalIngressClass,
}

/// Exact durable state for one Control Proposal digest.
///
/// Unlike pending/notary work queues, this point lookup preserves terminal
/// signed rejects and accepted Seal coverage, so decision submit replay and
/// the authenticated decision-read operation never infer state from queue
/// membership.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlProposalSnapshot {
    pub event: Event,
    /// Trusted Realm digest suite used to key this exact accepted Event.
    pub digest_suite: arkret_canonical::DigestSuite,
    pub control_proposal_ack: Option<ControlProposalAck>,
    pub decisions: Vec<ControlProposalDecision>,
    pub covering_seals: Vec<SealId>,
    pub decision_overdue: bool,
}

/// Pending + sealed control-plane Event log.
///
/// A Control Move is an [`Event`] carrying `seal_basis`
/// (`event-auth-state-resolution.md` §5); there is no separate Move object,
/// so this store holds Events and keys them by [`control_event_digest`].
pub trait ControlEventStore: Send + Sync {
    /// Stash a control-plane Event that passed local format / proof
    /// pre-check, together with its durable ingress classification.
    /// Re-`put_pending_with_ingress` of the same digest with the
    /// byte-identical ingress MUST be idempotent; a different class or Ack
    /// for the same digest is a conflict because it would move the
    /// already-committed admission basis or deadlines.
    ///
    /// The class and its payload are inseparable: `AckRequired` carries the
    /// canonical Control Proposal Ack and `AcklessSelfPrincipal` carries no
    /// Ack, so an Ack-required Move without its Ack cannot be written.
    fn put_pending_with_ingress(
        &self,
        event: &Event,
        ingress: &ControlProposalIngress,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()>;

    /// Promote a previously-pending Event to sealed under `seal`.
    /// Re-anchoring the same Event under the same Seal id is idempotent.
    fn mark_sealed(&self, event_digest: &Hash, seal: &Seal) -> StoreResult<()>;

    fn get(&self, event_digest: &Hash) -> StoreResult<Option<Event>>;

    /// Trusted digest suite frozen atomically with the accepted Control Event.
    fn digest_suite(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<arkret_canonical::DigestSuite>>;

    /// Every accepted Seal whose `delta[]` directly covers `event_digest`.
    ///
    /// This is the bounded internal point lookup for decision state and for
    /// preparing explicit Seal-only resolve selectors. Event resolve never
    /// attaches covering Seals. Scanning [`Self::list_sealed`] would answer
    /// the same question but is unbounded in the Realm's history.
    /// Default implementation reports the backend as unmigrated, matching
    /// [`SealStore::successors`].
    fn covering_seals(&self, _event_digest: &Hash) -> StoreResult<Vec<SealId>> {
        Err(StoreError::Backend(
            "ControlEventStore::covering_seals not implemented for this backend".to_owned(),
        ))
    }

    fn control_proposal_ack(&self, event_digest: &Hash) -> StoreResult<Option<ControlProposalAck>>;

    /// Read one proposal/Ack/decision/Seal row-set from a single backend
    /// snapshot. Unknown digests return `None`; no terminal state is removed.
    fn control_proposal_snapshot(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalSnapshot>>;

    fn record_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
        policy: ControlProposalDecisionPolicy,
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
    /// Single-signer, threshold, and mixed-primary coordinators use one
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

    fn put(&self, seal: &Seal, digest_suite: arkret_canonical::DigestSuite) -> StoreResult<()>;

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
    fn put_if_frontier(
        &self,
        seal: &Seal,
        expected_leaves: &[SealId],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool>;

    fn get(&self, id: &SealId) -> StoreResult<Option<Seal>>;

    /// Trusted digest suite frozen atomically with the accepted Seal.
    fn digest_suite(&self, id: &SealId) -> StoreResult<Option<arkret_canonical::DigestSuite>>;

    /// Current leaf set for a Realm (Seals with no successor).
    fn list_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>>;

    /// Whether all `refs` have been seen by this store.
    fn predecessors_known(&self, refs: &[SealId]) -> StoreResult<bool>;

    /// The Realm's genesis Seal, if any. Each Realm has at most one.
    fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>>;

    /// Direct successors of `seal_id` — every Seal `S` for which
    /// `S.predecessor_refs.contains(seal_id)`. This is a read-only DAG query;
    /// callers MUST NOT rewrite signed predecessor references or delete an
    /// object while any successor, frontier, or retention pin still names it.
    /// Default implementation returns `StoreError::Backend("unsupported")`.
    fn successors(&self, _realm_id: &RealmId, _seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        Err(StoreError::Backend(
            "SealStore::successors not implemented for this backend".to_owned(),
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

    /// Roll back a previously-`append_sealed_effects` call when publishing the
    /// accepting Seal fails after candidate-state validation.
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
