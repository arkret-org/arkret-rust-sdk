//! Store trait contracts for the control-plane Event / Seal / StateModel runtime.
//!
//! Four traits cleanly partitioned by what they own:
//!
//! - [`ControlEventStore`] — pending + sealed control-plane Event log, addressed by `Hash` (the
//!   canonical `event_digest`).
//! - [`SealStore`] — confirmed per-Realm Seal chain, addressed by `SealId`.
//! - [`CellStore`] — per-cell sealed op log + per-view effective state cache.
//! - [`CellStateRegistry`] — `cell_family` → `StateModel` instance + `bottom` mode mapping.
//!
//! All four ship with [`memory`] backends used by tests / SDK harness.
//! Production servers (soland, third-party) implement durable backends
//! against the same trait surface.

pub mod memory;

use arkret_wire::event_envelope::Event;
pub use arkret_wire::{CausalRegisterBottomPolicy, EventCellExecution, EventCellValueShape};
use arkret_wire::{
    CommandOutcome, ControlProposalAck, ControlProposalDecision, ControlProposalDecisionPolicy,
    ReasonCode,
};
use async_trait::async_trait;
use thiserror::Error;

use crate::state_model::ordered_log::IssuedOp;
use crate::state_model::{DomainTransitionRule, ResolvedCellState, StateModel, StateModelKind};
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

/// One Event occurrence in an accepted Seal command result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealCommandEventDecision {
    pub seal_id: SealId,
    pub command_index: u32,
    pub member_index: u32,
    pub outcome: CommandOutcome,
    pub reason_code: Option<ReasonCode>,
}

/// A control Event with a durable committed or rejected Seal result.
#[derive(Clone, Debug, PartialEq)]
pub struct DecidedControlEventRecord {
    pub event: Event,
    /// Trusted Realm digest suite used to key this exact accepted Event.
    pub digest_suite: arkret_canonical::DigestSuite,
    pub covering_seals: Vec<SealId>,
    pub command_decisions: Vec<SealCommandEventDecision>,
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

/// One member submitted as part of a registered atomic command unit.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlUnitIngressMember {
    pub event: Event,
    pub digest_suite: arkret_canonical::DigestSuite,
    pub ingress: ControlProposalIngress,
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

/// A pending registered command unit in normative member order.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingControlUnitRecord {
    pub members: Vec<PendingControlEventRecord>,
}

/// Exact durable state for one Control Proposal digest.
///
/// Unlike pending/notary work queues, this point lookup preserves bounded
/// defers and terminal Seal command decisions, so decision submit replay and
/// the authenticated decision-read operation never infer state from queue
/// membership.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlProposalSnapshot {
    pub event: Event,
    /// Trusted Realm digest suite used to key this exact accepted Event.
    pub digest_suite: arkret_canonical::DigestSuite,
    pub control_proposal_ack: Option<ControlProposalAck>,
    pub ingress_class: ControlProposalIngressClass,
    pub decisions: Vec<ControlProposalDecision>,
    pub covering_seals: Vec<SealId>,
    pub command_decisions: Vec<SealCommandEventDecision>,
    pub decision_overdue: bool,
}

/// Fenced ownership of one due Control Seal Realm attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlSealScheduleClaim {
    pub realm_id: RealmId,
    pub generation: u64,
    pub holder: String,
    pub fence: u64,
    pub claimed_at_ms: i64,
    pub claim_until_ms: i64,
    pub scan_cursor: Option<Hash>,
    /// A failed or interrupted attempt must probe individual ordinary
    /// candidates before returning to batching; Genesis remains indivisible.
    pub isolate_candidates: bool,
}

/// Durable classification of one bounded Control Seal attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlSealAttemptOutcome {
    ProgressPublished,
    NoAcceptedMoves,
    LocalSignerNotAuthority,
    NotaryValueUnavailable,
    SignerSlotUnavailable,
    ProposalPolicyUnavailable,
    SigningLeaseBusy,
    TransientStoreFailure,
    SigningFailed,
    PassTimedOut,
}

impl ControlSealAttemptOutcome {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ProgressPublished => "progress_published",
            Self::NoAcceptedMoves => "no_accepted_moves",
            Self::LocalSignerNotAuthority => "local_signer_not_authority",
            Self::NotaryValueUnavailable => "notary_value_unavailable",
            Self::SignerSlotUnavailable => "signer_slot_unavailable",
            Self::ProposalPolicyUnavailable => "proposal_policy_unavailable",
            Self::SigningLeaseBusy => "signing_lease_busy",
            Self::TransientStoreFailure => "transient_store_failure",
            Self::SigningFailed => "signing_failed",
            Self::PassTimedOut => "pass_timed_out",
        }
    }

    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::SignerSlotUnavailable
                | Self::ProposalPolicyUnavailable
                | Self::TransientStoreFailure
                | Self::SigningFailed
                | Self::PassTimedOut
        )
    }

    /// Compute the next due time from the outcome and the post-attempt
    /// consecutive failure count. Delays are operational, bounded, and shared
    /// by every backend so memory and durable stores cannot drift.
    #[must_use]
    pub fn next_eligible_at_ms(&self, observed_at_ms: i64, consecutive_failures: u32) -> i64 {
        let delay_ms = match self {
            Self::ProgressPublished => 0,
            Self::SigningLeaseBusy => 1_000,
            Self::NoAcceptedMoves | Self::NotaryValueUnavailable => 5_000,
            Self::LocalSignerNotAuthority => 60_000,
            Self::SignerSlotUnavailable
            | Self::ProposalPolicyUnavailable
            | Self::TransientStoreFailure
            | Self::SigningFailed
            | Self::PassTimedOut => {
                let exponent = consecutive_failures.saturating_sub(1).min(6);
                1_000_i64.saturating_mul(1_i64 << exponent).min(60_000)
            }
        };
        observed_at_ms.saturating_add(delay_ms)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlSealAttemptCompletion {
    Applied,
    ReleasedNewGeneration,
    StaleClaim,
}

impl ControlSealAttemptCompletion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::ReleasedNewGeneration => "released_new_generation",
            Self::StaleClaim => "stale_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlSealScheduleRepairStats {
    pub scanned: usize,
    pub inserted: usize,
    pub generation_repaired: usize,
    pub stale_deleted: usize,
    pub cursor_wrapped: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlSealScheduleStats {
    pub pending: usize,
    pub eligible: usize,
    pub claimed: usize,
    pub expired_claims: usize,
    pub oldest_pending_at_ms: Option<i64>,
    pub oldest_eligible_at_ms: Option<i64>,
}

/// Pending + sealed control-plane Event log.
///
/// A Control Move is an [`Event`] carrying `seal_basis`
/// (`event-auth-state-resolution.md` §5); there is no separate Move object,
/// so this store holds Events and keys them by [`control_event_digest`].
#[async_trait]
pub trait ControlEventStore: Send + Sync {
    /// Stash a control-plane Event that passed local format / proof
    /// pre-check, together with its durable ingress classification.
    /// Re-submission of the same complete unit with byte-identical ingress is
    /// idempotent. Any different member order, boundary, class, Ack, or digest
    /// suite is a conflict.
    ///
    /// The class and its payload are inseparable: `AckRequired` carries the
    /// canonical Control Proposal Ack and `AcklessSelfPrincipal` carries no
    /// Ack, so an Ack-required Move without its Ack cannot be written.
    async fn put_pending_unit_with_ingress(
        &self,
        members: &[ControlUnitIngressMember],
    ) -> StoreResult<Vec<Hash>>;

    /// Persist every member decision from an accepted Seal atomically.
    /// Committed members in `Seal.delta` additionally become direct coverage;
    /// rejected members become terminal without entering coverage.
    async fn record_seal_command_results(&self, seal: &Seal) -> StoreResult<()>;

    async fn get(&self, event_digest: &Hash) -> StoreResult<Option<Event>>;

    /// Trusted digest suite frozen atomically with the accepted Control Event.
    async fn digest_suite(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<arkret_canonical::DigestSuite>>;

    /// Exact registered unit boundary and normative member order for an Event.
    async fn registered_unit_members(&self, event_digest: &Hash) -> StoreResult<Option<Vec<Hash>>>;

    /// Every accepted Seal whose `delta[]` directly covers `event_digest`.
    ///
    /// This is the bounded internal point lookup for decision state and for
    /// preparing explicit Seal-only resolve selectors. Event resolve never
    /// attaches covering Seals. Scanning [`Self::list_decided`] would answer
    /// the same question but is unbounded in the Realm's history.
    /// Default implementation reports the backend as unmigrated, matching
    /// [`SealStore::successors`].
    async fn covering_seals(&self, _event_digest: &Hash) -> StoreResult<Vec<SealId>> {
        Err(StoreError::Backend(
            "ControlEventStore::covering_seals not implemented for this backend".to_owned(),
        ))
    }

    async fn control_proposal_ack(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalAck>>;

    /// Read one proposal/Ack/decision/Seal row-set from a single backend
    /// snapshot. Unknown digests return `None`; no terminal state is removed.
    async fn control_proposal_snapshot(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalSnapshot>>;

    async fn record_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
        policy: ControlProposalDecisionPolicy,
    ) -> StoreResult<()>;

    /// Diagnostic records ordered by Ack absolute deadline and proposal digest.
    /// Ack-less rows sort first so a missing obligation cannot hide behind a
    /// bounded Ack sample. Notary work uses its separate insertion-order scan.
    async fn list_pending_records(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlEventRecord>>;

    /// Atomically claim due Realm schedule rows in fair due-time order.
    /// Callers MUST pass no more than their currently free execution slots.
    async fn claim_due_control_seal_realms(
        &self,
        holder: &str,
        now_ms: i64,
        claim_until_ms: i64,
        limit: usize,
    ) -> StoreResult<Vec<ControlSealScheduleClaim>>;

    /// Complete one fenced attempt. A matching fence with a newer generation
    /// releases the claim without applying the stale outcome or its backoff.
    async fn complete_control_seal_attempt(
        &self,
        claim: &ControlSealScheduleClaim,
        outcome: &ControlSealAttemptOutcome,
        observed_at_ms: i64,
    ) -> StoreResult<ControlSealAttemptCompletion>;

    /// Persist page progress before attempting work. Expired or replaced
    /// claims cannot move the cursor; newer ingress does not reset progress.
    async fn advance_control_seal_scan(
        &self,
        claim: &ControlSealScheduleClaim,
        cursor: Option<&Hash>,
        observed_at_ms: i64,
    ) -> StoreResult<bool>;

    /// Run one bounded page of the always-on repair scan over authoritative
    /// pending Event state.
    async fn repair_control_seal_schedule(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> StoreResult<ControlSealScheduleRepairStats>;

    /// Return a bounded aggregate snapshot for scrape-time scheduling gauges.
    /// Implementations must not enumerate Realm identifiers in the result.
    async fn control_seal_schedule_stats(
        &self,
        now_ms: i64,
    ) -> StoreResult<ControlSealScheduleStats>;

    /// Pending registered units for the notary worker, oldest unit first.
    /// Pagination never splits one unit.
    async fn list_pending_units_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlUnitRecord>>;

    /// Decided control Event list for federation backfill / audit replay.
    async fn list_decided(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<DecidedControlEventRecord>>;
}

/// Confirmed per-Realm Seal chain.
#[async_trait]
pub trait SealStore: Send + Sync {
    /// Durably reserve the first complete signing body at `(realm_id, notary_seq)`.
    /// Before first insertion, require the current confirmed predecessor and next sequence.
    /// Once reserved, return the original body on every retry; never replace it on lease
    /// expiry, failover, configuration change, or a competing candidate. A digest-suite
    /// mismatch is a conflict. The caller must sign only the returned body.
    async fn reserve_signing_body(
        &self,
        body: &arkret_wire::UnsignedSeal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<arkret_wire::UnsignedSeal>;

    /// Recover immutable signing material before rebuilding or executing a candidate.
    async fn signing_body(
        &self,
        realm_id: &RealmId,
        notary_seq: u64,
    ) -> StoreResult<Option<arkret_wire::UnsignedSeal>>;

    /// Acquire a bounded, fenced signing lease for one `(Realm, signer slot)`.
    ///
    /// The confirmed sequenced-state coordinator uses one Realm-wide slot.
    async fn try_claim_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> StoreResult<Option<u64>>;

    async fn release_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        fence: u64,
    ) -> StoreResult<bool>;

    /// Atomically insert `seal` only when the Realm's confirmed head equals
    /// `expected_head`. Genesis uses `None`; every successor uses its signed
    /// `predecessor_ref`.
    ///
    /// Returns `true` when the Seal was inserted and `false` when the expected
    /// head was stale. A `false` result MUST leave the store unchanged.
    async fn put_if_head(
        &self,
        seal: &Seal,
        expected_head: Option<&SealId>,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool>;

    async fn get(&self, id: &SealId) -> StoreResult<Option<Seal>>;

    /// Trusted digest suite frozen atomically with the accepted Seal.
    async fn digest_suite(&self, id: &SealId)
    -> StoreResult<Option<arkret_canonical::DigestSuite>>;

    /// Current confirmed head for a Realm.
    async fn confirmed_head(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>>;

    /// Whether the signed predecessor has been seen by this store. Genesis has
    /// no predecessor and is therefore known structurally.
    async fn predecessor_known(&self, predecessor_ref: Option<&SealId>) -> StoreResult<bool>;

    /// The Realm's genesis Seal, if any. Each Realm has at most one.
    async fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>>;

    /// Direct successors of `seal_id` — every Seal `S` for which
    /// `S.predecessor_ref == Some(seal_id)`. This is a read-only chain query;
    /// callers MUST NOT rewrite signed predecessor references or delete an
    /// object while any successor or retention pin still names it.
    /// Default implementation returns `StoreError::Backend("unsupported")`.
    async fn successors(&self, _realm_id: &RealmId, _seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        Err(StoreError::Backend(
            "SealStore::successors not implemented for this backend".to_owned(),
        ))
    }
}

/// Per-cell sealed op log + per-view effective-state cache.
#[async_trait]
pub trait CellStore: Send + Sync {
    /// All cells with at least one effect in this Realm. Used for
    /// `state_root` enumeration.
    async fn list_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>>;

    /// All sealed ops applying to this cell, in deterministic order.
    ///
    /// The issuer travels with the op because `ordered_log` keys its slots by
    /// `(cell, actor_id, issuer_seq)` (`event-auth-state-resolution.md` 9.3.1).
    /// A store that dropped it would force every join back onto a synthetic
    /// issuer, merging distinct actors into one sub-chain and writing that
    /// synthetic DID into the `state_root` leaf.
    async fn state_writes_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<IssuedOp>>;

    /// Confirmed security operations grouped by the Seal that accepted them,
    /// in Seal acceptance order.
    ///
    /// Ordered command replay and registered-unit atomicity are authenticated
    /// by the Seal's `command_results`; this log contains only the committed
    /// effects after that replay succeeds.
    async fn confirmed_write_batches_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<(SealId, Vec<IssuedOp>)>>;

    /// Cached effective state. `None` means the runtime must recompute.
    async fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<ResolvedCellState>>;

    async fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &ResolvedCellState,
    ) -> StoreResult<()>;

    /// `apply_seal` write-back: extend the per-cell op log atomically
    /// with one Seal's worth of effects.
    async fn append_confirmed_effects(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()>;

    /// Roll back a previously-`append_confirmed_effects` call when publishing the
    /// accepting Seal fails after candidate-state validation.
    async fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> StoreResult<()>;
}

/// Complete executable binding for one registered Cell family.
pub struct CellStateModelBinding {
    pub model: Box<dyn StateModel>,
    pub state_model: StateModelKind,
    pub execution: EventCellExecution,
    pub value_shape: EventCellValueShape,
    pub bottom_policy: Option<CausalRegisterBottomPolicy>,
    pub domain_transition: Option<DomainTransitionRule>,
}

impl std::fmt::Debug for CellStateModelBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellStateModelBinding")
            .field("state_model", &self.state_model)
            .field("execution", &self.execution)
            .field("value_shape", &self.value_shape)
            .field("bottom_policy", &self.bottom_policy)
            .field("has_domain_transition", &self.domain_transition.is_some())
            .finish()
    }
}

/// `cell_family` → `StateModel` instance mapping.
pub trait CellStateRegistry: Send + Sync {
    fn resolve(&self, realm_id: &RealmId, cell: &CellRef) -> StoreResult<CellStateModelBinding>;

    /// Identifies all rules used to derive a durable cell view for this Realm.
    ///
    /// Returning `Some` promises an immutable rule snapshot for the entire
    /// lifetime of this registry, including every `resolve` call. A mutable
    /// registry must return `None`; matching hashes before and after a call do
    /// not exclude an intervening rule change. Unknown contexts cannot reuse
    /// previously derived cell values. This is private execution metadata,
    /// never a replacement for accepted Seal bytes or current authorization.
    fn checkpoint_context(&self, _realm_id: &RealmId) -> StoreResult<Option<Hash>> {
        Ok(None)
    }
}

/// One transaction boundary for publishing an accepted Seal.
///
/// All read views must address the same backend. `commit_seal` compares the
/// confirmed head with `seal.predecessor_ref` and publishes the complete Cell
/// effects, new head, and every committed/rejected command member decision
/// together. Failure or a stale head must leave all three views unchanged.
#[async_trait]
pub trait SealCommitStore: Send + Sync {
    fn control_events(&self) -> &dyn ControlEventStore;
    fn seals(&self) -> &dyn SealStore;
    fn cells(&self) -> &dyn CellStore;
    async fn commit_seal(
        &self,
        seal: &Seal,
        new_ops: &[(CellRef, IssuedOp)],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool>;
}
