//! Journaled direct Seal traversal for bulk/old history governance.
//!
//! `zh/governance/history-visibility.md` §5 splits governance verification in
//! two: the bounded near-current `group_security_frontier` query, and this
//! receipt-bound direct traversal for everything older. The traversal walks
//! backwards from the release service's `target_basis` along each Seal's
//! already-signed `predecessor_ref` until it reaches the caller-pinned,
//! independently verified predecessor-free `trusted_history_base_basis`, and
//! only then replays the discovered cut forwards through the ordinary
//! `apply_seal` reducer.
//!
//! Two things are deliberately separated here.
//!
//! * **Discovery** is streaming and durable. The work queue and visited set are a caller-supplied
//!   [`DirectTraversalJournal`] port ("SQLite or an equivalent disk-backed work queue and visited
//!   set", `history-visibility.md` §5), so the verifier keeps only the Seal descriptor it is
//!   currently expanding plus a constant number of accumulators live. Nothing about the discovered
//!   cut is materialized in this crate's memory.
//! * **Replay** reuses the existing reducer through [`crate::apply_replayed_seal_in_context`].
//!   There is exactly one implementation of notary selection, delta admission, root recomputation
//!   and Bottom/recovery in the SDK, and direct traversal streams Seals into it one at a time
//!   rather than handing it a materialized `Vec<Seal>`. The reducer stores and returned effective
//!   state still grow with the accepted history; durable discovery does not bound the replay
//!   phase's total memory.
//!
//! The two verifier phases are separately callable because they consume
//! different evidence: discovery needs only signed `(seal_ref,
//! predecessor_ref)` descriptors, while replay needs complete Seal and Event
//! bytes. The closed-cut vectors in
//! `fixtures/history-key-recovery-fixture.json#/direct_traversal_kat` exercise
//! discovery directly; sibling `direct_traversal_replay_kat` constructs a
//! deterministic Genesis + successor cut and exercises full replay, including
//! ambiguous material admission and predecessor-frozen notary keys.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::mls::{MlsProposalPayload, MlsProposalType};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencyResolveOutcome,
};
use arkret_models_collaboration::history_key::AuthorizationIncarnation;
use arkret_models_crypto::mls_payloads::MlsCommitPayload;
use arkret_wire::error_codes::{ErrorCode, ReasonCode};
use arkret_wire::event_envelope::Event;
use arkret_wire::{
    CellRef, EventId, Hash, NotarySignerDescriptor, NotaryValue, RealmId, Seal, SealBasis, SealId,
    SealSignature, WireError, event_kind_str,
};
use async_trait::async_trait;
use serde_json::Value;

use crate::mls_governance_proof::{
    ReplayEventLookup, SealDependencyReplayContext, live_digest_suite_at_basis, replay_one_seal,
};
use crate::state::store::memory::{MemoryCellStore, MemoryControlEventStore, MemorySealStore};
use crate::state_model::ResolvedCellState;
use crate::{CellStateRegistry, ControlEventStore, SealStore, effective_state_at};

/// Upper bound on the number of Seals one direct-traversal cut may visit.
///
/// `zh/conformance/conformance-vectors.md` freezes a 65,536-epoch traversal
/// ceiling; the corresponding Seal chain carries one additional bootstrap Seal.
/// The budget is checked against the responder's declared descriptor count
/// **before** the first journal row is written, so an over-limit cut leaves
/// every durable counter at zero.
pub const MAX_DIRECT_TRAVERSAL_SEALS: u64 = 65_537;

/// Closed set of reasons a target -> base cut is not a valid closed interval.
///
/// The string forms are the machine vocabulary used by
/// `direct_traversal_kat.negative_cases`; they are the verifier's canonical
/// output, not a second error namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DirectTraversalError {
    /// A pinned base leaf was never reached by any target-rooted path.
    BaseLeafNotConsumed,
    /// The responder offered more Seals than the v1 traversal ceiling admits.
    BoundsExceeded,
    /// A Seal reachable from the target has no resolvable descriptor.
    DependencyMissing,
    /// The responder offered the same `seal_ref` twice.
    DuplicateDescriptor,
    /// An in-interval Seal has no predecessor and is not a base leaf, so the
    /// branch terminates before the caller-pinned bootstrap cut.
    IntervalStopsBeforeBase,
    /// The responder offered a Seal outside the target -> base closure.
    SurplusDescriptor,
    /// At least one anti-rollback `trusted_current_basis` leaf is not dominated
    /// by the target antichain.
    TrustedCurrentNotDominated,
}

impl DirectTraversalError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseLeafNotConsumed => "base_leaf_not_consumed",
            Self::BoundsExceeded => "bounds_exceeded",
            Self::DependencyMissing => "dependency_missing",
            Self::DuplicateDescriptor => "duplicate_descriptor",
            Self::IntervalStopsBeforeBase => "interval_stops_before_base",
            Self::SurplusDescriptor => "surplus_descriptor",
            Self::TrustedCurrentNotDominated => "trusted_current_not_dominated",
        }
    }

    /// Wire error code for this rejection.
    ///
    /// Missing required material is `dependency_missing`; an over-budget cut is
    /// `limit_exceeded`; every concurrency/unreachability cause shares
    /// `frontier_unavailable` at the envelope level and carries
    /// [`ReasonCode::HistoryTraversalAnchorUnreachable`].
    pub fn error_code(self) -> ErrorCode {
        match self {
            Self::DependencyMissing => ErrorCode::DependencyMissing,
            Self::BoundsExceeded => ErrorCode::LimitExceeded,
            _ => ErrorCode::FrontierUnavailable,
        }
    }

    pub fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Self::DependencyMissing => Some(ReasonCode::DependencyMissing),
            Self::BoundsExceeded => None,
            _ => Some(ReasonCode::HistoryTraversalAnchorUnreachable),
        }
    }
}

/// One Seal's signed reverse-traversal descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealPredecessorDescriptor {
    pub seal_ref: SealId,
    pub predecessor_ref: Option<SealId>,
}

/// The caller-pinned coordinates of one direct-traversal cut.
///
/// All three antichains come from the request receipt's frozen
/// `HistoryGovernanceTraversalIntent`; the verifier never substitutes a single
/// head, a common descendant or a service-selected basis for any of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectCutRequest {
    pub realm_id: RealmId,
    pub trusted_history_base_basis: SealBasis,
    pub trusted_current_basis: SealBasis,
    pub target_basis: SealBasis,
}

impl DirectCutRequest {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.trusted_history_base_basis.validate_protocol_bounds()?;
        self.trusted_current_basis.validate_protocol_bounds()?;
        self.target_basis.validate_protocol_bounds()
    }
}

/// One durable work-queue row.
///
/// `expanded` distinguishes the two visits an iterative depth-first post-order
/// makes to each Seal: the first discovers its predecessors, the second emits it
/// into the topological log once every predecessor has already been emitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectTraversalWorkItem {
    pub seal_ref: SealId,
    pub expanded: bool,
}

/// Durable work queue, visited set and topological log for one traversal.
///
/// The queue is LIFO. Implementations are expected to be crash-safe and
/// disk-backed (SQLite or equivalent); this crate never assumes the rows fit in
/// memory and only ever holds the row it just popped.
pub trait DirectTraversalJournal {
    /// Drop every row of a previous traversal. Called once before the budget
    /// check so `written_row_count` is a truthful pre-write counter.
    fn reset(&mut self) -> arkret_wire::Result<()>;

    fn push_work(&mut self, item: DirectTraversalWorkItem) -> arkret_wire::Result<()>;

    fn pop_work(&mut self) -> arkret_wire::Result<Option<DirectTraversalWorkItem>>;

    /// Insert into the visited set; returns `false` when already present.
    fn mark_visited(&mut self, seal_ref: &SealId) -> arkret_wire::Result<bool>;

    fn contains_visited(&self, seal_ref: &SealId) -> arkret_wire::Result<bool>;

    fn visited_count(&self) -> arkret_wire::Result<u64>;

    /// Append one Seal to the base -> target topological log.
    fn record_topological(&mut self, seal_ref: &SealId) -> arkret_wire::Result<()>;

    fn topological_len(&self) -> arkret_wire::Result<u64>;

    fn topological_at(&self, index: u64) -> arkret_wire::Result<Option<SealId>>;

    /// Stream the topological log oldest first.
    fn for_each_topological(
        &self,
        visit: &mut dyn FnMut(&SealId) -> arkret_wire::Result<()>,
    ) -> arkret_wire::Result<()>;

    /// Total rows this journal has written since the last [`Self::reset`].
    fn written_row_count(&self) -> arkret_wire::Result<u64>;
}

/// Bounded in-memory reference journal.
///
/// Production callers (`soland`, `inkson`) supply a SQLite-backed
/// implementation. This one exists so the SDK's own vectors and any embedder
/// without durable storage still get an explicit, enforced ceiling instead of an
/// unbounded allocation.
#[derive(Clone, Debug)]
pub struct BoundedDirectTraversalJournal {
    capacity: u64,
    work: Vec<DirectTraversalWorkItem>,
    visited: BTreeSet<SealId>,
    topological: Vec<SealId>,
    written_rows: u64,
}

impl BoundedDirectTraversalJournal {
    pub fn with_capacity(capacity: u64) -> Self {
        Self {
            capacity,
            work: Vec::new(),
            visited: BTreeSet::new(),
            topological: Vec::new(),
            written_rows: 0,
        }
    }

    fn charge_row(&mut self) -> arkret_wire::Result<()> {
        self.written_rows = self.written_rows.saturating_add(1);
        if self.visited.len() as u64 > self.capacity
            || self.topological.len() as u64 > self.capacity
            || self.work.len() as u64 > self.capacity.saturating_mul(2)
        {
            return Err(WireError::Protocol(
                "direct traversal journal exceeded its bounded capacity".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Default for BoundedDirectTraversalJournal {
    fn default() -> Self {
        Self::with_capacity(MAX_DIRECT_TRAVERSAL_SEALS)
    }
}

impl DirectTraversalJournal for BoundedDirectTraversalJournal {
    fn reset(&mut self) -> arkret_wire::Result<()> {
        self.work.clear();
        self.visited.clear();
        self.topological.clear();
        self.written_rows = 0;
        Ok(())
    }

    fn push_work(&mut self, item: DirectTraversalWorkItem) -> arkret_wire::Result<()> {
        self.work.push(item);
        self.charge_row()
    }

    fn pop_work(&mut self) -> arkret_wire::Result<Option<DirectTraversalWorkItem>> {
        Ok(self.work.pop())
    }

    fn mark_visited(&mut self, seal_ref: &SealId) -> arkret_wire::Result<bool> {
        let inserted = self.visited.insert(seal_ref.clone());
        if inserted {
            self.charge_row()?;
        }
        Ok(inserted)
    }

    fn contains_visited(&self, seal_ref: &SealId) -> arkret_wire::Result<bool> {
        Ok(self.visited.contains(seal_ref))
    }

    fn visited_count(&self) -> arkret_wire::Result<u64> {
        Ok(self.visited.len() as u64)
    }

    fn record_topological(&mut self, seal_ref: &SealId) -> arkret_wire::Result<()> {
        self.topological.push(seal_ref.clone());
        self.charge_row()
    }

    fn topological_len(&self) -> arkret_wire::Result<u64> {
        Ok(self.topological.len() as u64)
    }

    fn topological_at(&self, index: u64) -> arkret_wire::Result<Option<SealId>> {
        let index = usize::try_from(index)
            .map_err(|_| traversal_error(DirectTraversalError::BoundsExceeded))?;
        Ok(self.topological.get(index).cloned())
    }

    fn for_each_topological(
        &self,
        visit: &mut dyn FnMut(&SealId) -> arkret_wire::Result<()>,
    ) -> arkret_wire::Result<()> {
        for seal_ref in &self.topological {
            visit(seal_ref)?;
        }
        Ok(())
    }

    fn written_row_count(&self) -> arkret_wire::Result<u64> {
        Ok(self.written_rows)
    }
}

/// Lazy access to the responder's offered Seal graph.
///
/// The verifier pulls one descriptor at a time by `SealId`; it never asks for
/// the whole set, and `for_each_offered_seal_ref` is a stream so the
/// every-and-only check does not materialize the offered closure either.
pub trait DirectCutGraphSource {
    /// Number of distinct Seal descriptors offered for this cut. Used as the
    /// pre-write budget input, so an honest implementation answers without
    /// staging anything.
    fn offered_seal_count(&self) -> arkret_wire::Result<u64>;

    fn for_each_offered_seal_ref(
        &self,
        visit: &mut dyn FnMut(&SealId) -> arkret_wire::Result<()>,
    ) -> arkret_wire::Result<()>;

    /// Signed `predecessor_ref` of one offered Seal. The outer `Option` means
    /// the responder omitted the descriptor; the inner `Option` is genesis.
    fn predecessor_ref(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Option<SealId>>>;
}

/// Lazy access to the complete signed objects the replay needs.
///
/// `control_event` MUST return the exact canonical Event bytes the Seal pinned
/// when it was accepted. Returning a different variant that hashes to another
/// digest is rejected by the replay. A resolver response that maps one claimed
/// digest to multiple distinct Event values MUST be rejected before this
/// single-value source is constructed; [`DirectCutMaterial::new`] is the
/// reference admission boundary. Returning a variant chosen by a current
/// resolver rather than by the accepted Seal is what
/// `history-visibility.md` §5 forbids.
pub trait DirectCutObjectSource: DirectCutGraphSource {
    fn seal(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Seal>>;

    fn control_event(&self, event_digest: &Hash) -> arkret_wire::Result<Option<Event>>;
}

/// In-memory reference graph source over signed predecessor descriptors.
#[derive(Clone, Debug, Default)]
pub struct DirectCutDescriptorIndex {
    descriptors: BTreeMap<SealId, Option<SealId>>,
}

impl DirectCutDescriptorIndex {
    pub fn new(
        descriptors: impl IntoIterator<Item = SealPredecessorDescriptor>,
    ) -> arkret_wire::Result<Self> {
        let mut index = BTreeMap::new();
        for descriptor in descriptors {
            if index
                .insert(descriptor.seal_ref, descriptor.predecessor_ref)
                .is_some()
            {
                return Err(traversal_error(DirectTraversalError::DuplicateDescriptor));
            }
        }
        Ok(Self { descriptors: index })
    }
}

impl DirectCutGraphSource for DirectCutDescriptorIndex {
    fn offered_seal_count(&self) -> arkret_wire::Result<u64> {
        Ok(self.descriptors.len() as u64)
    }

    fn for_each_offered_seal_ref(
        &self,
        visit: &mut dyn FnMut(&SealId) -> arkret_wire::Result<()>,
    ) -> arkret_wire::Result<()> {
        for seal_ref in self.descriptors.keys() {
            visit(seal_ref)?;
        }
        Ok(())
    }

    fn predecessor_ref(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Option<SealId>>> {
        Ok(self.descriptors.get(seal_ref).cloned())
    }
}

/// In-memory reference object source used by SDK vectors and small cuts.
#[derive(Clone, Debug, Default)]
pub struct DirectCutMaterial {
    seals: BTreeMap<SealId, Seal>,
    events: BTreeMap<Hash, Event>,
}

impl DirectCutMaterial {
    pub fn new(
        seals: impl IntoIterator<Item = Seal>,
        events: impl IntoIterator<Item = (Hash, Event)>,
    ) -> arkret_wire::Result<Self> {
        let mut material = Self::default();
        for seal in seals {
            if material.seals.insert(seal.id.clone(), seal).is_some() {
                return Err(traversal_error(DirectTraversalError::DuplicateDescriptor));
            }
        }
        for (digest, event) in events {
            if let Some(previous) = material.events.insert(digest, event.clone())
                && previous != event
            {
                return Err(WireError::Protocol(
                    "ambiguous direct traversal material carries two Event variants for one claimed digest"
                        .to_owned(),
                ));
            }
        }
        Ok(material)
    }
}

impl DirectCutGraphSource for DirectCutMaterial {
    fn offered_seal_count(&self) -> arkret_wire::Result<u64> {
        Ok(self.seals.len() as u64)
    }

    fn for_each_offered_seal_ref(
        &self,
        visit: &mut dyn FnMut(&SealId) -> arkret_wire::Result<()>,
    ) -> arkret_wire::Result<()> {
        for seal_ref in self.seals.keys() {
            visit(seal_ref)?;
        }
        Ok(())
    }

    fn predecessor_ref(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Option<SealId>>> {
        Ok(self
            .seals
            .get(seal_ref)
            .map(|seal| seal.predecessor_ref.clone()))
    }
}

impl DirectCutObjectSource for DirectCutMaterial {
    fn seal(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Seal>> {
        Ok(self.seals.get(seal_ref).cloned())
    }

    fn control_event(&self, event_digest: &Hash) -> arkret_wire::Result<Option<Event>> {
        Ok(self.events.get(event_digest).cloned())
    }
}

/// Counters proving one discovery pass closed the interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectCutDiscovery {
    pub visited_seal_count: u64,
    pub consumed_base_leaf_count: u64,
    pub topological_len: u64,
}

/// Result of one discovery pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectCutOutcome {
    Closed(DirectCutDiscovery),
    Rejected(BTreeSet<DirectTraversalError>),
}

impl DirectCutOutcome {
    /// Canonical machine vocabulary for a rejection, empty when closed.
    pub fn error_names(&self) -> BTreeSet<&'static str> {
        match self {
            Self::Closed(_) => BTreeSet::new(),
            Self::Rejected(errors) => errors.iter().map(|error| error.as_str()).collect(),
        }
    }

    pub fn into_result(self) -> arkret_wire::Result<DirectCutDiscovery> {
        match self {
            Self::Closed(discovery) => Ok(discovery),
            Self::Rejected(errors) => Err(WireError::Protocol(format!(
                "direct traversal cut is not closed: {}",
                errors
                    .iter()
                    .map(|error| error.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }
}

fn traversal_error(error: DirectTraversalError) -> WireError {
    WireError::Protocol(format!("direct traversal rejected: {}", error.as_str()))
}

/// Walk backwards from `target_basis` to `trusted_history_base_basis`.
///
/// Termination follows `history-visibility.md` §5 exactly: every direct
/// predecessor of an in-interval Seal must either stay inside the interval or be
/// literally one of the base leaves; every base leaf must be consumed by at
/// least one target-rooted path; the target must dominate every
/// `trusted_current_basis` leaf; and hidden predecessors, unreachable concurrent
/// branches and surplus descriptors all fail closed.
///
/// The journal receives the complete base -> target topological order as a side
/// effect, so the replay phase never re-derives it.
pub fn discover_direct_cut(
    request: &DirectCutRequest,
    source: &dyn DirectCutGraphSource,
    journal: &mut dyn DirectTraversalJournal,
) -> arkret_wire::Result<DirectCutOutcome> {
    request.validate()?;
    journal.reset()?;
    if source.offered_seal_count()? > MAX_DIRECT_TRAVERSAL_SEALS {
        return Ok(DirectCutOutcome::Rejected(BTreeSet::from([
            DirectTraversalError::BoundsExceeded,
        ])));
    }

    let base = request
        .trusted_history_base_basis
        .leaves
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut errors = BTreeSet::new();
    let mut consumed_base = BTreeSet::new();

    for leaf in request.target_basis.leaves.iter().rev() {
        journal.push_work(DirectTraversalWorkItem {
            seal_ref: leaf.clone(),
            expanded: false,
        })?;
    }

    while let Some(item) = journal.pop_work()? {
        if item.expanded {
            journal.record_topological(&item.seal_ref)?;
            continue;
        }
        if !journal.mark_visited(&item.seal_ref)? {
            continue;
        }
        if journal.visited_count()? > MAX_DIRECT_TRAVERSAL_SEALS {
            errors.insert(DirectTraversalError::BoundsExceeded);
            break;
        }
        let Some(predecessor_ref) = source.predecessor_ref(&item.seal_ref)? else {
            errors.insert(DirectTraversalError::DependencyMissing);
            continue;
        };
        if base.contains(&item.seal_ref) {
            consumed_base.insert(item.seal_ref.clone());
            journal.record_topological(&item.seal_ref)?;
            continue;
        }
        if predecessor_ref.is_none() {
            errors.insert(DirectTraversalError::IntervalStopsBeforeBase);
        }
        journal.push_work(DirectTraversalWorkItem {
            seal_ref: item.seal_ref,
            expanded: true,
        })?;
        for predecessor in predecessor_ref.iter() {
            if !journal.contains_visited(predecessor)? {
                journal.push_work(DirectTraversalWorkItem {
                    seal_ref: predecessor.clone(),
                    expanded: false,
                })?;
            }
        }
    }

    for leaf in &request.trusted_current_basis.leaves {
        if !journal.contains_visited(leaf)? {
            errors.insert(DirectTraversalError::TrustedCurrentNotDominated);
            break;
        }
    }
    if consumed_base != base {
        errors.insert(DirectTraversalError::BaseLeafNotConsumed);
    }

    let mut offered = 0_u64;
    let mut surplus = false;
    source.for_each_offered_seal_ref(&mut |seal_ref| {
        offered = offered.saturating_add(1);
        if !journal.contains_visited(seal_ref)? {
            surplus = true;
        }
        Ok(())
    })?;
    if surplus || offered != journal.visited_count()? {
        errors.insert(DirectTraversalError::SurplusDescriptor);
    }

    if errors.is_empty() {
        Ok(DirectCutOutcome::Closed(DirectCutDiscovery {
            visited_seal_count: journal.visited_count()?,
            consumed_base_leaf_count: consumed_base.len() as u64,
            topological_len: journal.topological_len()?,
        }))
    } else {
        Ok(DirectCutOutcome::Rejected(errors))
    }
}

/// Reducer-derived truth of one verified direct-traversal cut.
///
/// The cut's Seals and Events are deliberately absent: they were streamed
/// through the reducer and are recoverable from the caller's own object store.
/// What survives is the replayed state at the pinned target, which is what
/// winning MLS transition, join/incarnation, RHRK tuple and current history
/// access are all derived from.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedDirectTraversalCut {
    pub realm_id: RealmId,
    pub target_basis: SealBasis,
    pub live_digest_suite: DigestSuite,
    pub discovery: DirectCutDiscovery,
    pub effective_state: BTreeMap<CellRef, ResolvedCellState>,
}

impl Eq for VerifiedDirectTraversalCut {}

/// Lazy Event lookup for one Seal's replay step.
///
/// Only the Seal currently being applied has its `delta[]` Events resident; every
/// older covered Event is answered by the reducer's own Control Event store,
/// which already froze its exact accepted bytes and digest suite.
struct DeltaEventLookup<'a> {
    delta: &'a BTreeMap<Hash, Event>,
    store: &'a MemoryControlEventStore,
}

/// Observer invoked after one Seal and its exact delta have been replayed.
pub type DirectTraversalSealObserver<'a> =
    dyn FnMut(&Seal, &BTreeMap<Hash, Event>) -> arkret_wire::Result<()> + 'a;

#[async_trait]
impl ReplayEventLookup for DeltaEventLookup<'_> {
    async fn event(&self, digest: &Hash) -> arkret_wire::Result<Option<Event>> {
        if let Some(event) = self.delta.get(digest) {
            return Ok(Some(event.clone()));
        }
        self.store
            .get(digest)
            .await
            .map_err(|error| WireError::Protocol(error.to_string()))
    }
}

/// Discover and replay one complete `target -> base` direct-traversal cut.
///
/// Discovery is streamed through `journal`; replay then walks the durable
/// topological log base-first, pulling each Seal and its `delta[]` Events from
/// `source` and applying them through the standard `apply_seal` reducer. The
/// input buffer contains one Seal and delta; the current reducer stores still
/// retain the accepted history and do not provide a history-independent memory
/// bound.
///
/// `on_replayed_seal` sees every accepted Seal together with its exact resolved
/// delta Events, so a caller can project the bounded slice it needs (winning MLS
/// transitions, membership incarnations, the RHRK tuple) without this function
/// accumulating a second raw cut in the observer.
#[allow(clippy::too_many_arguments)]
pub async fn verify_direct_traversal_cut_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    request: &DirectCutRequest,
    source: &dyn DirectCutObjectSource,
    journal: &mut dyn DirectTraversalJournal,
    dependencies: &[GovernanceDependency],
    registry: &dyn CellStateRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
    on_replayed_seal: &mut DirectTraversalSealObserver<'_>,
) -> arkret_wire::Result<VerifiedDirectTraversalCut>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> crate::mls_governance_proof::VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(
            &Event,
            DigestSuite,
            &BTreeMap<CellRef, ResolvedCellState>,
        ) -> Result<crate::ControlProjection, String>
        + Copy,
{
    let discovery = discover_direct_cut(request, source, journal)?.into_result()?;
    if discovery.topological_len != discovery.visited_seal_count {
        return Err(WireError::Protocol(
            "direct traversal topological log is not every-and-only the visited cut".to_owned(),
        ));
    }
    GovernanceDependencyResolveOutcome {
        items: dependencies.to_vec(),
        missing_selectors: Vec::new(),
    }
    .validate()?;

    let event_store = MemoryControlEventStore::default();
    let seal_store = MemorySealStore::default();
    let cell_store = MemoryCellStore::default();
    let mut live_suites = BTreeMap::new();
    let mut replayed = 0_u64;

    while let Some(seal_ref) = journal.topological_at(replayed)? {
        let seal = source
            .seal(&seal_ref)?
            .ok_or_else(|| traversal_error(DirectTraversalError::DependencyMissing))?;
        if seal.id != seal_ref {
            return Err(WireError::Protocol(
                "direct traversal Seal does not match the requested seal_ref".to_owned(),
            ));
        }
        if seal.realm_id != request.realm_id {
            return Err(WireError::Protocol(
                "direct traversal cut contains a cross-Realm Seal".to_owned(),
            ));
        }
        seal.validate_structural()?;
        let mut delta = BTreeMap::new();
        for digest in &seal.delta {
            let event = source
                .control_event(digest)?
                .ok_or_else(|| traversal_error(DirectTraversalError::DependencyMissing))?;
            if event.realm_id != request.realm_id {
                return Err(WireError::Protocol(
                    "direct traversal delta Control Move is cross-Realm".to_owned(),
                ));
            }
            if let Some(previous) = delta.insert(digest.clone(), event.clone())
                && previous != event
            {
                return Err(WireError::Protocol(
                    "direct traversal resolved two Event variants for one Seal delta digest"
                        .to_owned(),
                ));
            }
        }
        if delta.len() != seal.delta.len() {
            return Err(WireError::Protocol(
                "direct traversal Seal delta contains a duplicate Event digest".to_owned(),
            ));
        }
        let lookup = DeltaEventLookup {
            delta: &delta,
            store: &event_store,
        };
        replay_one_seal(
            &seal,
            &lookup,
            &event_store,
            &seal_store,
            &cell_store,
            dependencies,
            registry,
            verify_seal_signature,
            verify_event_proofs.clone(),
            verify_seal_dependencies,
            project_writes,
            &mut live_suites,
        )
        .await?;
        on_replayed_seal(&seal, &delta)?;
        replayed = replayed.saturating_add(1);
    }

    if replayed != discovery.visited_seal_count {
        return Err(WireError::Protocol(
            "direct traversal replay did not consume every discovered Seal".to_owned(),
        ));
    }
    let leaves = seal_store
        .confirmed_head(&request.realm_id)
        .await
        .map_err(|error| WireError::Protocol(error.to_string()))?
        .into_iter()
        .collect::<Vec<_>>();
    if leaves.iter().cloned().collect::<BTreeSet<_>>()
        != request
            .target_basis
            .leaves
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    {
        return Err(WireError::Protocol(
            "direct traversal replay does not end at the pinned target basis".to_owned(),
        ));
    }
    let effective_state = effective_state_at(
        &request.target_basis.leaves,
        &request.realm_id,
        &seal_store,
        &cell_store,
        registry,
    )
    .await
    .map_err(|error| WireError::Protocol(error.to_string()))?;

    Ok(VerifiedDirectTraversalCut {
        realm_id: request.realm_id.clone(),
        target_basis: request.target_basis.clone(),
        live_digest_suite: live_digest_suite_at_basis(&request.target_basis, &live_suites)?,
        discovery,
        effective_state,
    })
}

/// Follow the reducer-selected epoch value, never raw candidate counts.
/// Retained losing transitions are not authority. The target must come from
/// the registered epoch cell at the same already verified governance basis.
pub(crate) fn winning_mls_lineage<'a>(
    retained: &'a [Event],
    scope: &arkret_wire::HistoryEffectiveScope,
    transition_ref: &EventId,
    target_epoch: u64,
) -> arkret_wire::Result<Vec<&'a Event>> {
    let group_id = scope.canonical_mls_group_id()?;
    let mut events = BTreeMap::new();
    for event in retained {
        if event.realm_id != *scope.realm_id() {
            return Err(WireError::Protocol(
                "history cut contains a cross-Realm Event".to_owned(),
            ));
        }
        if let Some(previous) = events.insert(&event.event_id, event)
            && previous != event
        {
            return Err(WireError::Protocol(
                "retained Event identity has conflicting bytes".to_owned(),
            ));
        }
    }
    let mut current = transition_ref.clone();
    let mut expected_epoch = target_epoch;
    let mut lineage = Vec::new();
    loop {
        let event = events.remove(&current).ok_or_else(|| {
            WireError::Protocol(
                "winning MLS lineage is missing an Event or contains a cycle".to_owned(),
            )
        })?;
        lineage.push(event);
        match event.kind.as_str() {
            event_kind_str::MLS_COMMIT => {
                let commit: MlsCommitPayload = payload_of(event)?;
                if commit.mls_group_id() != group_id
                    || commit.next_epoch() != expected_epoch
                    || commit.base_epoch().checked_add(1) != Some(expected_epoch)
                    || commit.governance_binding().effective_scope()
                        != &arkret_wire::ScopeRef::from(scope.clone())
                {
                    return Err(WireError::Protocol(
                        "winning MLS lineage has inconsistent scope or epoch".to_owned(),
                    ));
                }
                current = EventId::new(commit.base_epoch_ref().to_owned())?;
                expected_epoch = commit.base_epoch();
            }
            event_kind_str::MLS_GENESIS
                if expected_epoch == 0
                    && event.payload.get("mls_group_id").and_then(Value::as_str)
                        == Some(group_id.as_str())
                    && event.payload.get("epoch").and_then(Value::as_u64) == Some(0) =>
            {
                lineage.reverse();
                return Ok(lineage);
            }
            _ => {
                return Err(WireError::Protocol(
                    "winning MLS lineage does not terminate in its Genesis".to_owned(),
                ));
            }
        }
    }
}

/// Derive the MLS phase of an already resolved membership from the same
/// verified cut. `None` means membership is ready but its lineage is not.
///
/// `zh/governance/history-visibility.md` §3 fixes exactly two sources of truth:
///
/// * the `next_epoch` of the winning Commit that consumes the `Add` proposal binding this exact
///   `target_authorization_incarnation`, and
/// * `0` for a Genesis initial member, which holds only when the same replay proves both the
///   founding membership incarnation and the Genesis initial leaf.
///
/// Nothing else is admissible. There is deliberately no variant keyed on
/// `joined_at`, `received_at` or the current epoch.
/// `genesis_incarnation` must come from the membership reducer at the winning
/// lineage's Genesis signed basis in these same stores. The public store
/// query constructs this input; it is never supplied by a remote assertion.
pub(crate) fn history_join_epoch_from_verified_membership(
    retained_control_events: &[Event],
    membership: &crate::history_authorization::VerifiedMembership,
    genesis_incarnation: Option<&AuthorizationIncarnation>,
    lineage: &[&Event],
) -> arkret_wire::Result<Option<u64>> {
    let group_id = membership.scope().canonical_mls_group_id()?;
    let (realm_ref, circle_ref) = match membership.incarnation() {
        AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref,
        } => (realm_membership_incarnation_ref, None),
        AuthorizationIncarnation::Circle {
            realm_membership_incarnation_ref,
            circle_membership_incarnation_ref,
        } => (
            realm_membership_incarnation_ref,
            Some(circle_membership_incarnation_ref),
        ),
    };
    if std::iter::once(realm_ref).chain(circle_ref).any(|id| {
        !retained_control_events
            .iter()
            .any(|event| &event.event_id == id)
    }) {
        return Err(WireError::Protocol(
            "verified authorization incarnation is absent from the retained cut".to_owned(),
        ));
    }
    let Some(genesis) = lineage.first() else {
        return Ok(None);
    };
    if genesis.actor_id == *membership.actor()
        && genesis_incarnation == Some(membership.incarnation())
    {
        return Ok(Some(0));
    }
    let mut adds = BTreeMap::<EventId, MlsProposalPayload>::new();
    for event in retained_control_events {
        if event.kind.as_str() == event_kind_str::MLS_PROPOSAL {
            let proposal: MlsProposalPayload = payload_of(event)?;
            if proposal.mls_group_id.as_str() == group_id
                && proposal.proposal_type == MlsProposalType::Add
                && proposal.target_actor_id.as_ref() == Some(membership.actor())
                && proposal.target_authorization_incarnation.as_ref()
                    == Some(membership.incarnation())
            {
                adds.insert(event.event_id.clone(), proposal);
            }
        }
    }
    for event in lineage.iter().skip(1) {
        let commit: MlsCommitPayload = payload_of(event)?;
        if commit.proposal_refs().iter().any(|id| {
            adds.get(id)
                .is_some_and(|proposal| proposal.base_epoch == commit.base_epoch())
        }) {
            return Ok(Some(commit.next_epoch()));
        }
    }
    Ok(None)
}

fn payload_of<T: serde::de::DeserializeOwned>(event: &Event) -> arkret_wire::Result<T> {
    Ok(serde_json::from_value(Value::Object(
        event.payload.clone().into_iter().collect(),
    ))?)
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::mls_envelopes::MlsCommitEnvelope;
    use arkret_models_crypto::mls_payloads::MlsGovernanceBindingPayload;
    use arkret_wire::event_envelope::ScopeRef;
    use arkret_wire::{
        AccountId, ActorId, ContentScheme, DidCoreId, DurabilityPolicy, Hlc, MlsGroupId,
    };
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN";
    const GROUP: &str = "YWs6cmVhbG06QVl3LVBIV0lPVHVaaG0tRWVuWngtY0NiT3ppQzhwTkNyaDEwb1JmcWlFbU4";

    fn seal_id(marker: &str) -> SealId {
        SealId::new(format!("ak:seal:sha256:{}", marker.repeat(32)))
            .expect("content-addressed Seal id")
    }

    fn descriptor(seal: &SealId, predecessors: &[&SealId]) -> SealPredecessorDescriptor {
        assert!(predecessors.len() <= 1);
        SealPredecessorDescriptor {
            seal_ref: seal.clone(),
            predecessor_ref: predecessors.first().map(|value| (*value).clone()),
        }
    }

    fn basis(leaves: &[&SealId]) -> SealBasis {
        let mut leaves = leaves
            .iter()
            .map(|value| (*value).clone())
            .collect::<Vec<_>>();
        leaves.sort();
        let basis = SealBasis { leaves };
        basis
            .validate_protocol_bounds()
            .expect("canonical antichain");
        basis
    }

    /// Two independent bootstrap roots, each with one intermediate and one
    /// target leaf; the current antichain sits on the intermediates. This is the
    /// exact shape of `direct_traversal_kat.direct_cut`.
    struct FixtureShapedCut {
        base_left: SealId,
        base_right: SealId,
        mid_left: SealId,
        mid_right: SealId,
        target_left: SealId,
        target_right: SealId,
    }

    impl FixtureShapedCut {
        fn new() -> Self {
            Self {
                base_left: seal_id("11"),
                base_right: seal_id("22"),
                mid_left: seal_id("33"),
                mid_right: seal_id("44"),
                target_left: seal_id("55"),
                target_right: seal_id("66"),
            }
        }

        fn descriptors(&self) -> Vec<SealPredecessorDescriptor> {
            vec![
                descriptor(&self.base_left, &[]),
                descriptor(&self.base_right, &[]),
                descriptor(&self.mid_left, &[&self.base_left]),
                descriptor(&self.mid_right, &[&self.base_right]),
                descriptor(&self.target_left, &[&self.mid_left]),
                descriptor(&self.target_right, &[&self.mid_right]),
            ]
        }

        fn request(&self) -> DirectCutRequest {
            DirectCutRequest {
                realm_id: RealmId::new(REALM).expect("Realm id"),
                trusted_history_base_basis: basis(&[&self.base_left, &self.base_right]),
                trusted_current_basis: basis(&[&self.mid_left, &self.mid_right]),
                target_basis: basis(&[&self.target_left, &self.target_right]),
            }
        }
    }

    fn discover(
        request: &DirectCutRequest,
        descriptors: Vec<SealPredecessorDescriptor>,
    ) -> (DirectCutOutcome, BoundedDirectTraversalJournal) {
        let source = DirectCutDescriptorIndex::new(descriptors).expect("distinct descriptors");
        let mut journal = BoundedDirectTraversalJournal::default();
        let outcome = discover_direct_cut(request, &source, &mut journal).expect("traversal runs");
        (outcome, journal)
    }

    #[tokio::test]
    async fn closed_cut_emits_a_base_first_topological_order() {
        let cut = FixtureShapedCut::new();
        let (outcome, journal) = discover(&cut.request(), cut.descriptors());
        assert_eq!(
            outcome,
            DirectCutOutcome::Closed(DirectCutDiscovery {
                visited_seal_count: 6,
                consumed_base_leaf_count: 2,
                topological_len: 6,
            })
        );
        let mut order = Vec::new();
        journal
            .for_each_topological(&mut |seal_ref| {
                order.push(seal_ref.clone());
                Ok(())
            })
            .expect("topological log streams");
        let position = |seal: &SealId| {
            order
                .iter()
                .position(|candidate| candidate == seal)
                .expect("every discovered Seal is logged")
        };
        assert!(position(&cut.base_left) < position(&cut.mid_left));
        assert!(position(&cut.mid_left) < position(&cut.target_left));
        assert!(position(&cut.base_right) < position(&cut.mid_right));
        assert!(position(&cut.mid_right) < position(&cut.target_right));
    }

    #[tokio::test]
    async fn a_hidden_predecessor_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut descriptors = cut.descriptors();
        descriptors.retain(|item| item.seal_ref != cut.mid_left);
        let (outcome, _) = discover(&cut.request(), descriptors);
        assert_eq!(
            outcome.error_names(),
            BTreeSet::from([
                "base_leaf_not_consumed",
                "dependency_missing",
                "surplus_descriptor",
            ])
        );
    }

    #[tokio::test]
    async fn an_undominated_trusted_current_leaf_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut request = cut.request();
        request.trusted_current_basis = basis(&[&seal_id("ee")]);
        let (outcome, _) = discover(&request, cut.descriptors());
        assert_eq!(
            outcome.error_names(),
            BTreeSet::from(["trusted_current_not_dominated"])
        );
    }

    #[tokio::test]
    async fn a_branch_that_stops_before_the_base_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut descriptors = cut.descriptors();
        descriptors.retain(|item| item.seal_ref != cut.mid_left);
        for item in &mut descriptors {
            if item.predecessor_ref.as_ref() == Some(&cut.mid_left) {
                item.predecessor_ref = None;
            }
        }
        let (outcome, _) = discover(&cut.request(), descriptors);
        assert_eq!(
            outcome.error_names(),
            BTreeSet::from([
                "base_leaf_not_consumed",
                "interval_stops_before_base",
                "surplus_descriptor",
                "trusted_current_not_dominated",
            ])
        );
    }

    #[tokio::test]
    async fn an_unconsumed_base_leaf_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut request = cut.request();
        request.trusted_history_base_basis =
            basis(&[&cut.base_left, &cut.base_right, &seal_id("ee")]);
        let (outcome, _) = discover(&request, cut.descriptors());
        assert_eq!(
            outcome.error_names(),
            BTreeSet::from(["base_leaf_not_consumed"])
        );
    }

    #[tokio::test]
    async fn a_surplus_descriptor_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut descriptors = cut.descriptors();
        descriptors.push(descriptor(&seal_id("ee"), &[]));
        let (outcome, _) = discover(&cut.request(), descriptors);
        assert_eq!(
            outcome.error_names(),
            BTreeSet::from(["surplus_descriptor"])
        );
    }

    #[tokio::test]
    async fn a_duplicate_descriptor_is_refused_by_the_source() {
        let cut = FixtureShapedCut::new();
        let mut descriptors = cut.descriptors();
        descriptors.push(descriptor(&cut.base_left, &[]));
        let error = DirectCutDescriptorIndex::new(descriptors)
            .expect_err("a repeated seal_ref is not a cut descriptor set");
        assert!(
            error.to_string().contains("duplicate_descriptor"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn ambiguous_event_variants_are_refused_before_replay_material_exists() {
        let claimed = Hash::new(format!("sha256:{}", "a7".repeat(32))).expect("claimed digest");
        let variant_a = event(
            arkret_wire::EventKind::PolicySet.as_str(),
            7,
            json!({"variant": "a"}),
            "ak:event:AWYr1ucW0vOccjnC8XMFGQK8PjKzaha_YpYb8B0uDY_y",
        );
        let mut variant_b = variant_a.clone();
        variant_b.payload.insert("variant".to_owned(), json!("b"));
        let error = DirectCutMaterial::new(
            Vec::<Seal>::new(),
            [(claimed.clone(), variant_a), (claimed, variant_b)],
        )
        .expect_err("one claimed digest cannot select between two Event preimages");
        assert!(
            error
                .to_string()
                .contains("ambiguous direct traversal material"),
            "{error}"
        );
    }

    /// A responder that declares more Seals than the v1 ceiling is refused
    /// before the journal writes its first row.
    struct OverBudgetSource;

    impl DirectCutGraphSource for OverBudgetSource {
        fn offered_seal_count(&self) -> arkret_wire::Result<u64> {
            Ok(MAX_DIRECT_TRAVERSAL_SEALS + 1)
        }

        fn for_each_offered_seal_ref(
            &self,
            _visit: &mut dyn FnMut(&SealId) -> arkret_wire::Result<()>,
        ) -> arkret_wire::Result<()> {
            panic!("an over-budget cut must be refused before enumeration");
        }

        fn predecessor_ref(
            &self,
            _seal_ref: &SealId,
        ) -> arkret_wire::Result<Option<Option<SealId>>> {
            panic!("an over-budget cut must be refused before any descriptor fetch");
        }
    }

    #[tokio::test]
    async fn an_over_budget_cut_is_refused_before_the_first_journal_row() {
        let cut = FixtureShapedCut::new();
        let mut journal = BoundedDirectTraversalJournal::default();
        let outcome = discover_direct_cut(&cut.request(), &OverBudgetSource, &mut journal)
            .expect("the budget check is not an I/O failure");
        assert_eq!(outcome.error_names(), BTreeSet::from(["bounds_exceeded"]));
        assert_eq!(journal.written_row_count().expect("counter"), 0);
        assert_eq!(journal.visited_count().expect("counter"), 0);
        assert_eq!(journal.topological_len().expect("counter"), 0);
    }

    fn actor() -> DidCoreId {
        DidCoreId::new("ak:did_core:key:z6MkfixtureMember").expect("actor id")
    }

    fn event(kind: &str, seq: u64, payload: Value, event_id: &str) -> Event {
        event_by(actor(), kind, seq, payload, event_id)
    }

    fn event_by(
        actor_id: DidCoreId,
        kind: &str,
        seq: u64,
        payload: Value,
        event_id: &str,
    ) -> Event {
        let mut event = arkret_wire::test_support::raw_event(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new(REALM).expect("Realm id"),
            },
            actor_id.clone(),
            actor_id,
            seq,
            Hlc::new(format!("01970e589d21-{seq:04}-a13f9c2e")).expect("hlc"),
            payload,
        )
        .expect("raw Event");
        event.event_id = EventId::new(event_id).expect("event id");
        event
    }

    fn membership_join(event_id: &str) -> Event {
        event(
            event_kind_str::MEMBER_STATE,
            1,
            json!({
                "member_id": ActorId::account(AccountId::new(actor(), actor())),
                "membership": "join"
            }),
            event_id,
        )
    }

    // The creator coordinate is the Genesis Event's own actor_id, not a
    // payload field: the closed mls_genesis_payload schema declares none.
    fn genesis(event_id: &str, creator: &DidCoreId) -> Event {
        event_by(
            creator.clone(),
            event_kind_str::MLS_GENESIS,
            2,
            json!({
                "mls_group_id": GROUP,
                "epoch": 0
            }),
            event_id,
        )
    }

    fn governance_binding(previous_epoch: u64, next_epoch: u64) -> MlsGovernanceBindingPayload {
        MlsGovernanceBindingPayload::realm(
            RealmId::new(REALM).expect("Realm id"),
            previous_epoch,
            next_epoch,
            Hash::new(format!("sha256:{}", "ab".repeat(32))).expect("frontier digest"),
            ContentScheme::MlsExporterAeadV1,
            Some(DurabilityPolicy::None),
            "ak.profile.mls_governance.v1",
            "ak.profile.reducer.v1",
        )
        .expect("governance binding")
    }

    fn add_proposal(event_id: &str, incarnation: &EventId) -> Event {
        let proposal_bytes = b"direct-traversal-add-proposal";
        let payload = MlsProposalPayload {
            mls_group_id: MlsGroupId::new(GROUP).expect("group id"),
            base_epoch: 0,
            proposal_type: MlsProposalType::Add,
            proposal_bytes_b64: arkret_canonical::base64url_encode(proposal_bytes),
            proposal_digest: Hash::new(arkret_canonical::sha256_digest(proposal_bytes))
                .expect("proposal digest"),
            target_actor_id: Some(ActorId::account(AccountId::new(actor(), actor()))),
            target_authorization_incarnation: Some(AuthorizationIncarnation::Realm {
                realm_membership_incarnation_ref: incarnation.clone(),
            }),
            governance_binding: governance_binding(0, 1),
        };
        event(
            event_kind_str::MLS_PROPOSAL,
            3,
            serde_json::to_value(payload).expect("proposal payload"),
            event_id,
        )
    }

    fn commit(event_id: &str, base_epoch_ref: &EventId, proposal_refs: Vec<EventId>) -> Event {
        commit_at(event_id, base_epoch_ref, proposal_refs, 0)
    }

    fn commit_at(
        event_id: &str,
        base_epoch_ref: &EventId,
        proposal_refs: Vec<EventId>,
        base_epoch: u64,
    ) -> Event {
        let commit_bytes = b"arkret-test-commit";
        let payload = MlsCommitPayload::new(
            base_epoch_ref.as_str(),
            proposal_refs,
            &MlsCommitEnvelope {
                group_id: GROUP.to_owned(),
                epoch: base_epoch + 1,
                commit: arkret_canonical::base64url_encode(commit_bytes),
                commit_digest: Hash::new(arkret_canonical::sha256_digest(commit_bytes))
                    .expect("commit digest"),
                ratchet_tree: None,
            },
            governance_binding(base_epoch, base_epoch + 1),
        )
        .expect("commit payload");
        event(
            event_kind_str::MLS_COMMIT,
            4,
            serde_json::to_value(payload).expect("commit payload"),
            event_id,
        )
    }

    fn subject(incarnation: &EventId) -> crate::history_authorization::VerifiedMembership {
        crate::history_authorization::VerifiedMembership {
            scope: arkret_wire::HistoryEffectiveScope::Realm {
                realm_id: RealmId::new(REALM).unwrap(),
            },
            actor: ActorId::account(AccountId::new(actor(), actor())),
            incarnation: AuthorizationIncarnation::Realm {
                realm_membership_incarnation_ref: incarnation.clone(),
            },
        }
    }

    fn join_epoch_at(
        retained: &[Event],
        membership: &crate::history_authorization::VerifiedMembership,
        genesis_incarnation: Option<&AuthorizationIncarnation>,
        transition_ref: &str,
        epoch: u64,
    ) -> arkret_wire::Result<Option<u64>> {
        let lineage = winning_mls_lineage(
            retained,
            membership.scope(),
            &EventId::new(transition_ref)?,
            epoch,
        )?;
        history_join_epoch_from_verified_membership(
            retained,
            membership,
            genesis_incarnation,
            &lineage,
        )
    }

    const INCARNATION_REF: &str = "ak:event:AWYr1ucW0vOccjnC8XMFGQK8PjKzaha_YpYb8B0uDY_y";
    const GENESIS_REF: &str = "ak:event:AZc5yUQiAVSI3hquJ6vb24B9nBqhiONzxJK6xPKc-IQ9";
    const ADD_REF: &str = "ak:event:AbNAprqpf8plo9xcY8bDOmf3mEUhUCZbN63erkPaxN_8";
    const COMMIT_REF: &str = "ak:event:ARrXzX07X_prHPMAeOGPMrI4_sUFneJW2aYSvHN_-9aQ";

    #[tokio::test]
    async fn join_epoch_is_the_winning_commit_that_consumes_the_exact_add() {
        let incarnation = EventId::new(INCARNATION_REF).expect("incarnation ref");
        let genesis_ref = EventId::new(GENESIS_REF).expect("genesis ref");
        let founder = DidCoreId::new("ak:did_core:key:z6MkfixtureFounder").expect("founder");
        let retained = vec![
            membership_join(INCARNATION_REF),
            genesis(GENESIS_REF, &founder),
            add_proposal(ADD_REF, &incarnation),
            commit(
                COMMIT_REF,
                &genesis_ref,
                vec![EventId::new(ADD_REF).expect("add ref")],
            ),
        ];
        assert_eq!(
            join_epoch_at(&retained, &subject(&incarnation), None, COMMIT_REF, 1)
                .expect("join epoch"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_genesis_initial_leaf_joins_at_epoch_zero() {
        let incarnation = EventId::new(INCARNATION_REF).expect("incarnation ref");
        let retained = vec![
            membership_join(INCARNATION_REF),
            genesis(GENESIS_REF, &actor()),
        ];
        assert_eq!(
            join_epoch_at(
                &retained,
                &subject(&incarnation),
                Some(subject(&incarnation).incarnation()),
                GENESIS_REF,
                0
            )
            .expect("join epoch"),
            Some(0)
        );
    }

    #[test]
    fn genesis_membership_uses_the_historical_reducer_not_producer_ordering() {
        let incarnation = EventId::new(INCARNATION_REF).unwrap();
        let member = subject(&incarnation);
        let admin = DidCoreId::new("ak:did_core:key:z6MkfixtureAdmin").unwrap();
        let mut join = membership_join(INCARNATION_REF);
        join.actor_id = ActorId::account(AccountId::new(admin.clone(), admin));
        join.actor_seq = 100;
        let retained = vec![join, genesis(GENESIS_REF, &actor())];
        assert_eq!(
            join_epoch_at(
                &retained,
                &member,
                Some(member.incarnation()),
                GENESIS_REF,
                0
            )
            .unwrap(),
            Some(0),
        );
        let old_member = subject(&EventId::new(ADD_REF).unwrap());
        assert_eq!(
            join_epoch_at(
                &retained,
                &member,
                Some(old_member.incarnation()),
                GENESIS_REF,
                0
            )
            .unwrap(),
            None,
        );
    }

    #[test]
    fn verified_membership_producer_shape_does_not_redefine_the_join() {
        let incarnation = EventId::new(INCARNATION_REF).unwrap();
        let genesis_ref = EventId::new(GENESIS_REF).unwrap();
        let founder = DidCoreId::new("ak:did_core:key:z6MkfixtureFounder").unwrap();
        let retained = vec![
            event(event_kind_str::INVITE_ACCEPT, 1, json!({}), INCARNATION_REF),
            genesis(GENESIS_REF, &founder),
            add_proposal(ADD_REF, &incarnation),
            commit(
                COMMIT_REF,
                &genesis_ref,
                vec![EventId::new(ADD_REF).unwrap()],
            ),
        ];
        assert_eq!(
            join_epoch_at(&retained, &subject(&incarnation), None, COMMIT_REF, 1).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn lineage_uses_the_reducer_selected_successor_and_deduplicates_identity() {
        let incarnation = EventId::new(INCARNATION_REF).unwrap();
        let genesis_ref = EventId::new(GENESIS_REF).unwrap();
        let founder = DidCoreId::new("ak:did_core:key:z6MkfixtureFounder").unwrap();
        let accepted_commit = commit(
            COMMIT_REF,
            &genesis_ref,
            vec![EventId::new(ADD_REF).unwrap()],
        );
        let mut retained = vec![
            membership_join(INCARNATION_REF),
            genesis(GENESIS_REF, &founder),
            add_proposal(ADD_REF, &incarnation),
            accepted_commit.clone(),
            accepted_commit,
        ];
        assert_eq!(
            join_epoch_at(&retained, &subject(&incarnation), None, COMMIT_REF, 1).unwrap(),
            Some(1)
        );
        retained.push(retained[1].clone());
        assert_eq!(
            join_epoch_at(&retained, &subject(&incarnation), None, COMMIT_REF, 1).unwrap(),
            Some(1)
        );
        retained.push(commit(
            "ak:event:AaDhdv-ZXFF_BFoRFd0wDaCk_iEjsbNYRgnubpgUwTGC",
            &genesis_ref,
            Vec::new(),
        ));
        assert_eq!(
            join_epoch_at(&retained, &subject(&incarnation), None, COMMIT_REF, 1).unwrap(),
            Some(1),
            "a retained losing Commit must not override the reducer-selected recovered lineage"
        );
        assert_eq!(
            join_epoch_at(
                &retained,
                &subject(&incarnation),
                None,
                "ak:event:AaDhdv-ZXFF_BFoRFd0wDaCk_iEjsbNYRgnubpgUwTGC",
                1
            )
            .unwrap(),
            None,
            "an Add consumed only on the losing lineage must not grant history access"
        );
        assert!(join_epoch_at(&retained, &subject(&incarnation), None, COMMIT_REF, 2).is_err());
        let missing = retained
            .iter()
            .filter(|event| event.event_id != genesis_ref)
            .cloned()
            .collect::<Vec<_>>();
        assert!(join_epoch_at(&missing, &subject(&incarnation), None, COMMIT_REF, 1).is_err());
    }

    #[tokio::test]
    async fn device_adds_preserve_the_principal_join_floor() {
        let incarnation = EventId::new(INCARNATION_REF).unwrap();
        let genesis_ref = EventId::new(GENESIS_REF).unwrap();
        let second_add_ref = "ak:event:ASmikVTqZVHXrc7W_v34KTlnAXhVdm_rVRzstrRVXbL6";
        let founder = DidCoreId::new("ak:did_core:key:z6MkfixtureFounder").unwrap();
        let mut retained = vec![
            membership_join(INCARNATION_REF),
            genesis(GENESIS_REF, &founder),
            add_proposal(ADD_REF, &incarnation),
            add_proposal(second_add_ref, &incarnation),
            commit(
                COMMIT_REF,
                &genesis_ref,
                vec![
                    EventId::new(ADD_REF).unwrap(),
                    EventId::new(second_add_ref).unwrap(),
                ],
            ),
        ];
        assert_eq!(
            join_epoch_at(&retained, &subject(&incarnation), None, COMMIT_REF, 1).unwrap(),
            Some(1)
        );
        let later_add_ref = "ak:event:Aa5iC1k8qBhLViQvgYBaDDu8kW0AZcwnQyf3uwwBrOPh";
        let mut later_add = add_proposal(later_add_ref, &incarnation);
        later_add.payload.insert("base_epoch".into(), json!(1));
        later_add.payload.insert(
            "governance_binding".into(),
            serde_json::to_value(governance_binding(1, 2)).unwrap(),
        );
        retained.push(later_add);
        retained.push(commit_at(
            "ak:event:AaDhdv-ZXFF_BFoRFd0wDaCk_iEjsbNYRgnubpgUwTGC",
            &EventId::new(COMMIT_REF).unwrap(),
            vec![EventId::new(later_add_ref).unwrap()],
            1,
        ));
        assert_eq!(
            join_epoch_at(
                &retained,
                &subject(&incarnation),
                None,
                "ak:event:AaDhdv-ZXFF_BFoRFd0wDaCk_iEjsbNYRgnubpgUwTGC",
                2
            )
            .unwrap(),
            Some(1)
        );
        retained[1] = genesis(GENESIS_REF, &actor());
        assert_eq!(
            join_epoch_at(
                &retained,
                &subject(&incarnation),
                Some(subject(&incarnation).incarnation()),
                "ak:event:AaDhdv-ZXFF_BFoRFd0wDaCk_iEjsbNYRgnubpgUwTGC",
                2
            )
            .unwrap(),
            Some(0)
        );
        // A different incarnation at Genesis cannot regain the creator's floor,
        // irrespective of the current producer's author or sequence.
        let old_incarnation = subject(&EventId::new(ADD_REF).unwrap());
        assert_eq!(
            join_epoch_at(
                &retained,
                &subject(&incarnation),
                Some(old_incarnation.incarnation()),
                "ak:event:AaDhdv-ZXFF_BFoRFd0wDaCk_iEjsbNYRgnubpgUwTGC",
                2
            )
            .unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_non_founding_member_without_lineage_remains_member_ready() {
        let incarnation = EventId::new(INCARNATION_REF).expect("incarnation ref");
        let founder = DidCoreId::new("ak:did_core:key:z6MkfixtureFounder").expect("founder");
        let retained = vec![
            membership_join(INCARNATION_REF),
            genesis(GENESIS_REF, &founder),
        ];
        assert_eq!(
            join_epoch_at(&retained, &subject(&incarnation), None, GENESIS_REF, 0).unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn an_unproven_incarnation_fails_closed() {
        let incarnation = EventId::new(INCARNATION_REF).expect("incarnation ref");
        let retained = vec![genesis(GENESIS_REF, &actor())];
        let error = join_epoch_at(&retained, &subject(&incarnation), None, GENESIS_REF, 0)
            .expect_err("an unproven incarnation is not a join floor");
        assert!(
            error.to_string().contains("authorization incarnation"),
            "{error}"
        );
    }
}
