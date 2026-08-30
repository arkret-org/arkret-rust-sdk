//! Disk-backed direct Seal traversal for bulk/old history governance.
//!
//! `zh/governance/history-visibility.md` §5 splits governance verification in
//! two: the bounded near-current `group_security_frontier` query, and this
//! receipt-bound direct traversal for everything older. The traversal walks
//! backwards from the release service's `target_basis` along each Seal's
//! already-signed `predecessor_refs[]` until it reaches the caller-pinned,
//! independently verified predecessor-free `trusted_history_base_basis`, and
//! only then replays the discovered cut forwards through the ordinary
//! `apply_seal` reducer.
//!
//! Two things are deliberately separated here.
//!
//! * **Discovery** is streaming and durable. The work queue and visited set are a caller-supplied
//!   [`DirectTraversalJournal`] port ("SQLite 或等价 disk-backed work queue+visited set",
//!   `history-visibility.md` §5), so the verifier keeps only the Seal descriptor it is currently
//!   expanding plus a constant number of accumulators live. Nothing about the discovered cut is
//!   materialized in this crate's memory.
//! * **Replay** reuses the existing reducer through [`crate::apply_replayed_seal_in_context`].
//!   There is exactly one implementation of notary selection, delta admission, root recomputation
//!   and Bottom/recovery in the SDK, and direct traversal streams Seals into it one at a time
//!   rather than handing it a materialized `Vec<Seal>`.
//!
//! The two verifier phases are separately callable because they consume
//! different evidence: discovery needs only signed `(seal_ref,
//! predecessor_refs)` descriptors, while replay needs complete Seal and Event
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
    ActorId, CellRef, EventId, Hash, MlsGroupId, NotarySignerDescriptor, NotaryValue,
    ProjectedCellWrite, RealmId, Seal, SealBasis, SealId, SealSignature, WireError, event_kind_str,
};
use serde_json::Value;

use crate::lattice::CellState;
use crate::mls_governance_proof::{
    ReplayEventLookup, SealDependencyReplayContext, live_digest_suite_at_basis, replay_one_seal,
};
use crate::state::store::memory::{MemoryCellStore, MemoryControlEventStore, MemorySealStore};
use crate::{CellRegistry, ControlEventStore, SealStore, effective_state_at};

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
    pub predecessor_refs: Vec<SealId>,
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

    /// Signed `predecessor_refs[]` of one offered Seal, or `None` when the
    /// responder did not offer it.
    fn predecessor_refs(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Vec<SealId>>>;
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
    descriptors: BTreeMap<SealId, Vec<SealId>>,
}

impl DirectCutDescriptorIndex {
    pub fn new(
        descriptors: impl IntoIterator<Item = SealPredecessorDescriptor>,
    ) -> arkret_wire::Result<Self> {
        let mut index = BTreeMap::new();
        for descriptor in descriptors {
            if index
                .insert(descriptor.seal_ref, descriptor.predecessor_refs)
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

    fn predecessor_refs(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Vec<SealId>>> {
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

    fn predecessor_refs(&self, seal_ref: &SealId) -> arkret_wire::Result<Option<Vec<SealId>>> {
        Ok(self
            .seals
            .get(seal_ref)
            .map(|seal| seal.predecessor_refs.clone()))
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
        let Some(predecessor_refs) = source.predecessor_refs(&item.seal_ref)? else {
            errors.insert(DirectTraversalError::DependencyMissing);
            continue;
        };
        if base.contains(&item.seal_ref) {
            consumed_base.insert(item.seal_ref.clone());
            journal.record_topological(&item.seal_ref)?;
            continue;
        }
        if predecessor_refs.is_empty() {
            errors.insert(DirectTraversalError::IntervalStopsBeforeBase);
        }
        journal.push_work(DirectTraversalWorkItem {
            seal_ref: item.seal_ref,
            expanded: true,
        })?;
        for predecessor in predecessor_refs.iter().rev() {
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
/// winning MLS transition, join/incarnation, RRK tuple and current history
/// access are all derived from.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedDirectTraversalCut {
    pub realm_id: RealmId,
    pub target_basis: SealBasis,
    pub live_digest_suite: DigestSuite,
    pub discovery: DirectCutDiscovery,
    pub effective_state: BTreeMap<CellRef, CellState>,
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

impl ReplayEventLookup for DeltaEventLookup<'_> {
    fn event(&self, digest: &Hash) -> arkret_wire::Result<Option<Event>> {
        if let Some(event) = self.delta.get(digest) {
            return Ok(Some(event.clone()));
        }
        self.store
            .get(digest)
            .map_err(|error| WireError::Protocol(error.to_string()))
    }
}

/// Discover and replay one complete `target -> base` direct-traversal cut.
///
/// Discovery is streamed through `journal`; replay then walks the durable
/// topological log base-first, pulling each Seal and its `delta[]` Events from
/// `source` and applying them through the standard `apply_seal` reducer. Only
/// the Seal being applied and its own delta Events are resident at any point.
///
/// `on_replayed_seal` sees every accepted Seal together with its exact resolved
/// delta Events, so a caller can project the bounded slice it needs (winning MLS
/// transitions, membership incarnations, the RRK tuple) without this function
/// accumulating the whole cut.
#[allow(clippy::too_many_arguments)]
pub fn verify_direct_traversal_cut_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    request: &DirectCutRequest,
    source: &dyn DirectCutObjectSource,
    journal: &mut dyn DirectTraversalJournal,
    dependencies: &[GovernanceDependency],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
    on_replayed_seal: &mut DirectTraversalSealObserver<'_>,
) -> arkret_wire::Result<VerifiedDirectTraversalCut>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs:
        Fn(&Event, DigestSuite, &[GovernanceDependency]) -> arkret_wire::Result<()> + Copy,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
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

    journal.for_each_topological(&mut |seal_ref| {
        let seal = source
            .seal(seal_ref)?
            .ok_or_else(|| traversal_error(DirectTraversalError::DependencyMissing))?;
        if seal.id != *seal_ref {
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
            verify_event_proofs,
            verify_seal_dependencies,
            project_writes,
            &mut live_suites,
        )?;
        on_replayed_seal(&seal, &delta)?;
        replayed = replayed.saturating_add(1);
        Ok(())
    })?;

    if replayed != discovery.visited_seal_count {
        return Err(WireError::Protocol(
            "direct traversal replay did not consume every discovered Seal".to_owned(),
        ));
    }
    let leaves = seal_store
        .list_leaves(&request.realm_id)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
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
    .map_err(|error| WireError::Protocol(error.to_string()))?;

    Ok(VerifiedDirectTraversalCut {
        realm_id: request.realm_id.clone(),
        target_basis: request.target_basis.clone(),
        live_digest_suite: live_digest_suite_at_basis(&request.target_basis, &live_suites)?,
        discovery,
        effective_state,
    })
}

/// Subject of one `join_epoch` derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryJoinEpochSubject {
    pub mls_group_id: MlsGroupId,
    pub requester_actor_id: ActorId,
    pub authorization_incarnation: AuthorizationIncarnation,
}

/// Derive the `join_epoch` floor of one authorization incarnation from replayed
/// Control Events.
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
pub fn derive_history_join_epoch(
    retained_control_events: &[Event],
    subject: &HistoryJoinEpochSubject,
) -> arkret_wire::Result<u64> {
    let mut add_proposals = BTreeMap::<EventId, MlsProposalPayload>::new();
    let mut commits = Vec::<(EventId, MlsCommitPayload)>::new();
    let mut genesis = Vec::<(EventId, ActorId)>::new();
    let (realm_incarnation_ref, circle_incarnation_ref) = match &subject.authorization_incarnation {
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
    let mut realm_incarnation_proven = false;
    let mut circle_incarnation_proven = circle_incarnation_ref.is_none();

    for event in retained_control_events {
        match event.kind.as_str() {
            event_kind_str::MLS_PROPOSAL => {
                let proposal: MlsProposalPayload = payload_of(event)?;
                if proposal.mls_group_id == subject.mls_group_id
                    && proposal.proposal_type == MlsProposalType::Add
                    && proposal.target_principal_id.as_ref()
                        == Some(subject.requester_actor_id.signing_principal_id())
                    && proposal.target_authorization_incarnation.as_ref()
                        == Some(&subject.authorization_incarnation)
                {
                    add_proposals.insert(event.event_id.clone(), proposal);
                }
            }
            event_kind_str::MLS_COMMIT => {
                let commit: MlsCommitPayload = payload_of(event)?;
                if commit.mls_group_id() == subject.mls_group_id.as_str() {
                    commits.push((event.event_id.clone(), commit));
                }
            }
            event_kind_str::MLS_GENESIS
                if event
                    .payload
                    .get("mls_group_id")
                    .and_then(Value::as_str)
                    .is_some_and(|group| group == subject.mls_group_id.as_str())
                    && event.payload.get("epoch").and_then(Value::as_u64) == Some(0) =>
            {
                // The creator coordinate is not a payload field: the
                // closed mls_genesis_payload schema does not declare one,
                // and encryption-and-audit.md fixes creator principal as
                // the accepted Event's own actor_id.
                genesis.push((event.event_id.clone(), event.actor_id.clone()));
            }
            _ => {}
        }
        if !is_join_transition_of(event, &subject.requester_actor_id) {
            continue;
        }
        if event.kind.as_str() == event_kind_str::MEMBER_STATE
            && event.event_id == *realm_incarnation_ref
        {
            realm_incarnation_proven = true;
        }
        if event.kind.as_str() == event_kind_str::CIRCLE_MEMBER_STATE
            && circle_incarnation_ref.is_some_and(|expected| event.event_id == *expected)
        {
            circle_incarnation_proven = true;
        }
    }

    if !realm_incarnation_proven || !circle_incarnation_proven {
        return Err(WireError::Protocol(
            "requested authorization incarnation is not a retained winning join transition"
                .to_owned(),
        ));
    }
    let [(genesis_ref, genesis_creator)] = genesis.as_slice() else {
        return Err(WireError::Protocol(
            "retained history cut does not have exactly one winning MLS Genesis".to_owned(),
        ));
    };

    let mut winning_ref = genesis_ref.clone();
    let mut epoch = 0_u64;
    let mut join_epoch = None;
    for _ in 0..=commits.len() {
        let candidates = commits
            .iter()
            .filter(|(_, commit)| {
                commit.base_epoch() == epoch
                    && commit.base_epoch_ref() == winning_ref.as_str()
                    && commit.next_epoch() == epoch.saturating_add(1)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            break;
        }
        if candidates.len() != 1 {
            return Err(WireError::Protocol(
                "retained MLS Commit frontier is contested".to_owned(),
            ));
        }
        let (commit_ref, commit) = candidates[0];
        let matching_adds = commit
            .proposal_refs()
            .iter()
            .filter(|proposal_ref| {
                add_proposals
                    .get(*proposal_ref)
                    .is_some_and(|proposal| proposal.base_epoch == epoch)
            })
            .count();
        if matching_adds > 1 || (matching_adds == 1 && join_epoch.is_some()) {
            return Err(WireError::Protocol(
                "current authorization incarnation has multiple winning MLS Add transitions"
                    .to_owned(),
            ));
        }
        if matching_adds == 1 {
            join_epoch = Some(commit.next_epoch());
        }
        winning_ref = commit_ref.clone();
        epoch = commit.next_epoch();
    }

    if let Some(join_epoch) = join_epoch {
        return Ok(join_epoch);
    }
    // Genesis initial member: the same replay proved the founding membership
    // incarnation above, and the winning Genesis names this actor as its initial
    // leaf. No Add/Commit lineage exists for a founding member, so the floor is
    // the Genesis epoch itself.
    if *genesis_creator == subject.requester_actor_id {
        return Ok(0);
    }
    Err(WireError::Protocol(
        "current authorization incarnation has no winning MLS Add/Commit lineage and is not a proven Genesis initial leaf"
            .to_owned(),
    ))
}

fn payload_of<T: serde::de::DeserializeOwned>(event: &Event) -> arkret_wire::Result<T> {
    Ok(serde_json::from_value(Value::Object(
        event.payload.clone().into_iter().collect(),
    ))?)
}

fn is_join_transition_of(event: &Event, actor_id: &ActorId) -> bool {
    serde_json::from_value::<
        arkret_models_collaboration::governance::membership_invite::MembershipPayload,
    >(Value::Object(event.payload.clone().into_iter().collect()))
    .is_ok_and(|payload| {
        payload.member_id == *actor_id
            && payload.membership
                == arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::mls_envelopes::MlsCommitEnvelope;
    use arkret_models_crypto::mls_payloads::MlsGovernanceBindingPayload;
    use arkret_wire::event_envelope::ScopeRef;
    use arkret_wire::{AccountId, ContentScheme, DidCoreId, DurabilityPolicy, Hlc};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN";
    const GROUP: &str = "YWs6cmVhbG06MDE5YzAwMDA";

    fn seal_id(marker: &str) -> SealId {
        SealId::new(format!("ak:seal:sha256:{}", marker.repeat(32)))
            .expect("content-addressed Seal id")
    }

    fn descriptor(seal: &SealId, predecessors: &[&SealId]) -> SealPredecessorDescriptor {
        SealPredecessorDescriptor {
            seal_ref: seal.clone(),
            predecessor_refs: predecessors.iter().map(|value| (*value).clone()).collect(),
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

    #[test]
    fn closed_cut_emits_a_base_first_topological_order() {
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

    #[test]
    fn a_hidden_predecessor_fails_closed() {
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

    #[test]
    fn an_undominated_trusted_current_leaf_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut request = cut.request();
        request.trusted_current_basis = basis(&[&seal_id("ee")]);
        let (outcome, _) = discover(&request, cut.descriptors());
        assert_eq!(
            outcome.error_names(),
            BTreeSet::from(["trusted_current_not_dominated"])
        );
    }

    #[test]
    fn a_branch_that_stops_before_the_base_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut descriptors = cut.descriptors();
        descriptors.retain(|item| item.seal_ref != cut.mid_left);
        for item in &mut descriptors {
            item.predecessor_refs.retain(|value| *value != cut.mid_left);
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

    #[test]
    fn an_unconsumed_base_leaf_fails_closed() {
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

    #[test]
    fn a_surplus_descriptor_fails_closed() {
        let cut = FixtureShapedCut::new();
        let mut descriptors = cut.descriptors();
        descriptors.push(descriptor(&seal_id("ee"), &[]));
        let (outcome, _) = discover(&cut.request(), descriptors);
        assert_eq!(
            outcome.error_names(),
            BTreeSet::from(["surplus_descriptor"])
        );
    }

    #[test]
    fn a_duplicate_descriptor_is_refused_by_the_source() {
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

    #[test]
    fn ambiguous_event_variants_are_refused_before_replay_material_exists() {
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

        fn predecessor_refs(&self, _seal_ref: &SealId) -> arkret_wire::Result<Option<Vec<SealId>>> {
            panic!("an over-budget cut must be refused before any descriptor fetch");
        }
    }

    #[test]
    fn an_over_budget_cut_is_refused_before_the_first_journal_row() {
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
            GROUP,
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
            target_principal_id: Some(actor()),
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
        let commit_bytes = b"arkret-test-commit";
        let payload = MlsCommitPayload::new(
            0,
            base_epoch_ref.as_str(),
            proposal_refs,
            &MlsCommitEnvelope {
                group_id: GROUP.to_owned(),
                epoch: 1,
                commit: arkret_canonical::base64url_encode(commit_bytes),
                commit_digest: Hash::new(arkret_canonical::sha256_digest(commit_bytes))
                    .expect("commit digest"),
                ratchet_tree: None,
            },
            governance_binding(0, 1),
        )
        .expect("commit payload");
        event(
            event_kind_str::MLS_COMMIT,
            4,
            serde_json::to_value(payload).expect("commit payload"),
            event_id,
        )
    }

    fn subject(incarnation: &EventId) -> HistoryJoinEpochSubject {
        HistoryJoinEpochSubject {
            mls_group_id: MlsGroupId::new(GROUP).expect("group id"),
            requester_actor_id: ActorId::account(AccountId::new(actor(), actor())),
            authorization_incarnation: AuthorizationIncarnation::Realm {
                realm_membership_incarnation_ref: incarnation.clone(),
            },
        }
    }

    const INCARNATION_REF: &str = "ak:event:AWYr1ucW0vOccjnC8XMFGQK8PjKzaha_YpYb8B0uDY_y";
    const GENESIS_REF: &str = "ak:event:AZc5yUQiAVSI3hquJ6vb24B9nBqhiONzxJK6xPKc-IQ9";
    const ADD_REF: &str = "ak:event:AbNAprqpf8plo9xcY8bDOmf3mEUhUCZbN63erkPaxN_8";
    const COMMIT_REF: &str = "ak:event:ARrXzX07X_prHPMAeOGPMrI4_sUFneJW2aYSvHN_-9aQ";

    #[test]
    fn join_epoch_is_the_winning_commit_that_consumes_the_exact_add() {
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
            derive_history_join_epoch(&retained, &subject(&incarnation)).expect("join epoch"),
            1
        );
    }

    #[test]
    fn a_genesis_initial_leaf_joins_at_epoch_zero() {
        let incarnation = EventId::new(INCARNATION_REF).expect("incarnation ref");
        let retained = vec![
            membership_join(INCARNATION_REF),
            genesis(GENESIS_REF, &actor()),
        ];
        assert_eq!(
            derive_history_join_epoch(&retained, &subject(&incarnation)).expect("join epoch"),
            0
        );
    }

    #[test]
    fn a_non_founding_actor_without_an_add_lineage_fails_closed() {
        let incarnation = EventId::new(INCARNATION_REF).expect("incarnation ref");
        let founder = DidCoreId::new("ak:did_core:key:z6MkfixtureFounder").expect("founder");
        let retained = vec![
            membership_join(INCARNATION_REF),
            genesis(GENESIS_REF, &founder),
        ];
        let error = derive_history_join_epoch(&retained, &subject(&incarnation))
            .expect_err("no Add lineage and no Genesis leaf proof");
        assert!(
            error.to_string().contains("Genesis initial leaf"),
            "{error}"
        );
    }

    #[test]
    fn an_unproven_incarnation_fails_closed() {
        let incarnation = EventId::new(INCARNATION_REF).expect("incarnation ref");
        let retained = vec![genesis(GENESIS_REF, &actor())];
        let error = derive_history_join_epoch(&retained, &subject(&incarnation))
            .expect_err("an unproven incarnation is not a join floor");
        assert!(
            error.to_string().contains("authorization incarnation"),
            "{error}"
        );
    }
}
