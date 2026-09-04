//! Trust-pin admission for the near-current MLS governance proof surface.
//!
//! Proof DTO validation lives in `arkret-models-crypto`. Full signed Event and
//! Seal objects are resolved through their standard surfaces and replayed by
//! the ordinary state reducer; there is no materialized proof-bundle reducer.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::{
    RealmCreatePayload, RealmPolicyBundlePayload, RealmPurpose,
};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencyResolveOutcome,
};
use arkret_models_collaboration::objects::realm::RealmAvailabilityPolicy;
pub use arkret_models_crypto::mls_governance_proof::*;
use arkret_wire::cell::CellId;
use arkret_wire::event_envelope::{Event, EventSubmitContext, ScopeRef};
use arkret_wire::{
    ActorId, Base64UrlString, CellRef, ContentScheme, DidCoreId, DurabilityPolicy, EventId, Hash,
    NotarySig, NotarySignerDescriptor, NotaryValue, ProjectedCellWrite, RealmId, Seal, SealBasis,
    SealId, SealSignature, WireError,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::lattice::CellState;
use crate::state::store::memory::{MemoryCellStore, MemoryControlEventStore, MemorySealStore};
use crate::{
    CellRegistry, CellStore, ControlEventStore, SealDigestSuites, SealStore,
    apply_replayed_seal_in_context, control_event_completeness_root, effective_state_at,
    state_value_leaf_digest, union_predecessor_covered_events, verify_state_inclusion_proof,
};

pub type VerifyEventProofsFuture<'a> =
    Pin<Box<dyn Future<Output = arkret_wire::Result<()>> + Send + 'a>>;

/// SHA-256 over RFC 8785/JCS of the exact closed frontier registry artifact.
pub const MLS_SECURITY_FRONTIER_REGISTRY_DIGEST: &str =
    crate::generated::mls_security_frontier::MLS_SECURITY_FRONTIER_REGISTRY_DIGEST;

pub fn mls_security_frontier_registry_digest() -> Hash {
    Hash::new(MLS_SECURITY_FRONTIER_REGISTRY_DIGEST)
        .expect("generated MLS security-frontier registry digest is valid")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGroupGenesisBinding {
    pub content_scheme: ContentScheme,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durability_policy: Option<DurabilityPolicy>,
}

impl MlsGroupGenesisBinding {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        match (self.content_scheme, self.durability_policy) {
            (ContentScheme::MlsRfc9420, None)
            | (
                ContentScheme::MlsExporterAeadV1,
                Some(DurabilityPolicy::None | DurabilityPolicy::OrganizationRecoveryKey),
            ) => Ok(()),
            _ => Err(WireError::Protocol(
                "MLS group genesis binding content scheme and durability policy mismatch"
                    .to_owned(),
            )),
        }
    }

    pub fn from_proposal(proposal: &ProposedMlsGroupGenesisBinding) -> arkret_wire::Result<Self> {
        proposal.validate()?;
        Ok(Self {
            content_scheme: proposal.content_scheme,
            durability_policy: proposal.durability_policy,
        })
    }
}

fn validate_proposal_binding(
    request: &MlsGovernanceProofRequestBody,
    binding: &MlsGroupGenesisBinding,
) -> arkret_wire::Result<()> {
    if let Some(proposal) = &request.proposed_group_genesis_binding {
        let proposed = MlsGroupGenesisBinding::from_proposal(proposal)?;
        if &proposed != binding {
            return frontier_rejected(
                "materialized MLS genesis binding differs from proposed_group_genesis_binding",
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedMlsGovernanceFrontier {
    pub proof_target_basis: SealBasis,
    pub security_frontier_digest: Hash,
    pub page_digest: Hash,
    pub target_checkpoint: MlsGovernanceVerificationCheckpoint,
}

impl Eq for VerifiedMlsGovernanceFrontier {}

/// Crash-safe verified replay state pinned together with one canonical basis.
/// The checkpoint deliberately indexes the complete accepted signed-object and
/// dependency closure; a durable implementation should content-address and
/// deduplicate those objects instead of rewriting their bytes for every T3
/// update. A bare `SealBasis` is not a trust anchor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceVerificationCheckpoint {
    pub realm_id: RealmId,
    pub basis: SealBasis,
    pub live_digest_suite: DigestSuite,
    pub accepted_seals: Vec<Seal>,
    pub accepted_events: Vec<Event>,
    pub governance_dependencies: Vec<GovernanceDependency>,
}

impl Eq for MlsGovernanceVerificationCheckpoint {}

/// Lazy retrieval of the exact canonical Control Event bytes an accepted Seal
/// pinned at acceptance time.
///
/// Replay never materializes the whole cut: the direct-traversal driver keeps
/// only the Seal it is applying plus that Seal's own `delta[]` Events live, and
/// resolves every older covered Event from the reducer's Control Event store.
/// A fully materialized `BTreeMap<Hash, Event>` also implements this trait so
/// the near-current frontier surface keeps its existing shape.
#[async_trait]
pub trait ReplayEventLookup: Send + Sync {
    async fn event(&self, digest: &Hash) -> arkret_wire::Result<Option<Event>>;
}

#[async_trait]
impl ReplayEventLookup for BTreeMap<Hash, Event> {
    async fn event(&self, digest: &Hash) -> arkret_wire::Result<Option<Event>> {
        Ok(self.get(digest).cloned())
    }
}

pub struct ControlEventReplayLookup<'a> {
    store: &'a dyn ControlEventStore,
}

impl<'a> ControlEventReplayLookup<'a> {
    pub const fn new(store: &'a dyn ControlEventStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ReplayEventLookup for ControlEventReplayLookup<'_> {
    async fn event(&self, digest: &Hash) -> arkret_wire::Result<Option<Event>> {
        self.store
            .get(digest)
            .await
            .map_err(|error| WireError::Protocol(format!("Control Event lookup failed: {error}")))
    }
}

/// Reducer-derived predecessor facts required to evaluate one Seal's
/// AvailabilityReceipt policy without consulting current Realm state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealAvailabilityReplayAuthority {
    /// A genesis Seal has no predecessor governance authority. Its receipt
    /// commitment must be empty; the policy it materializes governs only its
    /// successors.
    Genesis,
    /// Availability policy and holder eligibility frozen at the predecessor
    /// view. Ordinary/DC Realms derive this set from effective joined member
    /// ActorId routing projections; PCRs derive the singleton from the accepted
    /// genesis create's admitted `station_id`.
    Predecessor {
        policy: RealmAvailabilityPolicy,
        eligible_holder_service_ids: BTreeSet<DidCoreId>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealDependencyReplayContext {
    pub event_digest_suites: BTreeMap<Hash, DigestSuite>,
    pub seal_digest_suite: DigestSuite,
    pub availability_authority: SealAvailabilityReplayAuthority,
}

impl MlsGovernanceVerificationCheckpoint {
    pub fn validate_checkpoint(&self) -> arkret_wire::Result<()> {
        self.basis.validate_protocol_bounds()?;
        if self.accepted_seals.is_empty() || self.accepted_events.is_empty() {
            return frontier_rejected("governance checkpoint is empty");
        }
        let mut seals = BTreeMap::new();
        let mut covered = BTreeSet::new();
        for seal in &self.accepted_seals {
            seal.validate_structural()?;
            if seal.realm_id != self.realm_id || seals.insert(seal.id.clone(), seal).is_some() {
                return frontier_rejected(
                    "governance checkpoint Seal set is duplicate or cross-Realm",
                );
            }
            covered.extend(seal.delta.iter().cloned());
        }
        let events = events_by_claimed_digest(&self.accepted_events)?;
        if covered != events.keys().cloned().collect() {
            return frontier_rejected(
                "governance checkpoint Events are not every-and-only accepted Seal deltas",
            );
        }
        let mut visited = BTreeSet::new();
        let mut pending = self.basis.leaves.clone();
        while let Some(id) = pending.pop() {
            if !visited.insert(id.clone()) {
                continue;
            }
            let seal = seals.get(&id).ok_or_else(|| {
                WireError::Protocol("governance checkpoint Seal closure is incomplete".to_owned())
            })?;
            pending.extend(seal.predecessor_refs.iter().cloned());
        }
        if visited.len() != seals.len() {
            return frontier_rejected(
                "governance checkpoint contains material outside its basis closure",
            );
        }
        GovernanceDependencyResolveOutcome {
            items: self.governance_dependencies.clone(),
            missing_selectors: Vec::new(),
        }
        .validate()?;
        Ok(())
    }
}

/// Materialize one registered reducer cell from an already verified complete
/// checkpoint. The replay is isolated and uses the same projector and lattice
/// registry as proof verification; a missing or Bottom target is rejected.
pub async fn materialize_registered_cell_value_from_verified_checkpoint<ProjectWrites>(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    cell: &CellRef,
    registry: &dyn CellRegistry,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<Value>
where
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    materialize_registered_cell_value_at_basis_from_verified_checkpoint(
        checkpoint,
        &checkpoint.basis,
        cell,
        registry,
        project_writes,
    )
    .await
}

/// Read a registered cell at an explicitly named accepted cut of a trusted
/// checkpoint. The caller cannot manufacture authority by naming an unknown
/// Seal; the reducer resolves the basis against the fully replayed checkpoint.
pub async fn materialize_registered_cell_value_at_basis_from_verified_checkpoint<ProjectWrites>(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    basis: &SealBasis,
    cell: &CellRef,
    registry: &dyn CellRegistry,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<Value>
where
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let mut values = materialize_registered_cell_values_at_basis_from_verified_checkpoint(
        checkpoint,
        basis,
        std::slice::from_ref(cell),
        registry,
        project_writes,
    )
    .await?;
    match values.remove(cell) {
        Some(value) => Ok(value),
        None => frontier_rejected("verified checkpoint target cell is missing"),
    }
}

/// Read a bounded set of registered cells from one verified accepted cut.
///
/// The checkpoint is replayed once for the whole set so an authorization
/// query over many capability-grant cells cannot amplify one Signal into one
/// complete governance replay per grant. Missing cells are omitted; any
/// requested Bottom cell rejects the batch.
pub async fn materialize_registered_cell_values_at_basis_from_verified_checkpoint<ProjectWrites>(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    basis: &SealBasis,
    cells: &[CellRef],
    registry: &dyn CellRegistry,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<BTreeMap<CellRef, Value>>
where
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    checkpoint.validate_checkpoint()?;
    basis.validate_protocol_bounds()?;
    if basis
        .leaves
        .iter()
        .any(|id| !checkpoint.accepted_seals.iter().any(|seal| &seal.id == id))
    {
        return frontier_rejected("requested cell basis contains an unverified Seal");
    }
    let (seal_store, cell_store, ..) = replay_checkpoint_and_cut_to_basis(
        &checkpoint.realm_id,
        &checkpoint.basis,
        &checkpoint.basis,
        checkpoint,
        &[],
        &[],
        &checkpoint.governance_dependencies,
        registry,
        |_, _, _, _| Ok(()),
        |_, _, _| Box::pin(async { Ok(()) }),
        |_, _, _, _| Ok(()),
        project_writes,
    )
    .await?;
    let state = effective_state_at(
        &basis.leaves,
        &checkpoint.realm_id,
        &seal_store,
        &cell_store,
        registry,
    )
    .await
    .map_err(replay_reject_error)?;
    let mut values = BTreeMap::new();
    for cell in cells {
        match state.get(cell) {
            Some(CellState::Value(value)) => {
                values.insert(cell.clone(), value.clone());
            }
            Some(CellState::Bottom(_)) => {
                return frontier_rejected("verified checkpoint target cell is Bottom");
            }
            None => {}
        }
    }
    Ok(values)
}

/// Return the exact Event that established the effective `join` value of one
/// registered membership cell at a verified checkpoint.
///
/// This replays the checkpoint through the ordinary reducer. It does not pick
/// a retained `join` Event by timestamp or list order, so leave/rejoin and
/// concurrent histories cannot silently bind an MLS Add to a stale
/// authorization incarnation.
pub async fn winning_membership_join_event_from_verified_checkpoint<ProjectWrites>(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    cell: &CellRef,
    registry: &dyn CellRegistry,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<EventId>
where
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    checkpoint.validate_checkpoint()?;
    let cell_id = CellId::from_ref(cell)?;
    if !matches!(
        cell_id.component(),
        arkret_wire::CellFamilyId::MEMBER_STATE_V1 | arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1
    ) {
        return frontier_rejected("authorization incarnation target is not a membership cell");
    }
    let (seal_store, cell_store, ..) = replay_checkpoint_and_cut_to_basis(
        &checkpoint.realm_id,
        &checkpoint.basis,
        &checkpoint.basis,
        checkpoint,
        &[],
        &[],
        &checkpoint.governance_dependencies,
        registry,
        |_, _, _, _| Ok(()),
        |_, _, _| Box::pin(async { Ok(()) }),
        |_, _, _, _| Ok(()),
        project_writes,
    )
    .await?;
    let state = effective_state_at(
        &checkpoint.basis.leaves,
        &checkpoint.realm_id,
        &seal_store,
        &cell_store,
        registry,
    )
    .await
    .map_err(replay_reject_error)?;
    if !matches!(state.get(cell), Some(CellState::Value(value)) if value.as_str() == Some("join")) {
        return frontier_rejected("authorization membership cell is not effectively joined");
    }
    let issued = cell_store
        .sealed_ops_for_cell(&checkpoint.realm_id, cell)
        .await
        .map_err(replay_store_error)?;
    let winning_digest = winning_membership_join(&issued)?;
    for event in &checkpoint.accepted_events {
        if claimed_event_digest(event)? == winning_digest {
            return Ok(event.event_id.clone());
        }
    }
    Err(WireError::Protocol(
        "winning membership transition is absent from the verified checkpoint".to_owned(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn verify_mls_governance_checkpoint_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    candidate: &MlsGovernanceVerificationCheckpoint,
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<MlsGovernanceVerificationCheckpoint>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    replay_and_verify_checkpoint_with_registry(
        candidate,
        registry,
        verify_seal_signature,
        verify_event_proofs.clone(),
        verify_seal_dependencies,
        project_writes,
    )
    .await
    .map(|(checkpoint, _)| checkpoint)
}

/// Verify raw complete governance material and derive its target live digest
/// suite from isolated reducer replay. Callers do not provide, infer, or trust
/// a target suite before the Seal DAG has been verified.
#[allow(clippy::too_many_arguments)]
pub async fn verify_mls_governance_closure_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    realm_id: &RealmId,
    basis: &SealBasis,
    seals: &[Seal],
    events: &[Event],
    dependencies: &[GovernanceDependency],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<(
    MlsGovernanceVerificationCheckpoint,
    BTreeMap<Hash, DigestSuite>,
)>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let candidate = MlsGovernanceVerificationCheckpoint {
        realm_id: realm_id.clone(),
        basis: basis.clone(),
        // This value is deliberately ignored below. It exists only because a
        // durable verified checkpoint always stores the replay-derived suite.
        live_digest_suite: DigestSuite::Sha256,
        accepted_seals: seals.to_vec(),
        accepted_events: events.to_vec(),
        governance_dependencies: dependencies.to_vec(),
    };
    let (verified, live_suites) = replay_and_verify_checkpoint_material_with_registry(
        &candidate,
        None,
        registry,
        verify_seal_signature,
        verify_event_proofs,
        verify_seal_dependencies,
        project_writes,
    )
    .await?;
    let event_digest_suites =
        event_digest_suites_for_verified_replay(&verified, &live_suites).await?;
    Ok((verified, event_digest_suites))
}

/// Verify a complete checkpoint and derive the live digest suite at an
/// ancestor basis from the replayed digest-suite state. The suite is never
/// inferred from a Seal id or digest prefix.
#[allow(clippy::too_many_arguments)]
pub async fn verified_live_digest_suite_at_basis_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    candidate: &MlsGovernanceVerificationCheckpoint,
    requested_basis: &SealBasis,
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<(
    MlsGovernanceVerificationCheckpoint,
    DigestSuite,
    BTreeMap<Hash, DigestSuite>,
)>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    requested_basis.validate_protocol_bounds()?;
    let (verified, live_suites) = replay_and_verify_checkpoint_with_registry(
        candidate,
        registry,
        verify_seal_signature,
        verify_event_proofs,
        verify_seal_dependencies,
        project_writes,
    )
    .await?;
    let requested_suite = live_digest_suite_at_basis(requested_basis, &live_suites)?;
    let event_digest_suites =
        event_digest_suites_for_verified_replay(&verified, &live_suites).await?;
    Ok((verified, requested_suite, event_digest_suites))
}

async fn event_digest_suites_for_verified_replay(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    live_suites: &BTreeMap<SealId, DigestSuite>,
) -> arkret_wire::Result<BTreeMap<Hash, DigestSuite>> {
    let events = events_by_claimed_digest(&checkpoint.accepted_events)?
        .into_iter()
        .map(|(digest, event)| (digest, event.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut suites = BTreeMap::new();
    for seal in &checkpoint.accepted_seals {
        let digest_suites = digest_suites_for_replay_seal(seal, &events, live_suites).await?;
        for digest in &seal.delta {
            let event = events.get(digest).ok_or_else(|| {
                WireError::Protocol("verified replay Event is unresolved".to_owned())
            })?;
            let suite = if seal.predecessor_refs.is_empty()
                && event.kind == arkret_wire::EventKind::RealmCreate
            {
                DigestSuite::Sha256
            } else {
                digest_suites.event_digest_suite
            };
            if let Some(previous) = suites.insert(digest.clone(), suite)
                && previous != suite
            {
                return frontier_rejected(
                    "verified replay assigned conflicting digest suites to one Event",
                );
            }
        }
    }
    Ok(suites)
}

#[allow(clippy::too_many_arguments)]
async fn replay_and_verify_checkpoint_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    candidate: &MlsGovernanceVerificationCheckpoint,
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<(
    MlsGovernanceVerificationCheckpoint,
    BTreeMap<SealId, DigestSuite>,
)>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    replay_and_verify_checkpoint_material_with_registry(
        candidate,
        Some(candidate.live_digest_suite),
        registry,
        verify_seal_signature,
        verify_event_proofs,
        verify_seal_dependencies,
        project_writes,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn replay_and_verify_checkpoint_material_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    candidate: &MlsGovernanceVerificationCheckpoint,
    expected_live_digest_suite: Option<DigestSuite>,
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<(
    MlsGovernanceVerificationCheckpoint,
    BTreeMap<SealId, DigestSuite>,
)>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    candidate.validate_checkpoint()?;
    let event_store = MemoryControlEventStore::default();
    let events = events_by_claimed_digest(&candidate.accepted_events)?
        .into_iter()
        .map(|(digest, event)| (digest, event.clone()))
        .collect::<BTreeMap<_, _>>();
    let seal_store = MemorySealStore::default();
    let cell_store = MemoryCellStore::default();
    let mut live_suites = BTreeMap::new();
    let accepted_seals = replay_seal_set(
        &candidate.accepted_seals,
        &events,
        &event_store,
        &seal_store,
        &cell_store,
        &candidate.governance_dependencies,
        registry,
        verify_seal_signature,
        verify_event_proofs,
        verify_seal_dependencies,
        project_writes,
        &mut live_suites,
    )
    .await?;
    let leaves = seal_store
        .list_leaves(&candidate.realm_id)
        .await
        .map_err(replay_store_error)?;
    if canonical_seal_set(&leaves) != canonical_seal_set(&candidate.basis.leaves) {
        return frontier_rejected("verified checkpoint replay does not end at its pinned basis");
    }
    let live_digest_suite = live_digest_suite_at_basis(&candidate.basis, &live_suites)?;
    if expected_live_digest_suite.is_some_and(|expected| live_digest_suite != expected) {
        return frontier_rejected(
            "verified checkpoint live digest suite does not match its pinned basis",
        );
    }
    Ok((
        MlsGovernanceVerificationCheckpoint {
            realm_id: candidate.realm_id.clone(),
            basis: candidate.basis.clone(),
            live_digest_suite,
            accepted_seals,
            accepted_events: events.into_values().collect(),
            governance_dependencies: candidate.governance_dependencies.clone(),
        },
        live_suites,
    ))
}

/// Verify an exact `(base, target]` governance cut from a previously verified
/// checkpoint. The base checkpoint is replayed in isolation before any cut
/// object is admitted, so a bare `SealBasis` is never accepted as authority.
/// The returned checkpoint contains the complete verified base and cut
/// closure and is pinned to `target_basis`.
#[allow(clippy::too_many_arguments)]
pub async fn verify_mls_governance_cut_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    base_checkpoint: &MlsGovernanceVerificationCheckpoint,
    target_basis: &SealBasis,
    cut_seals: &[Seal],
    cut_events: &[Event],
    cut_dependencies: &[GovernanceDependency],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<MlsGovernanceVerificationCheckpoint>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    base_checkpoint.validate_checkpoint()?;
    target_basis.validate_protocol_bounds()?;

    let retained_seal_ids = base_checkpoint
        .accepted_seals
        .iter()
        .map(|seal| seal.id.clone())
        .collect::<BTreeSet<_>>();
    if cut_seals
        .iter()
        .any(|seal| retained_seal_ids.contains(&seal.id))
    {
        return frontier_rejected(
            "governance cut repeats a Seal from the verified base checkpoint",
        );
    }
    let expected_cut_events = cut_seals
        .iter()
        .flat_map(|seal| seal.delta.iter().cloned())
        .collect::<BTreeSet<_>>();
    let cut_events_by_digest = events_by_claimed_digest(cut_events)?;
    if expected_cut_events != cut_events_by_digest.keys().cloned().collect() {
        return frontier_rejected(
            "governance cut Events are not every-and-only the cut Seal deltas",
        );
    }
    if target_basis == &base_checkpoint.basis && (!cut_seals.is_empty() || !cut_events.is_empty()) {
        return frontier_rejected("an equal-basis governance cut must contain no Seal or Event");
    }

    let dependencies =
        merge_dependencies(&base_checkpoint.governance_dependencies, cut_dependencies)?;
    let (_, _, accepted_seals, accepted_events, live_suites) = replay_checkpoint_and_cut_to_basis(
        &base_checkpoint.realm_id,
        &base_checkpoint.basis,
        target_basis,
        base_checkpoint,
        cut_seals,
        cut_events,
        &dependencies,
        registry,
        verify_seal_signature,
        verify_event_proofs,
        verify_seal_dependencies,
        project_writes,
    )
    .await?;
    Ok(MlsGovernanceVerificationCheckpoint {
        realm_id: base_checkpoint.realm_id.clone(),
        basis: target_basis.clone(),
        live_digest_suite: live_digest_suite_at_basis(target_basis, &live_suites)?,
        accepted_seals,
        accepted_events,
        governance_dependencies: dependencies,
    })
}

#[derive(Serialize)]
struct SecurityFrontierCellEntry {
    cell_family: String,
    cell_subject: Value,
    projected_value_digest: Hash,
}

#[derive(Serialize)]
struct SecurityFrontierDigestInput<'a> {
    profile_id: &'static str,
    effective_scope: &'a ScopeRef,
    group_genesis_binding: &'a MlsGroupGenesisBinding,
    cell_entries: &'a [SecurityFrontierCellEntry],
    mls_leaf_set_digest: &'a Hash,
}

/// Verify one complete near-current response by replaying the exact accepted
/// Seal cut from a previously verified checkpoint. Seal authority is selected
/// from each Seal's predecessor joined notary state; the callback performs only
/// algorithm-specific signature math against the descriptor supplied by this
/// function.
#[allow(clippy::too_many_arguments)]
pub async fn verify_mls_governance_frontier_with_registry<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    request: &MlsGovernanceProofRequestBody,
    bundle: &MlsGovernanceProofBundle,
    base_checkpoint: &MlsGovernanceVerificationCheckpoint,
    resolved_seals: &[Seal],
    resolved_delta_events: &[Event],
    resolved_provenance_events: &[Event],
    resolved_dependencies: &[GovernanceDependency],
    group_genesis_binding: &MlsGroupGenesisBinding,
    local_mls_leaves: &[MlsSecurityFrontierLeaf],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<VerifiedMlsGovernanceFrontier>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    bundle.validate_for_request(request)?;
    if request.local_mls_leaves != local_mls_leaves {
        return frontier_rejected(
            "query local_mls_leaves differ from the verifier's RFC 9420 group state",
        );
    }
    group_genesis_binding.validate()?;
    validate_proposal_binding(request, group_genesis_binding)?;
    if bundle.frontier_projection.frontier_registry_digest
        != mls_security_frontier_registry_digest()
    {
        return frontier_rejected(
            "frontier registry digest does not match the locally pinned registry",
        );
    }

    let seals = verify_resolved_seals(request, bundle, resolved_seals)?;
    let provenance_events = verify_resolved_events(bundle, resolved_provenance_events)?;
    let expected_delta = seals
        .values()
        .filter(|seal| !request.proof_base_basis.leaves.contains(&seal.id))
        .flat_map(|seal| seal.delta.iter().cloned())
        .collect::<BTreeSet<_>>();
    let delta_events = events_by_claimed_digest(resolved_delta_events)?;
    if expected_delta != delta_events.keys().cloned().collect() {
        return frontier_rejected(
            "resolved delta Event set is not every-and-only the Seal cut delta",
        );
    }
    let mut accepted_event_digests = checkpoint_event_digests(base_checkpoint)?;
    accepted_event_digests.extend(expected_delta.iter().cloned());
    for event in provenance_events.values() {
        if !accepted_event_digests.contains(&claimed_event_digest(event)?) {
            return frontier_rejected(
                "frontier provenance Event is not accepted in the checkpoint or replay cut",
            );
        }
    }
    let dependencies = merge_dependencies(
        &base_checkpoint.governance_dependencies,
        resolved_dependencies,
    )?;
    let (seal_store, cell_store, accepted_seals, accepted_events, live_suites) =
        replay_checkpoint_and_cut(
            request,
            base_checkpoint,
            resolved_seals,
            resolved_delta_events,
            &dependencies,
            registry,
            verify_seal_signature,
            verify_event_proofs,
            verify_seal_dependencies,
            project_writes,
        )
        .await?;
    let (canonical_leaves, leaf_actors, leaf_credentials) = canonical_leaf_set(local_mls_leaves)?;
    let mls_leaf_set_digest = canonical_hash(&canonical_leaves)?;
    for branch in &bundle.frontier_projection.branches {
        let seal = seals.get(&branch.target_seal_ref).ok_or_else(|| {
            WireError::Protocol("frontier branch target Seal is unresolved".to_owned())
        })?;
        let branch_digest_suite = live_suites
            .get(&branch.target_seal_ref)
            .copied()
            .ok_or_else(|| {
                WireError::Protocol(
                    "frontier branch target Seal has no verified digest suite".to_owned(),
                )
            })?;
        if seal.state_root != branch.state_root {
            return frontier_rejected(
                "frontier branch state_root is not signed by its target Seal",
            );
        }
        verify_frontier_span_coverage(branch)?;
        for entry in &branch.cells {
            verify_frontier_entry(
                entry,
                &seals,
                &provenance_events,
                &seal_store,
                &cell_store,
                registry,
                branch_digest_suite,
            )
            .await?;
        }
        // Own the optional boundary entries before crossing an await. Keeping
        // `Option::iter`'s borrowed iterator alive in the async state machine
        // makes the verification future lifetime-specific and prevents native
        // queue drivers from requiring it to be `Send`.
        let boundary_entries = branch
            .range_witnesses
            .iter()
            .flat_map(|range| {
                range
                    .left_boundary
                    .entry
                    .iter()
                    .chain(range.right_boundary.entry.iter())
            })
            .cloned()
            .collect::<Vec<_>>();
        for boundary in &boundary_entries {
            verify_frontier_entry(
                boundary,
                &seals,
                &provenance_events,
                &seal_store,
                &cell_store,
                registry,
                branch_digest_suite,
            )
            .await?;
        }
        verify_branch_entry_closure(
            branch,
            &seal.realm_id,
            &seal_store,
            &cell_store,
            registry,
            &request.effective_scope,
            &leaf_actors,
            &leaf_credentials,
            group_genesis_binding,
        )
        .await?;
    }

    let target_state = effective_state_at(
        &request.proof_target_basis.leaves,
        &base_checkpoint.realm_id,
        &seal_store,
        &cell_store,
        registry,
    )
    .await
    .map_err(replay_reject_error)?;
    let mut projected_entries = Vec::new();
    for (cell, state) in target_state {
        let cell_id = CellId::from_ref(&cell)?;
        // The joined Realm state necessarily contains many governance cells
        // outside the closed MLS security-frontier registry. They are not
        // proof entries and must be ignored here, exactly as the per-branch
        // materializer and closure verifier do above. An unregistered family
        // supplied *as a proof entry* is still rejected by entry validation.
        if !registered_frontier_family(cell_id.component()) {
            continue;
        }
        if matches!(state, CellState::Bottom(_)) {
            return frontier_rejected("joined target security-frontier cell is Bottom");
        }
        let CellState::Value(value) = state else {
            continue;
        };
        let Some(projected_value) = project_frontier_value(
            cell_id.component(),
            &value,
            &request.effective_scope,
            &leaf_actors,
            &leaf_credentials,
            &cell_id,
            group_genesis_binding,
        )?
        else {
            continue;
        };
        projected_entries.push(SecurityFrontierCellEntry {
            cell_family: cell_id.component().to_owned(),
            cell_subject: decoded_cell_subject(&cell_id)?,
            projected_value_digest: canonical_hash(&projected_value)?,
        });
    }
    projected_entries.sort_by(|left, right| {
        left.cell_family
            .as_bytes()
            .cmp(right.cell_family.as_bytes())
            .then_with(|| {
                arkret_canonical::canonical_json_bytes(&left.cell_subject)
                    .expect("serializing JSON value cannot fail")
                    .cmp(
                        &arkret_canonical::canonical_json_bytes(&right.cell_subject)
                            .expect("serializing JSON value cannot fail"),
                    )
            })
            .then_with(|| {
                left.projected_value_digest
                    .as_str()
                    .cmp(right.projected_value_digest.as_str())
            })
    });
    if projected_entries.windows(2).any(|pair| {
        pair[0].cell_family == pair[1].cell_family
            && pair[0].cell_subject == pair[1].cell_subject
            && pair[0].projected_value_digest == pair[1].projected_value_digest
    }) {
        return frontier_rejected("security frontier contains duplicate projected cell entries");
    }
    let security_frontier_digest = canonical_hash(&SecurityFrontierDigestInput {
        profile_id: crate::generated::mls_security_frontier::MLS_SECURITY_FRONTIER_PROFILE_ID,
        effective_scope: &request.effective_scope,
        group_genesis_binding,
        cell_entries: &projected_entries,
        mls_leaf_set_digest: &mls_leaf_set_digest,
    })?;
    Ok(VerifiedMlsGovernanceFrontier {
        proof_target_basis: request.proof_target_basis.clone(),
        security_frontier_digest,
        page_digest: bundle.page_digest.clone(),
        target_checkpoint: MlsGovernanceVerificationCheckpoint {
            realm_id: base_checkpoint.realm_id.clone(),
            basis: request.proof_target_basis.clone(),
            live_digest_suite: live_digest_suite_at_basis(
                &request.proof_target_basis,
                &live_suites,
            )?,
            accepted_seals,
            accepted_events,
            governance_dependencies: dependencies,
        },
    })
}

/// Materialize the exact near-current proof page from a previously verified
/// complete target checkpoint. The checkpoint is replayed into isolated
/// stores; no live state is mutated.
pub async fn materialize_mls_governance_frontier_from_verified_checkpoint<ProjectWrites>(
    request: &MlsGovernanceProofRequestBody,
    target_checkpoint: &MlsGovernanceVerificationCheckpoint,
    group_genesis_binding: &MlsGroupGenesisBinding,
    local_mls_leaves: &[MlsSecurityFrontierLeaf],
    registry: &dyn CellRegistry,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<MlsGovernanceProofBundle>
where
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    request.validate()?;
    if request.local_mls_leaves != local_mls_leaves {
        return frontier_rejected("query local_mls_leaves differ from the materializer input");
    }
    target_checkpoint.validate_checkpoint()?;
    group_genesis_binding.validate()?;
    validate_proposal_binding(request, group_genesis_binding)?;
    let expected_realm = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| WireError::Protocol("MLS proof scope has no Realm".to_owned()))?;
    if &target_checkpoint.realm_id != expected_realm
        || target_checkpoint.basis != request.proof_target_basis
    {
        return frontier_rejected(
            "materializer checkpoint does not bind the exact query target basis",
        );
    }

    let event_store = MemoryControlEventStore::default();
    let mut events = BTreeMap::<Hash, Event>::new();
    for event in &target_checkpoint.accepted_events {
        let digest = claimed_event_digest(event)?;
        events.insert(digest, event.clone());
    }
    let seal_store = MemorySealStore::default();
    let cell_store = MemoryCellStore::default();
    let mut live_suites = BTreeMap::new();
    replay_seal_set(
        &target_checkpoint.accepted_seals,
        &events,
        &event_store,
        &seal_store,
        &cell_store,
        &target_checkpoint.governance_dependencies,
        registry,
        |_, _, _, _| Ok(()),
        |_, _, _| Box::pin(async { Ok(()) }),
        |_, _, _, _| Ok(()),
        project_writes,
        &mut live_suites,
    )
    .await?;
    if live_digest_suite_at_basis(&target_checkpoint.basis, &live_suites)?
        != target_checkpoint.live_digest_suite
    {
        return frontier_rejected(
            "materializer checkpoint live digest suite does not match its pinned basis",
        );
    }

    let seal_map = target_checkpoint
        .accepted_seals
        .iter()
        .map(|seal| (seal.id.clone(), seal))
        .collect::<BTreeMap<_, _>>();
    let (cut, edges) = exact_seal_cut(request, &seal_map)?;
    let mut seal_descriptors = cut
        .iter()
        .map(|seal_id| MlsGovernanceSealDescriptor {
            seal_ref: seal_id.clone(),
        })
        .collect::<Vec<_>>();
    seal_descriptors.sort();
    let mut seal_predecessor_edges = edges
        .into_iter()
        .map(
            |(seal_ref, predecessor_seal_ref)| MlsGovernanceSealPredecessorEdge {
                seal_ref,
                predecessor_seal_ref,
            },
        )
        .collect::<Vec<_>>();
    seal_predecessor_edges.sort();

    let (_, leaf_actors, leaf_credentials) = canonical_leaf_set(local_mls_leaves)?;
    let mut event_ids = BTreeSet::<EventId>::new();
    let mut branches = Vec::new();
    let mut target_leaves = request.proof_target_basis.leaves.clone();
    target_leaves.sort();
    for target_seal_ref in target_leaves {
        let seal = seal_map.get(&target_seal_ref).ok_or_else(|| {
            WireError::Protocol("materializer target Seal is unresolved".to_owned())
        })?;
        let branch_digest_suite = live_suites.get(&target_seal_ref).copied().ok_or_else(|| {
            WireError::Protocol("materializer target Seal has no verified digest suite".to_owned())
        })?;
        let state = effective_state_at(
            std::slice::from_ref(&target_seal_ref),
            expected_realm,
            &seal_store,
            &cell_store,
            registry,
        )
        .await
        .map_err(replay_reject_error)?;
        let ordered_values = state
            .iter()
            .filter_map(|(cell, state)| match state {
                CellState::Value(value) => Some((cell.clone(), value.clone())),
                CellState::Bottom(_) => None,
            })
            .collect::<Vec<_>>();
        let mut entries = Vec::new();
        let mut ranges = Vec::new();
        for (index, (cell, value)) in ordered_values.iter().enumerate() {
            let cell_id = CellId::from_ref(cell)?;
            if !registered_frontier_family(cell_id.component()) {
                continue;
            }
            if project_frontier_value(
                cell_id.component(),
                value,
                &request.effective_scope,
                &leaf_actors,
                &leaf_credentials,
                &cell_id,
                group_genesis_binding,
            )?
            .is_none()
            {
                continue;
            }
            let entry = materialize_frontier_entry(
                cell,
                &FrontierValueState { value },
                seal,
                &state,
                &seal_store,
                &cell_store,
                &events,
                &mut event_ids,
                branch_digest_suite,
            )
            .await?;
            let left = if let Some(boundary_index) = index.checked_sub(1) {
                let (boundary_cell, boundary_value) = &ordered_values[boundary_index];
                Some(
                    materialize_frontier_entry(
                        boundary_cell,
                        &FrontierValueState {
                            value: boundary_value,
                        },
                        seal,
                        &state,
                        &seal_store,
                        &cell_store,
                        &events,
                        &mut event_ids,
                        branch_digest_suite,
                    )
                    .await?,
                )
            } else {
                None
            };
            let right = if let Some((boundary_cell, boundary_value)) = ordered_values.get(index + 1)
            {
                Some(
                    materialize_frontier_entry(
                        boundary_cell,
                        &FrontierValueState {
                            value: boundary_value,
                        },
                        seal,
                        &state,
                        &seal_store,
                        &cell_store,
                        &events,
                        &mut event_ids,
                        branch_digest_suite,
                    )
                    .await?,
                )
            } else {
                None
            };
            let leaf_index = entry.inclusion_witness.leaf_index;
            let leaf_count = entry.inclusion_witness.leaf_count;
            ranges.push(MlsGovernanceFrontierRangeWitness {
                cell_family: cell_id.component().to_owned(),
                subject_prefix: cell_id.subject().to_owned(),
                leaf_count,
                start_index: leaf_index,
                end_index_exclusive: leaf_index + 1,
                included_entry_indices: vec![leaf_index],
                left_boundary: MlsGovernanceFrontierBoundary {
                    side: MlsGovernanceFrontierBoundarySide::Left,
                    state_edge: left.is_none(),
                    entry: left,
                },
                right_boundary: MlsGovernanceFrontierBoundary {
                    side: MlsGovernanceFrontierBoundarySide::Right,
                    state_edge: right.is_none(),
                    entry: right,
                },
            });
            entries.push(entry);
        }
        entries.sort_by(|left, right| left.cell_id.as_str().cmp(right.cell_id.as_str()));
        ranges.sort_by(|left, right| {
            (left.cell_family.as_str(), left.subject_prefix.as_str())
                .cmp(&(right.cell_family.as_str(), right.subject_prefix.as_str()))
        });
        branches.push(MlsGovernanceFrontierBranchProjection {
            target_seal_ref,
            state_root: seal.state_root.clone(),
            cells: entries,
            range_witnesses: ranges,
        });
    }

    let proof_material = MlsGovernanceTypedProofMaterial {
        seal_descriptors,
        seal_predecessor_edges,
        event_ids: event_ids.into_iter().collect(),
    };
    let placeholder =
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")?;
    let mut bundle = MlsGovernanceProofBundle {
        query_digest: request.query_digest()?,
        frontier_projection: MlsGovernanceFrontierProjection {
            frontier_registry_digest: mls_security_frontier_registry_digest(),
            branches,
        },
        proof_material,
        page_digest: placeholder,
    };
    bundle.page_digest = bundle.recompute_page_digest()?;
    bundle.validate_for_request(request)?;
    Ok(bundle)
}

type ExactSealCut = (BTreeSet<SealId>, BTreeSet<(SealId, SealId)>);

fn exact_seal_cut(
    request: &MlsGovernanceProofRequestBody,
    seals: &BTreeMap<SealId, &Seal>,
) -> arkret_wire::Result<ExactSealCut> {
    let base = request
        .proof_base_basis
        .leaves
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut reached = BTreeSet::new();
    let mut cut = BTreeSet::new();
    let mut edges = BTreeSet::new();
    let mut pending = request.proof_target_basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if !cut.insert(seal_id.clone()) {
            continue;
        }
        let seal = seals.get(&seal_id).ok_or_else(|| {
            WireError::Protocol("materializer Seal closure is incomplete".to_owned())
        })?;
        if base.contains(&seal_id) {
            reached.insert(seal_id);
            continue;
        }
        if seal.predecessor_refs.is_empty() {
            return frontier_rejected("materializer target does not dominate its base basis");
        }
        for predecessor in &seal.predecessor_refs {
            edges.insert((seal.id.clone(), predecessor.clone()));
            pending.push(predecessor.clone());
        }
    }
    if reached != base {
        return frontier_rejected("materializer did not reach every base basis leaf");
    }
    Ok((cut, edges))
}

#[derive(serde::Serialize)]
struct FrontierValueState<'a> {
    value: &'a Value,
}

fn canonical_state_leaf_preimage(cell: &CellRef, value: &Value) -> arkret_wire::Result<Vec<u8>> {
    arkret_canonical::canonical_json_bytes(&json!({
        "cell": cell.as_str(),
        "state": { "value": value },
    }))
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn materialize_frontier_entry(
    cell: &CellRef,
    cell_state: &FrontierValueState<'_>,
    seal: &Seal,
    state: &BTreeMap<CellRef, CellState>,
    seal_store: &MemorySealStore,
    cell_store: &MemoryCellStore,
    events: &BTreeMap<Hash, Event>,
    event_ids: &mut BTreeSet<EventId>,
    digest_suite: DigestSuite,
) -> arkret_wire::Result<MlsGovernanceFrontierCellEntry> {
    let value = cell_state.value;
    let proof = crate::state_inclusion_proof(state, cell, digest_suite)?;
    let preimage = canonical_state_leaf_preimage(cell, value)?;
    let covered = union_predecessor_covered_events(std::slice::from_ref(&seal.id), seal_store)
        .await
        .map_err(replay_reject_error)?;
    let provenance_digests = cell_store
        .sealed_ops_for_cell(&seal.realm_id, cell)
        .await
        .map_err(replay_store_error)?
        .into_iter()
        .filter(|issued| covered.contains(&issued.op.move_id))
        .map(|issued| issued.op.move_id)
        .collect::<BTreeSet<_>>();
    let mut provenance_event_refs = Vec::new();
    for digest in provenance_digests {
        let event = events.get(&digest).ok_or_else(|| {
            WireError::Protocol("materializer provenance Event is unresolved".to_owned())
        })?;
        if event.event_id.event_digest() != digest {
            return frontier_rejected("materializer Event id does not bind its resolved digest");
        }
        event_ids.insert(event.event_id.clone());
        provenance_event_refs.push(event.event_id.clone());
    }
    provenance_event_refs.sort();
    Ok(MlsGovernanceFrontierCellEntry {
        cell_id: cell.clone(),
        value_digest: canonical_hash(value)?,
        provenance_event_refs,
        inclusion_witness: MlsGovernanceMerkleMembershipWitness {
            proof_kind: MlsGovernanceMerkleProofKind::StateMembership,
            root_seal_ref: seal.id.clone(),
            root_field: MlsGovernanceMerkleRootField::StateRoot,
            root_digest: seal.state_root.clone(),
            leaf_canonical_preimage_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                &preimage,
            ))
            .map_err(|error| WireError::Protocol(error.to_owned()))?,
            leaf_digest: proof.leaf_digest,
            leaf_index: proof.leaf_index,
            leaf_count: proof.leaf_count,
            siblings: proof.inclusion_proof,
        },
    })
}

fn verify_resolved_seals<'a>(
    request: &MlsGovernanceProofRequestBody,
    bundle: &MlsGovernanceProofBundle,
    resolved: &'a [Seal],
) -> arkret_wire::Result<BTreeMap<SealId, &'a Seal>> {
    let descriptors = bundle
        .proof_material
        .seal_descriptors
        .iter()
        .map(|descriptor| descriptor.seal_ref.clone())
        .collect::<BTreeSet<_>>();
    if descriptors.len() != resolved.len() {
        return frontier_rejected("resolved Seal set is not every-and-only the descriptor set");
    }
    let expected_realm = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| WireError::Protocol("MLS proof scope has no Realm".to_owned()))?;
    let mut seals = BTreeMap::new();
    for seal in resolved {
        if !descriptors.contains(&seal.id) {
            return Err(WireError::Protocol("resolved undescribed Seal".to_owned()));
        }
        seal.validate_structural()?;
        if &seal.realm_id != expected_realm || seals.insert(seal.id.clone(), seal).is_some() {
            return frontier_rejected("resolved Seal set is duplicate or cross-Realm");
        }
    }

    let base = request
        .proof_base_basis
        .leaves
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut reached_base = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut expected_edges = BTreeSet::new();
    let mut pending = request.proof_target_basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if !visited.insert(seal_id.clone()) {
            continue;
        }
        let seal = seals.get(&seal_id).ok_or_else(|| {
            WireError::Protocol("Seal DAG descriptor closure is incomplete".to_owned())
        })?;
        if base.contains(&seal_id) {
            reached_base.insert(seal_id);
            continue;
        }
        if seal.predecessor_refs.is_empty() {
            return frontier_rejected("proof target does not dominate the complete base antichain");
        }
        for predecessor in &seal.predecessor_refs {
            expected_edges.insert((seal.id.clone(), predecessor.clone()));
            pending.push(predecessor.clone());
        }
    }
    if reached_base != base || visited.len() != seals.len() {
        return frontier_rejected(
            "Seal DAG is unreachable or contains material outside the exact cut",
        );
    }
    let supplied_edges = bundle
        .proof_material
        .seal_predecessor_edges
        .iter()
        .map(|edge| (edge.seal_ref.clone(), edge.predecessor_seal_ref.clone()))
        .collect::<BTreeSet<_>>();
    if supplied_edges != expected_edges {
        return frontier_rejected("Seal predecessor edge set is not every-and-only the exact cut");
    }
    Ok(seals)
}

fn verify_resolved_events<'a>(
    bundle: &MlsGovernanceProofBundle,
    resolved: &'a [Event],
) -> arkret_wire::Result<BTreeMap<EventId, &'a Event>> {
    let descriptors = bundle
        .proof_material
        .event_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if descriptors.len() != resolved.len() {
        return frontier_rejected("resolved Event set is not every-and-only the descriptor set");
    }
    let referenced = bundle
        .all_entries()
        .flat_map(|entry| entry.provenance_event_refs.iter().cloned())
        .collect::<BTreeSet<_>>();
    if referenced != descriptors {
        return frontier_rejected("Event descriptor set is not every-and-only provenance closure");
    }
    let mut events = BTreeMap::new();
    for event in resolved {
        if !descriptors.contains(&event.event_id) {
            return frontier_rejected("resolved undescribed Event");
        }
        if claimed_event_digest(event)? != event.event_id.event_digest()
            || events.insert(event.event_id.clone(), event).is_some()
        {
            return frontier_rejected("resolved Event id or signed digest mismatch");
        }
    }
    Ok(events)
}

fn events_by_claimed_digest(events: &[Event]) -> arkret_wire::Result<BTreeMap<Hash, &Event>> {
    let mut out = BTreeMap::new();
    for event in events {
        let digest = claimed_event_digest(event)?;
        if out.insert(digest, event).is_some() {
            return frontier_rejected("resolved delta Event set contains a duplicate digest");
        }
    }
    Ok(out)
}

fn checkpoint_event_digests(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
) -> arkret_wire::Result<BTreeSet<Hash>> {
    checkpoint
        .accepted_events
        .iter()
        .map(claimed_event_digest)
        .collect()
}

fn claimed_event_digest(event: &Event) -> arkret_wire::Result<Hash> {
    let mut claimed = None;
    for proof in &event.proofs {
        let digest = match proof {
            arkret_wire::EventProof::Producer(proof) => &proof.event_digest,
            arkret_wire::EventProof::StationAdmission(proof) => &proof.event_digest,
        };
        if let Some(previous) = &claimed {
            if previous != digest {
                return frontier_rejected("Event proofs disagree on event_digest");
            }
        } else {
            claimed = Some(digest.clone());
        }
    }
    let claimed = claimed
        .ok_or_else(|| WireError::Protocol("Event has no signed digest claim".to_owned()))?;
    if claimed != event.event_id.event_digest() {
        return frontier_rejected("Event id does not bind the signed digest claim");
    }
    Ok(claimed)
}

fn merge_dependencies(
    retained: &[GovernanceDependency],
    resolved: &[GovernanceDependency],
) -> arkret_wire::Result<Vec<GovernanceDependency>> {
    let mut by_selector = BTreeMap::<Vec<u8>, GovernanceDependency>::new();
    for item in retained.iter().chain(resolved) {
        let selector = arkret_canonical::canonical_json_bytes(item.selector())?;
        if let Some(previous) = by_selector.insert(selector, item.clone())
            && previous != *item
        {
            return frontier_rejected("governance dependency selector resolved to two values");
        }
    }
    let mut items = by_selector.into_values().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        dependency_sort_key(left)
            .expect("serializing a dependency selector cannot fail")
            .cmp(
                &dependency_sort_key(right).expect("serializing a dependency selector cannot fail"),
            )
    });
    GovernanceDependencyResolveOutcome {
        items: items.clone(),
        missing_selectors: Vec::new(),
    }
    .validate()?;
    Ok(items)
}

fn dependency_sort_key(item: &GovernanceDependency) -> arkret_wire::Result<(String, Vec<u8>)> {
    let value = serde_json::to_value(item.selector())?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| WireError::Protocol("dependency selector has no kind".to_owned()))?;
    Ok((
        kind.to_owned(),
        arkret_canonical::canonical_json_bytes(item.selector())?,
    ))
}

type ReplayedGovernanceCut = (
    MemorySealStore,
    MemoryCellStore,
    Vec<Seal>,
    Vec<Event>,
    BTreeMap<SealId, DigestSuite>,
);

#[allow(clippy::too_many_arguments)]
async fn replay_checkpoint_and_cut<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    request: &MlsGovernanceProofRequestBody,
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    resolved_seals: &[Seal],
    resolved_delta_events: &[Event],
    dependencies: &[GovernanceDependency],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<ReplayedGovernanceCut>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let expected_realm = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| WireError::Protocol("MLS proof scope has no Realm".to_owned()))?;
    replay_checkpoint_and_cut_to_basis(
        expected_realm,
        &request.proof_base_basis,
        &request.proof_target_basis,
        checkpoint,
        resolved_seals,
        resolved_delta_events,
        dependencies,
        registry,
        verify_seal_signature,
        verify_event_proofs,
        verify_seal_dependencies,
        project_writes,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn replay_checkpoint_and_cut_to_basis<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    expected_realm: &RealmId,
    expected_base_basis: &SealBasis,
    target_basis: &SealBasis,
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    resolved_seals: &[Seal],
    resolved_delta_events: &[Event],
    dependencies: &[GovernanceDependency],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
) -> arkret_wire::Result<ReplayedGovernanceCut>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    checkpoint.validate_checkpoint()?;
    if &checkpoint.realm_id != expected_realm || &checkpoint.basis != expected_base_basis {
        return frontier_rejected("base checkpoint does not bind the exact query base");
    }

    let event_store = MemoryControlEventStore::default();
    let mut all_events = BTreeMap::<Hash, Event>::new();
    for event in checkpoint
        .accepted_events
        .iter()
        .chain(resolved_delta_events)
    {
        let digest = claimed_event_digest(event)?;
        if let Some(previous) = all_events.insert(digest.clone(), event.clone())
            && previous != *event
        {
            return frontier_rejected("accepted Event digest collision in replay checkpoint");
        }
    }

    let seal_store = MemorySealStore::default();
    let cell_store = MemoryCellStore::default();
    let mut live_suites = BTreeMap::new();
    let checkpoint_order = replay_seal_set(
        &checkpoint.accepted_seals,
        &all_events,
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
    let base_leaves = seal_store
        .list_leaves(expected_realm)
        .await
        .map_err(replay_store_error)?;
    if canonical_seal_set(&base_leaves) != canonical_seal_set(&checkpoint.basis.leaves) {
        return frontier_rejected("replayed checkpoint leaf set does not equal its pinned basis");
    }
    if live_digest_suite_at_basis(&checkpoint.basis, &live_suites)? != checkpoint.live_digest_suite
    {
        return frontier_rejected(
            "replayed checkpoint live digest suite does not equal its pinned value",
        );
    }

    let mut new_seals = Vec::new();
    for seal in resolved_seals {
        match seal_store.get(&seal.id).await.map_err(replay_store_error)? {
            Some(previous) if previous != *seal => {
                return frontier_rejected("proof Seal conflicts with the retained checkpoint");
            }
            Some(_) => {}
            None => new_seals.push(seal.clone()),
        }
    }
    let new_order = replay_seal_set(
        &new_seals,
        &all_events,
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
    )
    .await?;
    let target_leaves = seal_store
        .list_leaves(expected_realm)
        .await
        .map_err(replay_store_error)?;
    if canonical_seal_set(&target_leaves) != canonical_seal_set(&target_basis.leaves) {
        return frontier_rejected("replayed target leaf set does not equal the query target basis");
    }

    let mut accepted_seals = checkpoint_order;
    accepted_seals.extend(new_order);
    Ok((
        seal_store,
        cell_store,
        accepted_seals,
        all_events.into_values().collect(),
        live_suites,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn replay_seal_set<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    seals: &[Seal],
    all_events: &dyn ReplayEventLookup,
    event_store: &MemoryControlEventStore,
    seal_store: &MemorySealStore,
    cell_store: &MemoryCellStore,
    dependencies: &[GovernanceDependency],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
    live_suites: &mut BTreeMap<SealId, DigestSuite>,
) -> arkret_wire::Result<Vec<Seal>>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let mut pending = seals
        .iter()
        .cloned()
        .map(|seal| (seal.id.clone(), seal))
        .collect::<BTreeMap<_, _>>();
    if pending.len() != seals.len() {
        return frontier_rejected("replay Seal set contains duplicate ids");
    }
    let mut ordered = Vec::with_capacity(seals.len());
    while !pending.is_empty() {
        let mut ready = Vec::new();
        for (id, seal) in &pending {
            if seal_store
                .predecessors_known(&seal.predecessor_refs)
                .await
                .unwrap_or(false)
            {
                ready.push(id.clone());
            }
        }
        if ready.is_empty() {
            return frontier_rejected("replay Seal set has a missing predecessor or cycle");
        }
        for id in ready {
            let seal = pending
                .remove(&id)
                .expect("ready Seal remains in the pending map");
            replay_one_seal(
                &seal,
                all_events,
                event_store,
                seal_store,
                cell_store,
                dependencies,
                registry,
                verify_seal_signature,
                verify_event_proofs.clone(),
                verify_seal_dependencies,
                project_writes,
                live_suites,
            )
            .await?;
            ordered.push(seal);
        }
    }
    Ok(ordered)
}

/// Apply exactly one already-discovered Seal through the standard `apply_seal`
/// path. Every caller of the reducer — near-current frontier replay and
/// disk-backed direct traversal alike — funnels through this function so there
/// is only one implementation of notary selection, delta admission, root
/// recomputation and Bottom/recovery.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn replay_one_seal<
    VerifySealSignature,
    VerifyEventProofs,
    VerifySealDependencies,
    ProjectWrites,
>(
    seal: &Seal,
    all_events: &dyn ReplayEventLookup,
    event_store: &MemoryControlEventStore,
    seal_store: &MemorySealStore,
    cell_store: &MemoryCellStore,
    dependencies: &[GovernanceDependency],
    registry: &dyn CellRegistry,
    verify_seal_signature: VerifySealSignature,
    verify_event_proofs: VerifyEventProofs,
    verify_seal_dependencies: VerifySealDependencies,
    project_writes: ProjectWrites,
    live_suites: &mut BTreeMap<SealId, DigestSuite>,
) -> arkret_wire::Result<()>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
    VerifyEventProofs: for<'a> Fn(
            &'a Event,
            DigestSuite,
            &'a [GovernanceDependency],
        ) -> VerifyEventProofsFuture<'a>
        + Clone,
    VerifySealDependencies: Fn(
            &Seal,
            &NotaryValue,
            &SealDependencyReplayContext,
            &[GovernanceDependency],
        ) -> arkret_wire::Result<()>
        + Copy,
    ProjectWrites: Fn(&Event, DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let digest_suites = digest_suites_for_replay_seal(seal, all_events, live_suites).await?;
    for digest in &seal.delta {
        let event = all_events.event(digest).await?.ok_or_else(|| {
            WireError::Protocol("replay Seal delta Event is unresolved".to_owned())
        })?;
        let event_digest_suite = if seal.predecessor_refs.is_empty()
            && event.kind == arkret_wire::EventKind::RealmCreate
        {
            DigestSuite::Sha256
        } else {
            digest_suites.event_digest_suite
        };
        let inserted = event_store
            .insert_verified_replay_event_with_digest_suite(&event, event_digest_suite)
            .map_err(replay_store_error)?;
        if &inserted != digest {
            return frontier_rejected(
                "replay Seal delta does not match the Event's verified historical suite",
            );
        }
    }
    let (notary, predecessor_state) =
        predecessor_notary_and_state(seal, all_events, seal_store, cell_store, registry).await?;
    verify_notary_authority(
        seal,
        &notary,
        digest_suites.seal_digest_suite,
        verify_seal_signature,
    )?;
    let dependency_context = seal_dependency_replay_context(
        seal,
        &predecessor_state,
        all_events,
        seal_store,
        cell_store,
        digest_suites,
    )
    .await?;
    verify_seal_dependencies(seal, &notary, &dependency_context, dependencies)?;

    for digest in &seal.delta {
        let event = all_events.event(digest).await?.ok_or_else(|| {
            WireError::Protocol("replay Seal delta Event is unresolved".to_owned())
        })?;
        let event_digest_suite = if seal.predecessor_refs.is_empty()
            && event.kind == arkret_wire::EventKind::RealmCreate
        {
            DigestSuite::Sha256
        } else {
            digest_suites.event_digest_suite
        };
        verify_event_proofs(&event, event_digest_suite, dependencies).await?;
    }

    apply_replayed_seal_in_context(
        seal,
        event_store,
        seal_store,
        cell_store,
        registry,
        digest_suites,
        |_, _| Ok(()),
        project_writes,
        if seal.predecessor_refs.is_empty() {
            EventSubmitContext::AnchorUnit
        } else {
            EventSubmitContext::Standard
        },
    )
    .await
    .map_err(replay_reject_error)?;
    let mut covered = union_predecessor_covered_events(&seal.predecessor_refs, seal_store)
        .await
        .map_err(replay_reject_error)?;
    covered.extend(seal.delta.iter().cloned());
    let mut covered_events = Vec::with_capacity(covered.len());
    for digest in &covered {
        let event = event_store
            .get(digest)
            .await
            .map_err(replay_store_error)?
            .ok_or_else(|| {
                WireError::Protocol(
                    "Seal completeness Event is absent from the replay closure".to_owned(),
                )
            })?;
        let event_digest_suite = event_store
            .digest_suite(digest)
            .await
            .map_err(replay_store_error)?
            .ok_or_else(|| {
                WireError::Protocol("Seal completeness Event has no frozen digest suite".to_owned())
            })?;
        covered_events.push((event, event_digest_suite));
    }
    let completeness =
        control_event_completeness_root(&covered_events, &covered, digest_suites.seal_digest_suite)
            .map_err(replay_reject_error)?;
    if completeness != seal.completeness_root {
        return frontier_rejected("Seal completeness_root does not match replayed Events");
    }
    live_suites.insert(seal.id.clone(), digest_suites.seal_digest_suite);
    Ok(())
}

async fn digest_suites_for_replay_seal(
    seal: &Seal,
    all_events: &dyn ReplayEventLookup,
    live_suites: &BTreeMap<SealId, DigestSuite>,
) -> arkret_wire::Result<SealDigestSuites> {
    if seal.predecessor_refs.is_empty() {
        let mut declared = None;
        for digest in &seal.delta {
            let event = all_events.event(digest).await?.ok_or_else(|| {
                WireError::Protocol("genesis Seal delta Event is unresolved".to_owned())
            })?;
            if event.kind != arkret_wire::EventKind::RealmCreate {
                continue;
            }
            let suite: DigestSuite = serde_json::from_value(
                event
                    .payload
                    .get("object")
                    .and_then(|object| object.get("digest_algorithm"))
                    .cloned()
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "Realm create Event omits object.digest_algorithm".to_owned(),
                        )
                    })?,
            )?;
            if declared.replace(suite).is_some() {
                return frontier_rejected("genesis Seal contains multiple Realm create Events");
            }
        }
        return declared.map(SealDigestSuites::standard).ok_or_else(|| {
            WireError::Protocol("genesis Seal contains no Realm create Event".to_owned())
        });
    }

    let mut predecessor_suite = None;
    for predecessor in &seal.predecessor_refs {
        let suite = live_suites.get(predecessor).copied().ok_or_else(|| {
            WireError::Protocol("replay Seal predecessor has no verified digest suite".to_owned())
        })?;
        if predecessor_suite.is_some_and(|previous| previous != suite) {
            return frontier_rejected("replay Seal predecessor digest-suite join is Bottom");
        }
        predecessor_suite = Some(suite);
    }
    let from = predecessor_suite.expect("non-genesis Seal has at least one predecessor");
    let mut transitions = Vec::new();
    for digest in &seal.delta {
        if let Some(event) = all_events.event(digest).await?
            && event.kind == arkret_wire::EventKind::RealmDigestSuiteTransition
        {
            transitions.push(event);
        }
    }
    match transitions.as_slice() {
        [] => Ok(SealDigestSuites::standard(from)),
        [event] => {
            let declared_from: DigestSuite = serde_json::from_value(
                event
                    .payload
                    .get("from_digest_algorithm")
                    .cloned()
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "digest-suite transition omits from_digest_algorithm".to_owned(),
                        )
                    })?,
            )?;
            let to: DigestSuite = serde_json::from_value(
                event
                    .payload
                    .get("to_digest_algorithm")
                    .cloned()
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "digest-suite transition omits to_digest_algorithm".to_owned(),
                        )
                    })?,
            )?;
            if declared_from != from {
                return frontier_rejected(
                    "digest-suite transition does not match the verified predecessor suite",
                );
            }
            Ok(SealDigestSuites::transition(from, to))
        }
        _ => frontier_rejected("replay Seal contains multiple digest-suite transitions"),
    }
}

pub(crate) fn live_digest_suite_at_basis(
    basis: &SealBasis,
    live_suites: &BTreeMap<SealId, DigestSuite>,
) -> arkret_wire::Result<DigestSuite> {
    let mut joined = None;
    for leaf in &basis.leaves {
        let suite = live_suites.get(leaf).copied().ok_or_else(|| {
            WireError::Protocol("basis leaf has no verified digest suite".to_owned())
        })?;
        if joined.is_some_and(|previous| previous != suite) {
            return frontier_rejected("basis live digest-suite join is Bottom");
        }
        joined = Some(suite);
    }
    joined.ok_or_else(|| WireError::Protocol("basis contains no leaves".to_owned()))
}

async fn predecessor_notary_and_state(
    seal: &Seal,
    all_events: &dyn ReplayEventLookup,
    seal_store: &MemorySealStore,
    cell_store: &MemoryCellStore,
    registry: &dyn CellRegistry,
) -> arkret_wire::Result<(NotaryValue, BTreeMap<CellRef, CellState>)> {
    if seal.predecessor_refs.is_empty() {
        let mut create_notary = None;
        for digest in &seal.delta {
            let Some(event) = all_events.event(digest).await? else {
                continue;
            };
            if event.kind.as_str() == arkret_wire::event_kind_str::REALM_CREATE {
                let value = event
                    .payload
                    .get("object")
                    .and_then(|object| object.get("notary"))
                    .ok_or_else(|| {
                        WireError::Protocol("Realm create payload omits notary".to_owned())
                    })?;
                let notary: NotaryValue = serde_json::from_value(value.clone())?;
                if create_notary.replace(notary).is_some() {
                    return frontier_rejected("genesis Seal contains multiple Realm create Events");
                }
            }
        }
        return create_notary
            .map(|notary| (notary, BTreeMap::new()))
            .ok_or_else(|| {
                WireError::Protocol("genesis Seal has no Realm create Event".to_owned())
            });
    }

    let state = effective_state_at(
        &seal.predecessor_refs,
        &seal.realm_id,
        seal_store,
        cell_store,
        registry,
    )
    .await
    .map_err(replay_reject_error)?;
    let mut notary = None;
    for (cell, value) in &state {
        let cell_id = CellId::from_ref(cell)?;
        if cell_id.component() != arkret_wire::CellFamilyId::NOTARY_V1 {
            continue;
        }
        let CellState::Value(value) = value else {
            return frontier_rejected("predecessor joined notary state is Bottom");
        };
        let parsed: NotaryValue = serde_json::from_value(value.clone())?;
        if notary.replace(parsed).is_some() {
            return frontier_rejected("predecessor view contains multiple notary cells");
        }
    }
    notary
        .map(|notary| (notary, state))
        .ok_or_else(|| WireError::Protocol("predecessor view has no notary state".to_owned()))
}

pub async fn derive_seal_dependency_replay_context(
    seal: &Seal,
    predecessor_state: &BTreeMap<CellRef, CellState>,
    all_events: &dyn ReplayEventLookup,
    seal_store: &dyn SealStore,
    cell_store: &dyn CellStore,
    digest_suites: SealDigestSuites,
) -> arkret_wire::Result<SealDependencyReplayContext> {
    seal_dependency_replay_context(
        seal,
        predecessor_state,
        all_events,
        seal_store,
        cell_store,
        digest_suites,
    )
    .await
}

async fn seal_dependency_replay_context(
    seal: &Seal,
    predecessor_state: &BTreeMap<CellRef, CellState>,
    all_events: &dyn ReplayEventLookup,
    seal_store: &dyn SealStore,
    cell_store: &dyn CellStore,
    digest_suites: SealDigestSuites,
) -> arkret_wire::Result<SealDependencyReplayContext> {
    let mut availability_policy = None;
    for (cell, state) in predecessor_state {
        let cell_id = CellId::from_ref(cell)?;
        if cell_id.component() != arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1 {
            continue;
        }
        let CellState::Value(value) = state else {
            return frontier_rejected("predecessor Realm policy bundle is Bottom");
        };
        let bundle: RealmPolicyBundlePayload = serde_json::from_value(value.clone())?;
        if availability_policy
            .replace(bundle.availability_policy.unwrap_or_default())
            .is_some()
        {
            return frontier_rejected("predecessor view has multiple Realm policy bundle cells");
        }
    }
    let mut event_digest_suites = BTreeMap::new();
    for digest in &seal.delta {
        let event = all_events
            .event(digest)
            .await?
            .ok_or_else(|| WireError::Protocol("Seal dependency Event is unresolved".to_owned()))?;
        let suite = if seal.predecessor_refs.is_empty()
            && event.kind == arkret_wire::EventKind::RealmCreate
        {
            DigestSuite::Sha256
        } else {
            digest_suites.event_digest_suite
        };
        event_digest_suites.insert(digest.clone(), suite);
    }
    let mut context = SealDependencyReplayContext {
        event_digest_suites,
        seal_digest_suite: digest_suites.seal_digest_suite,
        availability_authority: if seal.predecessor_refs.is_empty() {
            SealAvailabilityReplayAuthority::Genesis
        } else {
            SealAvailabilityReplayAuthority::Predecessor {
                policy: availability_policy.unwrap_or_default(),
                eligible_holder_service_ids: BTreeSet::new(),
            }
        },
    };
    if !seal.predecessor_refs.is_empty()
        && !add_pcr_holder_from_verified_create_anchor(seal, all_events, seal_store, &mut context)
            .await?
    {
        let covered = union_predecessor_covered_events(&seal.predecessor_refs, seal_store)
            .await
            .map_err(replay_reject_error)?;
        for (cell, state) in predecessor_state {
            let cell_id = CellId::from_ref(cell)?;
            if cell_id.component() != arkret_wire::CellFamilyId::MEMBER_STATE_V1
                || !matches!(state, CellState::Value(value) if value.as_str() == Some("join"))
            {
                continue;
            }
            let covered_ops = cell_store
                .sealed_ops_for_cell(&seal.realm_id, cell)
                .await
                .map_err(replay_store_error)?
                .into_iter()
                .filter(|issued| covered.contains(&issued.op.move_id))
                .collect::<Vec<_>>();
            let winning_join = winning_membership_join(&covered_ops)?;
            let event = all_events.event(&winning_join).await?.ok_or_else(|| {
                WireError::Protocol("winning membership Event is unresolved".to_owned())
            })?;
            add_joined_holder_from_event(&event, &mut context)?;
        }
    }
    Ok(context)
}

async fn add_pcr_holder_from_verified_create_anchor(
    seal: &Seal,
    all_events: &dyn ReplayEventLookup,
    seal_store: &dyn SealStore,
    context: &mut SealDependencyReplayContext,
) -> arkret_wire::Result<bool> {
    let genesis_id = seal_store
        .genesis(&seal.realm_id)
        .await
        .map_err(replay_store_error)?
        .ok_or_else(|| {
            WireError::Protocol("predecessor closure has no Realm genesis Seal".to_owned())
        })?;
    let genesis = seal_store
        .get(&genesis_id)
        .await
        .map_err(replay_store_error)?
        .ok_or_else(|| {
            WireError::Protocol("indexed Realm genesis Seal is unresolved".to_owned())
        })?;
    if genesis.realm_id != seal.realm_id || !genesis.predecessor_refs.is_empty() {
        return frontier_rejected("indexed Realm genesis Seal is not the verified create anchor");
    }
    let mut create = None;
    for digest in &genesis.delta {
        let event = all_events.event(digest).await?.ok_or_else(|| {
            WireError::Protocol("genesis create-anchor Event is unresolved".to_owned())
        })?;
        if event.kind != arkret_wire::EventKind::RealmCreate {
            continue;
        }
        if create.replace(event).is_some() {
            return frontier_rejected(
                "genesis create anchor contains multiple Realm create Events",
            );
        }
    }
    let Some(create) = create else {
        return frontier_rejected("genesis create anchor has no Realm create Event");
    };
    let payload: RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&create.payload)?)?;
    if !matches!(
        payload.object.purpose,
        RealmPurpose::PrincipalControl
            | RealmPurpose::AgentControl
            | RealmPurpose::AppletManagedControl
    ) {
        return Ok(false);
    }
    create
        .validate_station_admission_binding(DigestSuite::Sha256)
        .map_err(|error| {
            WireError::Protocol(format!(
                "MLS governance frontier rejected (state_mismatch): PCR create Station admission binding is invalid: {error}"
            ))
        })?;
    let SealAvailabilityReplayAuthority::Predecessor {
        eligible_holder_service_ids,
        ..
    } = &mut context.availability_authority
    else {
        return frontier_rejected("genesis replay cannot acquire PCR availability holder");
    };
    eligible_holder_service_ids.insert(create.actor_id.route_service_id().clone());
    Ok(true)
}

fn winning_membership_join(
    covered_ops: &[crate::lattice::ordered_log::IssuedOp],
) -> arkret_wire::Result<Hash> {
    let covered_ops = covered_ops
        .iter()
        .rposition(|issued| issued.op.recovery_reset)
        .map_or(covered_ops, |boundary| &covered_ops[boundary..]);
    let mut current = Value::String("leave".to_owned());
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut winning_join = None;
    for issued in covered_ops {
        let from = issued.op.op.from.as_ref().and_then(Value::as_str);
        let to = issued.op.op.to.as_ref().and_then(Value::as_str);
        let (Some(from), Some(to)) = (from, to) else {
            return Err(WireError::Protocol(
                "membership cell contains a non-transition operation".to_owned(),
            ));
        };
        let transition = (from.to_owned(), to.to_owned());
        if seen.contains(&transition) {
            continue;
        }
        if seen
            .iter()
            .any(|(seen_from, seen_to)| seen_from == from && seen_to != to)
            || current.as_str() != Some(from)
        {
            return Err(WireError::Protocol(
                "membership operation history does not resolve to the effective FSM value"
                    .to_owned(),
            ));
        }
        seen.insert(transition);
        current = Value::String(to.to_owned());
        winning_join = (to == "join").then(|| issued.op.move_id.clone());
    }
    winning_join.ok_or_else(|| {
        WireError::Protocol("joined member cell has no effective join Event".to_owned())
    })
}

fn add_joined_holder_from_event(
    event: &Event,
    context: &mut SealDependencyReplayContext,
) -> arkret_wire::Result<()> {
    if event.kind.as_str() != arkret_wire::event_kind_str::MEMBER_STATE {
        return Ok(());
    }
    let payload: MembershipPayload = serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    if payload.membership != MembershipPayloadState::Join {
        return Ok(());
    }
    let SealAvailabilityReplayAuthority::Predecessor {
        eligible_holder_service_ids,
        ..
    } = &mut context.availability_authority
    else {
        return Err(WireError::Protocol(
            "genesis replay cannot acquire predecessor availability holders".to_owned(),
        ));
    };
    eligible_holder_service_ids.insert(payload.member_id.route_service_id().clone());
    Ok(())
}

fn verify_notary_authority<VerifySealSignature>(
    seal: &Seal,
    notary: &NotaryValue,
    digest_suite: DigestSuite,
    verify_signature: VerifySealSignature,
) -> arkret_wire::Result<()>
where
    VerifySealSignature: Fn(&SealSignature, &NotarySignerDescriptor, &[u8], DigestSuite) -> arkret_wire::Result<()>
        + Copy,
{
    notary.validate()?;
    seal.validate_signature_payload_digests(|bytes| {
        Hash::new(arkret_canonical::digest(digest_suite, bytes)).map_err(Into::into)
    })?;
    let signatures = match &seal.notary_signature {
        NotarySig::Single(signature) => std::slice::from_ref(signature),
        NotarySig::Multi(multi) => multi.signatures.as_slice(),
    };
    let methods = signatures
        .iter()
        .map(|signature| signature.verification_method.clone())
        .collect::<BTreeSet<_>>();
    if methods.len() != signatures.len() || !notary.proposal_quorum_met(&methods) {
        return frontier_rejected("Seal signature set does not satisfy predecessor notary quorum");
    }
    let body = seal.canonical_bytes_for_id()?;
    for signature in signatures {
        let descriptor = notary
            .signer_descriptor(&signature.verification_method)
            .ok_or_else(|| {
                WireError::Protocol("Seal signer is absent from predecessor notary".to_owned())
            })?;
        signature.validate_descriptor_binding(descriptor)?;
        verify_signature(signature, descriptor, &body, digest_suite)?;
    }
    Ok(())
}

fn canonical_seal_set(values: &[SealId]) -> BTreeSet<SealId> {
    values.iter().cloned().collect()
}

fn replay_store_error(error: crate::StoreError) -> WireError {
    WireError::Protocol(format!("MLS governance checkpoint store error: {error}"))
}

fn replay_reject_error(error: crate::SealReject) -> WireError {
    WireError::Protocol(format!("MLS governance replay rejected: {error}"))
}

async fn verify_frontier_entry(
    entry: &MlsGovernanceFrontierCellEntry,
    seals: &BTreeMap<SealId, &Seal>,
    events: &BTreeMap<EventId, &Event>,
    seal_store: &MemorySealStore,
    cell_store: &MemoryCellStore,
    registry: &dyn CellRegistry,
    digest_suite: DigestSuite,
) -> arkret_wire::Result<Value> {
    let witness = &entry.inclusion_witness;
    if witness.root_field != MlsGovernanceMerkleRootField::StateRoot {
        return frontier_rejected("frontier cell entry must use a state_root witness");
    }
    let seal = seals.get(&witness.root_seal_ref).ok_or_else(|| {
        WireError::Protocol("frontier witness names an unresolved Seal".to_owned())
    })?;
    let signed_root = match witness.root_field {
        MlsGovernanceMerkleRootField::StateRoot => &seal.state_root,
        MlsGovernanceMerkleRootField::ControlEventSetRoot => &seal.control_event_set_root,
    };
    if signed_root != &witness.root_digest
        || !verify_state_inclusion_proof(
            &witness.leaf_digest,
            witness.leaf_index,
            witness.leaf_count,
            &witness.siblings,
            signed_root,
            digest_suite,
        )?
    {
        return frontier_rejected("frontier Merkle witness does not match its signed Seal root");
    }
    let preimage =
        arkret_canonical::base64url_decode(witness.leaf_canonical_preimage_b64u.as_str())?;
    let preimage_value: Value = serde_json::from_slice(&preimage).map_err(|error| {
        WireError::Protocol(format!("invalid state leaf preimage JSON: {error}"))
    })?;
    if arkret_canonical::canonical_json_bytes(&preimage_value)? != preimage {
        return frontier_rejected("state leaf preimage is not RFC 8785 canonical JSON");
    }
    let object = preimage_value
        .as_object()
        .ok_or_else(|| WireError::Protocol("state leaf preimage must be an object".to_owned()))?;
    if object.len() != 2 || object.get("cell") != Some(&json!(entry.cell_id.as_str())) {
        return frontier_rejected("state leaf preimage names a different cell");
    }
    let state = object
        .get("state")
        .and_then(Value::as_object)
        .ok_or_else(|| WireError::Protocol("state leaf preimage has no state object".to_owned()))?;
    if state.len() != 1 {
        return frontier_rejected("state leaf preimage state is not closed");
    }
    let value = state.get("value").ok_or_else(|| {
        WireError::Protocol("state leaf preimage is Bottom or missing value".to_owned())
    })?;
    if state_value_leaf_digest(&entry.cell_id, value, digest_suite)? != witness.leaf_digest
        || canonical_hash(value)? != entry.value_digest
    {
        return frontier_rejected("frontier value digest does not bind the state leaf value");
    }
    let provenance = entry
        .provenance_event_refs
        .iter()
        .map(|event_id| {
            events.get(event_id).copied().ok_or_else(|| {
                WireError::Protocol("unresolved frontier provenance Event".to_owned())
            })
        })
        .collect::<arkret_wire::Result<Vec<_>>>()?;

    let root_state = effective_state_at(
        std::slice::from_ref(&witness.root_seal_ref),
        &seal.realm_id,
        seal_store,
        cell_store,
        registry,
    )
    .await
    .map_err(replay_reject_error)?;
    let Some(CellState::Value(reduced)) = root_state.get(&entry.cell_id) else {
        return frontier_rejected("replayed root has no concrete value for the frontier cell");
    };
    if reduced != value {
        return frontier_rejected(
            "ordinary reducer projection disagrees with the signed state leaf",
        );
    }

    let covered =
        union_predecessor_covered_events(std::slice::from_ref(&witness.root_seal_ref), seal_store)
            .await
            .map_err(replay_reject_error)?;
    let replayed_provenance = cell_store
        .sealed_ops_for_cell(&seal.realm_id, &entry.cell_id)
        .await
        .map_err(replay_store_error)?
        .into_iter()
        .filter(|issued| covered.contains(&issued.op.move_id))
        .map(|issued| issued.op.move_id)
        .collect::<BTreeSet<_>>();
    let declared_provenance = provenance
        .into_iter()
        .map(claimed_event_digest)
        .collect::<arkret_wire::Result<BTreeSet<_>>>()?;
    if replayed_provenance != declared_provenance {
        return frontier_rejected(
            "frontier provenance is not every-and-only the replayed cell write chain",
        );
    }
    Ok(reduced.clone())
}

#[allow(clippy::too_many_arguments)]
async fn verify_branch_entry_closure(
    branch: &MlsGovernanceFrontierBranchProjection,
    realm_id: &RealmId,
    seal_store: &MemorySealStore,
    cell_store: &MemoryCellStore,
    registry: &dyn CellRegistry,
    scope: &ScopeRef,
    leaf_actors: &BTreeSet<ActorId>,
    leaf_credentials: &BTreeSet<String>,
    group_genesis_binding: &MlsGroupGenesisBinding,
) -> arkret_wire::Result<()> {
    let state = effective_state_at(
        std::slice::from_ref(&branch.target_seal_ref),
        realm_id,
        seal_store,
        cell_store,
        registry,
    )
    .await
    .map_err(replay_reject_error)?;
    let mut expected = BTreeSet::new();
    for (cell, state) in state {
        let cell_id = CellId::from_ref(&cell)?;
        if !registered_frontier_family(cell_id.component()) {
            continue;
        }
        let CellState::Value(value) = state else {
            return frontier_rejected("target branch security-frontier cell is Bottom");
        };
        if project_frontier_value(
            cell_id.component(),
            &value,
            scope,
            leaf_actors,
            leaf_credentials,
            &cell_id,
            group_genesis_binding,
        )?
        .is_some()
        {
            expected.insert(cell);
        }
    }
    let supplied = branch
        .cells
        .iter()
        .map(|entry| entry.cell_id.clone())
        .collect::<BTreeSet<_>>();
    if expected != supplied || supplied.len() != branch.cells.len() {
        return frontier_rejected(
            "frontier branch entries are not every-and-only the registered projection",
        );
    }
    Ok(())
}

fn registered_frontier_family(family: &str) -> bool {
    crate::generated::mls_security_frontier::MLS_SECURITY_FRONTIER_CELL_FAMILIES
        .binary_search_by(|candidate| candidate.as_bytes().cmp(family.as_bytes()))
        .is_ok()
}

fn verify_frontier_span_coverage(
    branch: &MlsGovernanceFrontierBranchProjection,
) -> arkret_wire::Result<()> {
    let mut coverage = BTreeMap::<&CellRef, usize>::new();
    for range in &branch.range_witnesses {
        let entries = branch
            .cells
            .iter()
            .filter(|entry| {
                CellId::from_ref(&entry.cell_id).is_ok_and(|cell| {
                    cell.component() == range.cell_family
                        && cell.subject().starts_with(&range.subject_prefix)
                })
            })
            .collect::<Vec<_>>();
        let indices = entries
            .iter()
            .map(|entry| entry.inclusion_witness.leaf_index)
            .collect::<Vec<_>>();
        if indices != range.included_entry_indices
            || entries.iter().any(|entry| {
                entry.inclusion_witness.leaf_count != range.leaf_count
                    || entry.inclusion_witness.root_digest != branch.state_root
                    || entry.inclusion_witness.root_seal_ref != branch.target_seal_ref
            })
        {
            return frontier_rejected(
                "frontier range does not exactly cover its disclosed entries",
            );
        }
        for entry in entries {
            *coverage.entry(&entry.cell_id).or_default() += 1;
        }
        verify_boundary_coordinates(range, true)?;
        verify_boundary_coordinates(range, false)?;
    }
    if coverage.len() != branch.cells.len() || coverage.values().any(|count| *count != 1) {
        return frontier_rejected("frontier entries are not covered by exactly one range witness");
    }
    Ok(())
}

fn verify_boundary_coordinates(
    range: &MlsGovernanceFrontierRangeWitness,
    left: bool,
) -> arkret_wire::Result<()> {
    let boundary = if left {
        &range.left_boundary
    } else {
        &range.right_boundary
    };
    let edge_expected = if left {
        range.start_index == 0
    } else {
        range.end_index_exclusive == range.leaf_count
    };
    if boundary.state_edge != edge_expected {
        return frontier_rejected("frontier boundary state-edge coordinate mismatch");
    }
    if let Some(entry) = &boundary.entry {
        let expected_index = if left {
            range.start_index.checked_sub(1)
        } else {
            Some(range.end_index_exclusive)
        };
        if Some(entry.inclusion_witness.leaf_index) != expected_index
            || entry.inclusion_witness.leaf_count != range.leaf_count
        {
            return frontier_rejected("frontier boundary is not adjacent to the selected range");
        }
        let boundary_cell = CellId::from_ref(&entry.cell_id)?;
        if boundary_cell.component() == range.cell_family
            && boundary_cell.subject().starts_with(&range.subject_prefix)
        {
            return frontier_rejected("frontier boundary remains inside the selected prefix");
        }
        let selected_edge = if left {
            range.included_entry_indices.first()
        } else {
            range.included_entry_indices.last()
        };
        if selected_edge.is_some_and(|selected| {
            if left {
                entry.inclusion_witness.leaf_index >= *selected
            } else {
                entry.inclusion_witness.leaf_index <= *selected
            }
        }) {
            return frontier_rejected(
                "frontier boundary order does not enclose the selected range",
            );
        }
    }
    Ok(())
}

fn canonical_leaf_set(
    leaves: &[MlsSecurityFrontierLeaf],
) -> arkret_wire::Result<(Vec<Value>, BTreeSet<ActorId>, BTreeSet<String>)> {
    let mut encoded = leaves
        .iter()
        .map(|leaf| {
            let value = serde_json::to_value(leaf)?;
            Ok((
                arkret_canonical::canonical_json_bytes(&value)?,
                value,
                leaf.actor_id.clone(),
                leaf.credential_ref.to_string(),
                leaf.leaf_index,
            ))
        })
        .collect::<arkret_wire::Result<Vec<_>>>()?;
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return frontier_rejected("MLS frontier leaf set contains duplicates");
    }
    let mut indexes = BTreeSet::new();
    let mut principals = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    for (_, _, principal, credential, index) in &encoded {
        if !indexes.insert(*index) || !credentials.insert(credential.clone()) {
            return frontier_rejected("MLS frontier leaf indexes or credentials are duplicate");
        }
        principals.insert(principal.clone());
    }
    Ok((
        encoded.into_iter().map(|(_, value, ..)| value).collect(),
        principals,
        credentials,
    ))
}

fn project_frontier_value(
    family: &str,
    value: &Value,
    scope: &ScopeRef,
    leaf_actors: &BTreeSet<ActorId>,
    leaf_credentials: &BTreeSet<String>,
    cell_id: &CellId,
    group_genesis_binding: &MlsGroupGenesisBinding,
) -> arkret_wire::Result<Option<Value>> {
    let registered = crate::generated::mls_security_frontier::MLS_SECURITY_FRONTIER_CELL_FAMILIES
        .binary_search_by(|candidate| candidate.as_bytes().cmp(family.as_bytes()))
        .is_ok();
    if !registered {
        return frontier_rejected("proof contains an unregistered security-frontier cell family");
    }
    let subject = decoded_cell_subject(cell_id)?;
    match family {
        arkret_wire::CellFamilyId::MEMBER_STATE_V1 => {
            let registry_subject = subject_single_string(&subject)?;
            if matches!(scope, ScopeRef::Circle { .. }) {
                let mut selected = false;
                for actor in leaf_actors {
                    let expected = arkret_wire::cell::composite_subject(&[actor.canonical_key()?])?;
                    selected |= expected == registry_subject;
                }
                if !selected {
                    return Ok(None);
                }
            }
            Ok(project_membership(value))
        }
        arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1 => {
            let ScopeRef::Circle { circle_id, .. } = scope else {
                return Ok(None);
            };
            let mut selected = false;
            for actor in leaf_actors {
                let expected = arkret_wire::cell::composite_subject(&[
                    Value::String(circle_id.to_string()),
                    Value::String(actor.canonical_key()?),
                ])?;
                selected |= subject_single_string(&subject)? == expected;
            }
            if !selected {
                return Ok(None);
            }
            Ok(project_membership(value))
        }
        arkret_wire::CellFamilyId::AGENT_STATUS_V1 => {
            let principal = subject_single_string(&subject)?;
            if !leaf_actors
                .iter()
                .any(|actor| actor.signing_principal_id().as_str() == principal)
            {
                return Ok(None);
            }
            let status = scalar_or_field(value, &["status", "state"])?;
            Ok(Some(json!({"agent_id": principal, "status": status})))
        }
        arkret_wire::CellFamilyId::DEVICE_AUTHORIZATION_V1
        | arkret_wire::CellFamilyId::AGENT_KEY_V1 => {
            if leaf_credentials.iter().any(|credential| {
                value_contains_string(value, credential)
                    || subject_contains_string(&subject, credential)
            }) {
                Ok(Some(value.clone()))
            } else {
                Ok(None)
            }
        }
        arkret_wire::CellFamilyId::DEVICE_REANCHOR_V1 => {
            if leaf_actors.iter().any(|actor| {
                let principal = actor.signing_principal_id().as_str();
                value_contains_string(value, principal)
                    || subject_contains_string(&subject, principal)
            }) {
                Ok(Some(value.clone()))
            } else {
                Ok(None)
            }
        }
        arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1 => Ok(Some(project_fields(
            value,
            &[
                "content_encryption_floor",
                "metadata_encryption_floor",
                "media_service_decrypts",
            ],
        )?)),
        arkret_wire::CellFamilyId::REALM_ORGANIZATION_RECOVERY_KEY_V1 => {
            if group_genesis_binding.durability_policy
                != Some(DurabilityPolicy::OrganizationRecoveryKey)
            {
                return Ok(None);
            }
            Ok(Some(project_fields(
                value,
                &[
                    "recovery_key_id",
                    "key_agreement_ref",
                    "method_controller_principal_id",
                    "holder_service_id",
                    "holder_signing_ref",
                    "hpke_suite",
                    "frozen_public_key_b64u",
                    "accepted_key_evidence_ref",
                    "holder_trusted_basis",
                ],
            )?))
        }
        arkret_wire::CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1 => {
            Ok(Some(project_plaintext_visible_services(value)?))
        }
        arkret_wire::CellFamilyId::CIRCLE_CREATE_V1 => {
            if !matches!(scope, ScopeRef::Circle { .. }) {
                return Ok(None);
            }
            Ok(Some(project_fields(
                value,
                &["encryption_profile", "content_scheme", "durability_policy"],
            )?))
        }
        _ => frontier_rejected("registered MLS security-frontier cell family has no SDK projector"),
    }
}

fn project_membership(value: &Value) -> Option<Value> {
    let membership = value
        .as_str()
        .or_else(|| value.get("membership").and_then(Value::as_str))
        .or_else(|| value.get("state").and_then(Value::as_str))?;
    matches!(membership, "join" | "leave" | "ban").then(|| Value::String(membership.to_owned()))
}

fn scalar_or_field(value: &Value, fields: &[&str]) -> arkret_wire::Result<Value> {
    if value.is_string() || value.is_boolean() || value.is_number() || value.is_null() {
        return Ok(value.clone());
    }
    fields
        .iter()
        .find_map(|field| value.get(*field).cloned())
        .ok_or_else(|| {
            WireError::Protocol(
                "security-frontier state omits its projected status field".to_owned(),
            )
        })
}

fn project_fields(value: &Value, fields: &[&str]) -> arkret_wire::Result<Value> {
    let object = value.as_object().ok_or_else(|| {
        WireError::Protocol("security-frontier projected state must be an object".to_owned())
    })?;
    let mut projected = Map::new();
    for field in fields {
        if let Some(value) = object.get(*field) {
            projected.insert((*field).to_owned(), value.clone());
        }
    }
    Ok(Value::Object(projected))
}

fn project_plaintext_visible_services(value: &Value) -> arkret_wire::Result<Value> {
    let services = value
        .as_array()
        .or_else(|| value.get("services").and_then(Value::as_array))
        .ok_or_else(|| {
            WireError::Protocol("plaintext-visible services state must be an array".to_owned())
        })?;
    services
        .iter()
        .map(|service| project_fields(service, &["service_id", "principal_id", "data_classes"]))
        .collect::<arkret_wire::Result<Vec<_>>>()
        .map(Value::Array)
}

fn decoded_cell_subject(cell_id: &CellId) -> arkret_wire::Result<Value> {
    let parts = arkret_canonical::canonical::decode_state_subject_parts(cell_id.subject())?;
    if parts.len() == 1 {
        Ok(Value::String(parts[0].clone()))
    } else {
        Ok(Value::Array(parts.into_iter().map(Value::String).collect()))
    }
}

fn subject_single_string(subject: &Value) -> arkret_wire::Result<&str> {
    subject.as_str().ok_or_else(|| {
        WireError::Protocol(
            "security-frontier cell subject must contain one principal id".to_owned(),
        )
    })
}

fn subject_contains_string(subject: &Value, expected: &str) -> bool {
    subject.as_str() == Some(expected)
        || subject
            .as_array()
            .is_some_and(|parts| parts.iter().any(|part| part.as_str() == Some(expected)))
}

fn value_contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_string(value, expected)),
        _ => false,
    }
}

fn canonical_hash<T: Serialize>(value: &T) -> arkret_wire::Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
        value,
    )?)?)
}

fn frontier_rejected<T>(message: &str) -> arkret_wire::Result<T> {
    Err(WireError::Protocol(format!(
        "MLS governance frontier rejected (state_mismatch): {message}"
    )))
}

/// Admit a candidate Seal as the local trust anchor for an event-derived
/// Realm. The caller independently resolves both signed objects and verifies
/// the genesis notary signature against the create payload designation.
pub fn admit_event_derived_genesis_anchor<E, VerifyNotary>(
    realm_id: &RealmId,
    create_event: &Event,
    candidate: &Seal,
    verify_notary_signature: VerifyNotary,
) -> Result<SealId, E>
where
    E: From<WireError>,
    VerifyNotary: Fn(&Seal, &Value) -> Result<(), E>,
{
    let expected_create_id = realm_id.event_id();
    if create_event.event_id != expected_create_id {
        return Err(anchor_rejected(
            "candidate create Event is not the one realm_id retypes to",
        ));
    }
    if create_event.kind.as_str() != arkret_wire::event_kind_str::REALM_CREATE {
        return Err(anchor_rejected(
            "realm anchor must derive from ak.realm.create",
        ));
    }
    if create_event.derive_event_id_with_digest_suite(DigestSuite::Sha256)? != expected_create_id {
        return Err(anchor_rejected(
            "create Event content does not reproduce its content-bound event_id",
        ));
    }
    if &candidate.realm_id != realm_id {
        return Err(anchor_rejected("candidate anchor belongs to another Realm"));
    }
    if !candidate.predecessor_refs.is_empty() {
        return Err(anchor_rejected("candidate anchor is not a genesis Seal"));
    }
    let create_digest =
        Hash::new(create_event.event_digest_with_digest_suite(DigestSuite::Sha256)?)
            .map_err(WireError::from)?;
    if !candidate.delta.contains(&create_digest) {
        return Err(anchor_rejected(
            "candidate genesis Seal does not cover the Realm create Event",
        ));
    }
    let notary = create_event
        .payload
        .get("object")
        .and_then(|object| object.get("notary"))
        .ok_or_else(|| anchor_rejected::<E>("create payload carries no notary designation"))?;
    verify_notary_signature(candidate, notary)?;
    Ok(candidate.id.clone())
}

fn anchor_rejected<E: From<WireError>>(message: &str) -> E {
    E::from(WireError::Protocol(format!(
        "MLS governance anchor rejected (state_mismatch): {message}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn security_frontier_leaf_set_preserves_same_principal_at_distinct_stations() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let actor = |station: &str| {
            ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                DidCoreId::new(station).unwrap(),
            ))
        };
        let first = MlsSecurityFrontierLeaf {
            leaf_index: 0,
            actor_id: actor("ak:did_core:web:station-a.example"),
            credential_ref: arkret_wire::NonEmptyString::new("device-a").unwrap(),
        };
        let mut other_station = first.clone();
        other_station.actor_id = actor("ak:did_core:web:station-b.example");
        let (first_preimage, ..) = canonical_leaf_set(std::slice::from_ref(&first)).unwrap();
        let (other_preimage, ..) =
            canonical_leaf_set(std::slice::from_ref(&other_station)).unwrap();
        assert_ne!(
            canonical_hash(&first_preimage).unwrap(),
            canonical_hash(&other_preimage).unwrap()
        );
        other_station.leaf_index = 1;
        other_station.credential_ref = arkret_wire::NonEmptyString::new("device-b").unwrap();
        let (_, actors, _) = canonical_leaf_set(&[first, other_station]).unwrap();
        assert_eq!(actors.len(), 2);
    }

    #[tokio::test]
    async fn security_frontier_leaf_rejects_legacy_principal_only_shape() {
        assert!(
            serde_json::from_value::<MlsSecurityFrontierLeaf>(json!({
                "leaf_index": 0,
                "principal_id": "ak:did_core:web:alice.example",
                "credential_ref": "device-a"
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn circle_frontier_selects_realm_members_by_registry_subject_encoding() {
        let actor = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let registry_subject =
            arkret_wire::cell::composite_subject(&[actor.canonical_key().unwrap()]).unwrap();
        let cell = CellId::parse(&arkret_wire::cell::subject_cell(
            arkret_wire::CellFamilyId::MEMBER_STATE_V1,
            &registry_subject,
        ))
        .unwrap();
        let scope = ScopeRef::Circle {
            realm_id: RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5")
                .unwrap(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:AXy9G1HY-05VpUDBKqm77h_Vu7DiFOJ3sduNSXuFewp_",
            )
            .unwrap(),
        };
        let binding = MlsGroupGenesisBinding {
            content_scheme: ContentScheme::MlsRfc9420,
            durability_policy: None,
        };

        assert_eq!(
            project_frontier_value(
                arkret_wire::CellFamilyId::MEMBER_STATE_V1,
                &json!("join"),
                &scope,
                &BTreeSet::from([actor.clone()]),
                &BTreeSet::new(),
                &cell,
                &binding,
            )
            .unwrap(),
            Some(json!("join")),
        );
        let other = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        assert_eq!(
            project_frontier_value(
                arkret_wire::CellFamilyId::MEMBER_STATE_V1,
                &json!("join"),
                &scope,
                &BTreeSet::from([other]),
                &BTreeSet::new(),
                &cell,
                &binding,
            )
            .unwrap(),
            None,
        );
    }

    #[tokio::test]
    async fn materializer_state_leaf_preimage_matches_state_root_contract() {
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
                .unwrap();
        let value = json!({"accepted_event_id": "ak:event:one"});

        let preimage = canonical_state_leaf_preimage(&cell, &value).unwrap();
        assert_eq!(
            preimage,
            br#"{"cell":"ak:cell:ak.component.member.state.v1:did.web.alice.example","state":{"value":{"accepted_event_id":"ak:event:one"}}}"#,
        );

        let mut leaf_input = vec![0];
        leaf_input.extend_from_slice(&preimage);
        let emitted_leaf_digest =
            Hash::new(arkret_canonical::digest(DigestSuite::Sha256, &leaf_input)).unwrap();
        assert_eq!(
            emitted_leaf_digest,
            state_value_leaf_digest(&cell, &value, DigestSuite::Sha256).unwrap(),
        );
    }
}
