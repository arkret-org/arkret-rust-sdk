//! Agent Principal Control Realm: canonical control materialization
//! and the controller-signed Seal built from it.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::{RealmCreatePayload, RealmGenesis};
use arkret_models_identity::ResolutionCommitment;
use arkret_state::state_model::ordered_log::{IssuedOp, ensure_unique_ordered_log_slots};
use arkret_state::{
    CellStateRegistry, GovernanceView, OrderedControlUnit, OrderedControlUnitEvent,
    ResolvedCellState, compute_state_root, control_event_set_root, resolve_projected_write,
};
use arkret_wire::{
    ActorId, AuthorizationRef, CellRef, DidCoreId, EncryptionProfile, Event, EventCellExecution,
    EventKind, GenesisSalt, Hash, Hlc, NotaryValue, PayloadSigner, ProfileId, RealmId, Result,
    SchemaId, Seal, SealCommandOutcome, SecurityClass, TrustDomainId, UnsignedSeal, WireError,
    event_spec, project_did_to_core_id,
};
use chrono::{DateTime, Utc};

use crate::REALM_CREATE_CELL;
use crate::projection::{CellWriteProjector, direct_projection, validate_realm_create_projection};

/// The `ak.realm.create` Event's own digest suite.
///
/// `realm-and-space.md` §2.5.0 derives `realm_id = retype(event_id, "realm")`
/// and fixes the v1 Realm token header at `0x01`, so the genesis Event digest
/// is SHA-256 for every Realm regardless of the suite that Realm locks for the
/// rest of its history. This is the Realm-token contract, not a SHA-256
/// fallback: every non-create Event, every root and the Seal itself use the
/// suite the genesis declared.
const REALM_CREATE_EVENT_DIGEST_SUITE: arkret_canonical::DigestSuite =
    arkret_canonical::DigestSuite::Sha256;

/// Public inputs for the profile-closed Agent PCR Realm payload.
#[derive(Clone, Debug)]
pub struct AgentPcrCreatePayloadInput {
    pub agent_id: DidCoreId,
    pub controller_principal_id: DidCoreId,
    pub notary: NotaryValue,
    /// Exact, already accepted method-native inception position. The Agent
    /// PCR commits this immutable pre-binding head; the Realm service entry is
    /// published only by a later continuous DID update.
    pub initial_resolution: ResolutionCommitment,
    pub genesis_salt: GenesisSalt,
    pub trust_domain: TrustDomainId,
    /// The suite this Agent PCR locks at create time. `realm-genesis` uses the
    /// ordinary Realm digest enum; Agent PCRs have no SHA-256 exception.
    pub digest_suite: arkret_canonical::DigestSuite,
    pub created_at: DateTime<Utc>,
}

/// Build the canonical `ak.realm.create` payload for a Agent PCR.
pub fn build_agent_pcr_create_payload(
    input: AgentPcrCreatePayloadInput,
) -> Result<RealmCreatePayload> {
    if project_did_to_core_id(&input.initial_resolution.did)? != input.agent_id {
        return Err(WireError::Protocol(
            "Agent initial_resolution did does not project to agent_id".to_owned(),
        ));
    }
    input.notary.validate()?;
    if !notary_primary_projects_to_principal(&input.notary, &input.agent_id)? {
        return Err(WireError::Protocol(
            "Agent notary primary does not match agent_id".to_owned(),
        ));
    }
    let genesis = RealmGenesis::agent_control(
        input.genesis_salt,
        input.initial_resolution,
        input.trust_domain,
        vec![
            SchemaId::REALM_V1.to_owned(),
            ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
        ],
        arkret_wire::CORE_REDUCER_PROFILE,
        input.digest_suite,
        SecurityClass::HighAssurance,
        EncryptionProfile::MlsRfc9420,
        input.notary,
    )?;

    let payload = RealmCreatePayload::new(genesis);
    payload.to_value()?;
    Ok(payload)
}

fn notary_primary_projects_to_principal(
    notary: &NotaryValue,
    signing_principal_id: &DidCoreId,
) -> Result<bool> {
    Ok(notary.signer.actor_id.signing_principal_id() == signing_principal_id)
}

fn notary_primary_projects_to_actor(notary: &NotaryValue, actor_id: &ActorId) -> Result<bool> {
    notary_primary_projects_to_principal(notary, actor_id.signing_principal_id())
}

/// Complete reducer material needed to construct or validate a
/// controller-signed Agent PCR Event Seal.
#[derive(Clone, Debug)]
pub struct AgentPcrControlMaterial {
    pub realm_id: RealmId,
    pub agent_id: ActorId,
    pub controller_actor_id: ActorId,
    pub authorization_ref: AuthorizationRef,
    /// The founding notary profile, exactly as the accepted create declared it.
    pub notary: NotaryValue,
    /// The Realm's locked digest suite, taken from the authenticated genesis
    /// object. Every covered Event digest, root, Seal id and notary payload
    /// digest in this material was derived under it.
    pub digest_suite: arkret_canonical::DigestSuite,
    pub covered_event_digests: Vec<Hash>,
    pub state_root: Hash,
    pub command_results: Vec<SealCommandOutcome>,
    pub joined: BTreeMap<CellRef, ResolvedCellState>,
    /// Sealed effects with their issuer attached, ready for a store that
    /// must keep ordered-log slots keyed by the real actor.
    pub event_ops: Vec<(CellRef, IssuedOp)>,
}

fn event_digest_suite(
    event: &Event,
    realm_digest_suite: arkret_canonical::DigestSuite,
) -> arkret_canonical::DigestSuite {
    if event.kind == EventKind::RealmCreate {
        REALM_CREATE_EVENT_DIGEST_SUITE
    } else {
        realm_digest_suite
    }
}

/// Build the sole registered Agent PCR genesis unit from its create Event.
///
/// Accepted successor history must instead be expanded from signed Seal
/// command results with [`arkret_state::resolve_committed_ordered_control_units`].
pub fn agent_pcr_genesis_control_unit(create: &Event) -> Result<OrderedControlUnit> {
    if create.kind != EventKind::RealmCreate || create.seal_basis.is_some() {
        return Err(WireError::Protocol(
            "Agent PCR genesis unit requires one basis-less ak.realm.create Event".to_owned(),
        ));
    }
    let payload: RealmCreatePayload = create.typed_payload::<event_spec::RealmCreate>()?;
    let digest_suite = event_digest_suite(create, payload.object.digest_algorithm);
    let digest = Hash::new(create.event_digest_with_digest_suite(digest_suite)?)?;
    Ok(OrderedControlUnit {
        events: vec![OrderedControlUnitEvent {
            digest,
            event: create.clone(),
            digest_suite,
        }],
    })
}

/// Materialize the canonical control state of an Agent PCR from verified
/// registered units in confirmed Seal command order.
///
/// The caller must obtain `units` by expanding the accepted Seal chain's
/// signed `command_results[]`; Event actor sequence and `seal_basis` do not
/// determine command order. The first unit is the single-Event Agent PCR
/// genesis anchor. Every later unit is replayed against the state staged by all
/// earlier committed units. This pure fold validates exact Event digests,
/// registered projection shapes, unit atomicity, and canonical result digests;
/// callers remain responsible for Seal signatures and basis verification.
pub fn materialize_agent_pcr_control(
    units: &[OrderedControlUnit],
    project: CellWriteProjector<'_>,
) -> Result<AgentPcrControlMaterial> {
    let first_unit = units.first().ok_or_else(|| {
        WireError::Protocol("Agent PCR material requires a genesis command unit".to_owned())
    })?;
    if first_unit.events.len() != 1
        || first_unit.events[0].event.kind != EventKind::RealmCreate
        || first_unit.events[0].event.seal_basis.is_some()
    {
        return Err(WireError::Protocol(
            "Agent PCR genesis must be one registered basis-less ak.realm.create unit".to_owned(),
        ));
    }
    if units.iter().skip(1).any(|unit| {
        unit.events.is_empty()
            || unit
                .events
                .iter()
                .any(|member| member.event.seal_basis.is_none())
    }) {
        return Err(WireError::Protocol(
            "Agent PCR successor command units require an explicit Seal basis".to_owned(),
        ));
    }

    let create = &first_unit.events[0].event;
    let create_effects = direct_projection(create, project)?;
    let managed_cell = CellRef::new(REALM_CREATE_CELL)?;
    if !create_effects
        .iter()
        .any(|effect| effect.cell_id == managed_cell)
    {
        return Err(WireError::Protocol(
            "Agent PCR genesis does not project its canonical create Cell".to_owned(),
        ));
    }
    validate_realm_create_projection(create, &create_effects)?;
    if units
        .iter()
        .flat_map(|unit| &unit.events)
        .skip(1)
        .any(|member| member.event.kind == EventKind::RealmCreate)
    {
        return Err(WireError::Protocol(
            "Agent PCR material contains more than one create Event".to_owned(),
        ));
    }
    if !create.refs.is_empty() {
        return Err(WireError::Protocol(
            "Agent PCR create must not carry semantic references".to_owned(),
        ));
    }
    let controller_actor_id = create.executed_by.clone().ok_or_else(|| {
        WireError::Protocol("Agent PCR create Event omits executed_by".to_owned())
    })?;
    let authorization_ref = create.authorization_ref.clone().ok_or_else(|| {
        WireError::Protocol("Agent PCR create Event omits authorization_ref".to_owned())
    })?;
    let payload: RealmCreatePayload = create.typed_payload::<event_spec::RealmCreate>()?;
    let object = payload.object;
    if object.purpose != arkret_models_collaboration::events_payloads::RealmPurpose::AgentControl {
        return Err(WireError::Protocol(
            "Agent PCR create purpose is inconsistent".to_owned(),
        ));
    }
    let digest_suite = object.digest_algorithm;
    let notary_value = object.notary;
    notary_value.validate()?;
    if !notary_primary_projects_to_actor(&notary_value, &create.actor_id)? {
        return Err(WireError::Protocol(
            "Agent PCR notary must be the Agent DID".to_owned(),
        ));
    }

    let mut seen = BTreeSet::new();
    for member in units.iter().flat_map(|unit| &unit.events) {
        let event = &member.event;
        if event.kind == EventKind::RealmDigestSuiteTransition {
            return Err(WireError::Protocol(
                "Agent PCR materializer does not accept digest-suite transition Seals".to_owned(),
            ));
        }
        if event.realm_id != create.realm_id
            || event.actor_id != create.actor_id
            || event.executed_by.as_ref() != Some(&controller_actor_id)
            || event.authorization_ref.as_deref() != Some(authorization_ref.as_str())
        {
            return Err(WireError::Protocol(
                "Agent PCR Event authority or Realm differs from its genesis".to_owned(),
            ));
        }
        let expected_suite = event_digest_suite(event, digest_suite);
        if member.digest_suite != expected_suite
            || event.event_id.event_digest().digest_suite()? != expected_suite
        {
            return Err(WireError::Protocol(format!(
                "Agent PCR Event {} was digested under a suite the genesis did not declare",
                event.event_id.as_str()
            )));
        }
        let recomputed = Hash::new(event.event_digest_with_digest_suite(expected_suite)?)?;
        if recomputed != member.digest || !seen.insert(member.digest.clone()) {
            return Err(WireError::Protocol(format!(
                "Agent PCR command member {} has a mismatched or duplicate digest",
                event.event_id.as_str()
            )));
        }
    }

    let registry = arkret_lattice_registry::build_sdk_state_registry();
    let anchor_digest = first_unit.events[0].digest.clone();
    let executed = arkret_state::execute_ordered_control_units(
        &create.realm_id,
        &BTreeMap::new(),
        &registry,
        units,
        digest_suite,
        true,
        |member, staged_state, _unit_entry_state| {
            let is_anchor = member.digest == anchor_digest;
            let effects = if is_anchor {
                direct_projection(&member.event, project).map_err(|error| {
                    arkret_state::OrderedControlBatchAbort::Structural(error.to_string())
                })?
            } else {
                let projected = project(&member.event).map_err(|error| {
                    arkret_state::OrderedControlBatchAbort::Structural(format!(
                        "Agent PCR cell write projection failed for {}: {error}",
                        member.event.kind.as_str()
                    ))
                })?;
                let mut effects = Vec::new();
                for write in &projected {
                    effects.extend(
                        resolve_projected_write(write, &create.realm_id, staged_state, &registry)
                            .map_err(|error| {
                            arkret_state::OrderedControlBatchAbort::Structural(format!(
                                "Agent PCR execution-position projection failed for {}: {error}",
                                member.event.kind.as_str()
                            ))
                        })?,
                    );
                }
                effects
            };
            if let Err(conflict) = ensure_unique_ordered_log_slots(&effects) {
                return Err(arkret_state::OrderedControlBatchAbort::Structural(format!(
                    "Agent PCR Event claims ordered-log slot {}#{} twice",
                    conflict.cell, conflict.issuer_seq
                )));
            }
            if !is_anchor {
                for effect in &effects {
                    let binding = registry
                        .resolve(&create.realm_id, &effect.cell_id)
                        .map_err(|error| {
                            arkret_state::OrderedControlBatchAbort::Infrastructure(
                                error.to_string(),
                            )
                        })?;
                    if binding.execution == EventCellExecution::Data {
                        return Err(arkret_state::OrderedControlBatchAbort::Structural(format!(
                            "Agent PCR successor command wrote ordinary Cell {}",
                            effect.cell_id
                        )));
                    }
                }
            }
            Ok(arkret_state::CommandEventResult::Applied(effects))
        },
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;

    let security_state = executed
        .post_state
        .iter()
        .filter_map(|(cell, state)| {
            registry
                .resolve(&create.realm_id, cell)
                .ok()
                .filter(|binding| binding.execution == EventCellExecution::Security)
                .map(|_| (cell.clone(), state.clone()))
        })
        .collect();
    let state_root = compute_state_root(GovernanceView::new(&security_state), digest_suite)
        .map_err(|error| WireError::Protocol(format!("Agent PCR state root: {error}")))?;

    Ok(AgentPcrControlMaterial {
        realm_id: create.realm_id.clone(),
        agent_id: create.actor_id.clone(),
        controller_actor_id,
        authorization_ref,
        notary: notary_value,
        digest_suite,
        covered_event_digests: executed.committed_event_digests,
        state_root,
        command_results: executed.command_results,
        joined: executed.post_state,
        event_ops: executed.committed_ops,
    })
}

/// The immutable proposal authority a Agent PCR was founded with.
///
/// Genesis authority is fixed by the single accepted `ak.realm.create`, so this
/// type is built from that Event alone. Later transitions belong to
/// [`materialize_agent_pcr_control`], which folds confirmed command order and
/// therefore supplies each transition its exact execution-position state.
/// Keeping the two questions in separate types is what stops a caller that only
/// wants genesis from handing over a full history and failing the moment a
/// replacement adds an `ak.agent.key.revoke`.
#[derive(Clone, Debug)]
pub struct AgentPcrGenesisAuthority {
    realm_id: RealmId,
    agent_id: ActorId,
    controller_actor_id: ActorId,
    authorization_ref: AuthorizationRef,
    notary: NotaryValue,
    digest_suite: arkret_canonical::DigestSuite,
    authority_set_ref: Hash,
}

impl AgentPcrGenesisAuthority {
    /// Derive the founding authority from a fully validated delegated create.
    ///
    /// The create may be the candidate closed anchor currently undergoing
    /// ingress or the byte-identical accepted genesis loaded for a successor.
    /// Acceptance is deliberately not inferred by this pure materializer; the
    /// caller must establish the appropriate protocol context.
    pub fn from_delegated_create(create: &Event, project: CellWriteProjector<'_>) -> Result<Self> {
        if create.kind != EventKind::RealmCreate {
            return Err(WireError::Protocol(
                "Agent PCR genesis authority requires ak.realm.create".to_owned(),
            ));
        }
        let unit = agent_pcr_genesis_control_unit(create)?;
        let material = materialize_agent_pcr_control(std::slice::from_ref(&unit), project)?;
        let authority_set_ref = Hash::new(arkret_canonical::digest(
            material.digest_suite,
            arkret_canonical::canonical_json_bytes(&material.notary)?,
        ))?;
        Ok(Self {
            realm_id: material.realm_id,
            agent_id: material.agent_id,
            controller_actor_id: material.controller_actor_id,
            authorization_ref: material.authorization_ref,
            notary: material.notary,
            digest_suite: material.digest_suite,
            authority_set_ref,
        })
    }

    /// Derive the authority from the one accepted delegated create Event.
    ///
    /// The complete genesis leaf set is validated exactly as it is for any
    /// other Agent PCR bootstrap branch, and the authority digest covers the
    /// whole founding [`NotaryValue`] — recovery members, controller
    /// organization, and every other field — not just the primary DID.
    pub fn from_accepted_create(create: &Event, project: CellWriteProjector<'_>) -> Result<Self> {
        Self::from_delegated_create(create, project)
    }

    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    pub fn agent_id(&self) -> &ActorId {
        &self.agent_id
    }

    /// The delegated controller whose device key signs receipts under this
    /// authority.
    pub fn controller_actor_id(&self) -> &ActorId {
        &self.controller_actor_id
    }

    pub fn authorization_ref(&self) -> &str {
        &self.authorization_ref
    }

    pub fn notary(&self) -> &NotaryValue {
        &self.notary
    }

    /// The suite this Agent PCR locked in its genesis object.
    pub fn digest_suite(&self) -> arkret_canonical::DigestSuite {
        self.digest_suite
    }

    /// Canonical digest of the founding notary profile.
    pub fn authority_set_ref(&self) -> &Hash {
        &self.authority_set_ref
    }
}

/// Build and sign a Agent PCR Seal with the controller device named
/// by the accepted Agent DID delegation.
pub fn build_agent_pcr_bootstrap_seal<S: PayloadSigner + ?Sized>(
    events: &[Event],
    hlc: Hlc,
    signer: &S,
    project: CellWriteProjector<'_>,
) -> Result<Seal> {
    if events.len() != 1 || events[0].kind != EventKind::RealmCreate {
        return Err(WireError::Protocol(
            "Agent PCR bootstrap Seal requires exactly its genesis create".to_owned(),
        ));
    }
    let unit = agent_pcr_genesis_control_unit(&events[0])?;
    let material = materialize_agent_pcr_control(std::slice::from_ref(&unit), project)?;
    if project_did_to_core_id(signer.signer_did())?
        != *material.controller_actor_id.signing_principal_id()
    {
        return Err(WireError::Protocol(
            "Agent PCR Seal signer must be the delegated controller".to_owned(),
        ));
    }
    let target = material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let current = BTreeSet::new();
    let notary_seq = 0;
    let delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if delta.is_empty() {
        return Err(WireError::Protocol(
            "Agent PCR Seal has no new Event delta".to_owned(),
        ));
    }
    let digest_suite = material.digest_suite;
    let control_root = control_event_set_root(&target, digest_suite)
        .map_err(|error| WireError::Protocol(format!("Agent PCR control root: {error}")))?;
    let availability_receipt_digests = Vec::new();
    let command_results = material.command_results;
    Seal::sign_with_signer(
        UnsignedSeal {
            realm_id: material.realm_id,
            predecessor_ref: None,
            delta,
            control_event_set_root: control_root,
            data_delta: Vec::new(),
            data_event_set_root: arkret_wire::empty_data_event_set_root(digest_suite)?,
            state_root: material.state_root,
            notary_seq,
            availability_receipt_digests,
            covered_event_digests: material.covered_event_digests,
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: Utc::now(),
            hlc,
            configuration_ref: events[0].event_id.clone(),
            command_results,
            authorization_closures: Vec::new(),
            data_closure_announcements: Vec::new(),
            data_closures: Vec::new(),
            existence_anchors: Vec::new(),
        },
        digest_suite,
        signer,
    )
}
