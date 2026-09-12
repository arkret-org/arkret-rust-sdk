//! Agent Principal Control Realm: canonical control materialization
//! and the controller-signed Seal built from it.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::{RealmCreatePayload, RealmGenesis};
use arkret_models_identity::ResolutionCommitment;
use arkret_state::state_model::ordered_log::{
    IssuedOp, OrderedLog, ensure_unique_ordered_log_slots,
};
use arkret_state::{
    CellStateRegistry, GovernanceView, ResolvedCellState, StateModelKind, StateWrite,
    compute_state_root, control_event_set_root, join_cell, join_cell_seal_batches,
    resolve_projected_write,
};
use arkret_wire::{
    ActorId, AuthorizationRef, CellRef, CommandResult, CommandResultCellState, CommandResultEffect,
    DidCoreId, EncryptionProfile, Event, EventCellExecution, EventKind, GenesisSalt, Hash, Hlc,
    NotaryValue, PayloadSigner, ProfileId, RealmId, Result, SchemaId, Seal, SecurityClass,
    TrustDomainId, UnsignedSeal, WireError, event_spec, project_did_to_core_id,
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
    Ok(notary
        .signers
        .iter()
        .any(|member| member.actor_id.signing_principal_id() == signing_principal_id))
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
    pub command_effects: Vec<CommandResultEffect>,
    pub joined: BTreeMap<CellRef, ResolvedCellState>,
    /// Sealed effects with their issuer attached, ready for a store that
    /// must keep ordered-log slots keyed by the real actor.
    pub event_ops: Vec<(CellRef, IssuedOp)>,
}

/// Materialize the canonical control state of a Agent PCR.
///
/// The delegated create Event derives the six common Realm genesis cells plus
/// its conditional Agent-status genesis cell. Every later Agent PCR Event
/// likewise contributes exactly what its registered contract projects. Keeping
/// this materialization in the SDK gives the controller-side Seal builder and
/// receiver admission one byte-identical state-root implementation.
/// Successor Events must already have passed Seal-DAG basis verification; this
/// pure fold groups identical leaf sets but does not resolve Seal objects.
pub fn materialize_agent_pcr_control(
    events: &[Event],
    project: CellWriteProjector<'_>,
) -> Result<AgentPcrControlMaterial> {
    if events
        .iter()
        .any(|event| event.kind == EventKind::RealmDigestSuiteTransition)
    {
        return Err(WireError::Protocol(
            "Agent PCR bootstrap materializer does not accept digest-suite transition Seals"
                .to_owned(),
        ));
    }
    let managed_cell = CellRef::new(REALM_CREATE_CELL)?;
    // The create-log cell is a derived target now, so "is this the canonical
    // genesis Event" is a question only the reducer contract can answer.
    let mut creates = Vec::new();
    for event in events {
        if event.kind != EventKind::RealmCreate {
            continue;
        }
        let effects = direct_projection(event, project)?;
        if effects.iter().any(|effect| effect.cell_id == managed_cell) {
            creates.push((event, effects));
        }
    }
    if creates.len() != 1 {
        return Err(WireError::Protocol(format!(
            "Agent PCR material requires exactly one canonical create Event (found {})",
            creates.len()
        )));
    }
    let (create, create_effects) = &creates[0];
    let create = *create;
    // The provision Event forward-declares `retype(this event_id)` as the
    // Agent PCR id.  Putting the provision id back into this envelope would
    // create a content-hash fixed point, so admission resolves the accepted
    // provision by that declared Realm id instead.
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
    validate_realm_create_projection(create, create_effects)?;

    // An Agent PCR is itself a control-only Realm. Effectless protocol
    // anchors such as `ak.mls.genesis` still belong to the notarized history:
    // they change the coverage root even though they do not change a lattice
    // cell. Omitting them would leave the MLS genesis outside its own
    // governance anchor.
    let included = events.iter().collect::<Vec<_>>();
    if included.iter().any(|event| {
        event.realm_id != create.realm_id
            || event.actor_id != create.actor_id
            || event.executed_by.as_ref() != Some(&controller_actor_id)
            || event.authorization_ref.as_deref() != Some(authorization_ref.as_str())
    }) {
        return Err(WireError::Protocol(
            "Agent PCR Event authority or Realm differs from its genesis".to_owned(),
        ));
    }

    let mut ordered = included
        .into_iter()
        .map(|event| {
            let event_suite = event_digest_suite(event, digest_suite);
            // The carried id losslessly encodes the suite its digest was taken
            // under. A history whose Events were digested under a different
            // suite than the genesis locked is rejected here rather than
            // silently re-digested into this Realm's contract.
            if event.event_id.event_digest().digest_suite()? != event_suite {
                return Err(WireError::Protocol(format!(
                    "Agent PCR Event {} was digested under a suite the genesis did not declare",
                    event.event_id.as_str()
                )));
            }
            Ok((
                event,
                Hash::new(event.event_digest_with_digest_suite(event_suite)?)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by(|(left, left_digest), (right, right_digest)| {
        left.actor_seq
            .cmp(&right.actor_seq)
            .then_with(|| left_digest.as_str().cmp(right_digest.as_str()))
    });
    if ordered
        .windows(2)
        .any(|pair| pair[0].0.actor_seq == pair[1].0.actor_seq)
    {
        return Err(WireError::Protocol(
            "Agent PCR Event history contains duplicate actor_seq".to_owned(),
        ));
    }

    // A first Agent PCR Seal is one closed anchor unit. Every later Event
    // is an ordinary Control Move and therefore carries the accepted Seal view
    // it was authored against. Keeping the batches explicit is load-bearing:
    // all Moves in one successor batch read the same frozen pre-state, while
    // the next batch reads the joined result of the preceding Seal.
    let anchor_len = ordered
        .iter()
        .take_while(|(event, _)| event.seal_basis.is_none())
        .count();
    if anchor_len == 0
        || ordered[anchor_len..]
            .iter()
            .any(|(event, _)| event.seal_basis.is_none())
    {
        return Err(WireError::Protocol(
            "Agent PCR basis-less Events must form one leading anchor unit".to_owned(),
        ));
    }

    let registry = arkret_lattice_registry::build_sdk_state_registry();
    let mut covered = BTreeSet::new();
    let mut batches_by_cell = BTreeMap::<CellRef, Vec<Vec<IssuedOp>>>::new();
    let mut event_ops = Vec::new();
    let mut joined = BTreeMap::new();

    apply_agent_batch(
        &ordered[..anchor_len],
        true,
        create,
        project,
        &registry,
        &mut covered,
        &mut batches_by_cell,
        &mut event_ops,
        &mut joined,
    )?;
    let mut cursor = anchor_len;
    while cursor < ordered.len() {
        let basis = ordered[cursor].0.seal_basis.as_ref().ok_or_else(|| {
            WireError::Protocol("Agent PCR successor Event omits seal_basis".to_owned())
        })?;
        let mut end = cursor + 1;
        while end < ordered.len() && ordered[end].0.seal_basis.as_ref() == Some(basis) {
            end += 1;
        }
        apply_agent_batch(
            &ordered[cursor..end],
            false,
            create,
            project,
            &registry,
            &mut covered,
            &mut batches_by_cell,
            &mut event_ops,
            &mut joined,
        )?;
        cursor = end;
    }

    let security_state = joined
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
    let command_effects = security_state
        .into_iter()
        .map(|(cell_id, state)| match state {
            ResolvedCellState::Sequenced(state) => Ok(CommandResultEffect {
                cell_id,
                state: CommandResultCellState {
                    revision_event_id: state.revision_event_id,
                    value: state.value,
                },
            }),
            _ => Err(WireError::Protocol(
                "Agent PCR Seal effects may contain only sequenced_state Cells".to_owned(),
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AgentPcrControlMaterial {
        realm_id: create.realm_id.clone(),
        agent_id: create.actor_id.clone(),
        controller_actor_id,
        authorization_ref,
        notary: notary_value,
        digest_suite,
        covered_event_digests: covered.into_iter().collect(),
        state_root,
        command_effects,
        joined,
        event_ops,
    })
}

/// The suite one Agent PCR Event's own digest is taken under.
///
/// Only `ak.realm.create` differs, and only because §2.5.0 makes the Realm
/// token a retype of its own `event_id`.
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

#[allow(clippy::too_many_arguments)]
fn apply_agent_batch(
    batch: &[(&Event, Hash)],
    anchor: bool,
    create: &Event,
    project: CellWriteProjector<'_>,
    registry: &dyn CellStateRegistry,
    covered: &mut BTreeSet<Hash>,
    batches_by_cell: &mut BTreeMap<CellRef, Vec<Vec<IssuedOp>>>,
    event_ops: &mut Vec<(CellRef, IssuedOp)>,
    joined: &mut BTreeMap<CellRef, ResolvedCellState>,
) -> Result<()> {
    let frozen_pre_state = joined.clone();
    let mut batch_ops = BTreeMap::<CellRef, Vec<IssuedOp>>::new();
    for (event, move_id) in batch {
        if !covered.insert(move_id.clone()) {
            return Err(WireError::Protocol(
                "Agent PCR Event material contains duplicate digests".to_owned(),
            ));
        }
        // Anchor-unit writes are staged by their closed bootstrap contract.
        // Ordinary writes resolve transition/apply-patch/remove-observed
        // operands from this batch's frozen predecessor state, exactly as
        // receiver admission does.
        let effects = if anchor {
            direct_projection(event, project)?
        } else {
            let projected = project(event).map_err(|error| {
                WireError::Protocol(format!(
                    "Agent PCR cell write projection failed for {}: {error}",
                    event.kind.as_str()
                ))
            })?;
            let mut effects = Vec::new();
            for write in &projected {
                effects.extend(
                    resolve_projected_write(write, &create.realm_id, &frozen_pre_state, registry)
                        .map_err(|error| {
                        WireError::Protocol(format!(
                            "Agent PCR frozen-pre-state projection failed for {}: {error}",
                            event.kind.as_str()
                        ))
                    })?,
                );
            }
            effects
        };
        // One Event may project at most one ordered-log entry into one cell;
        // Event identity is the grow-only set key.
        if let Err(conflict) = ensure_unique_ordered_log_slots(&effects) {
            return Err(WireError::Protocol(format!(
                "Agent PCR Event claims ordered-log slot {}#{} twice",
                conflict.cell, conflict.issuer_seq
            )));
        }
        for effect in effects {
            let issued = IssuedOp {
                issuer_id: create.actor_id.clone(),
                op: StateWrite::new(move_id.clone(), effect.op),
            };
            batch_ops
                .entry(effect.cell_id.clone())
                .or_default()
                .push(issued.clone());
            event_ops.push((effect.cell_id, issued));
        }
    }

    for (cell, issued) in batch_ops {
        if let Ok(binding) = registry.resolve(&create.realm_id, &cell)
            && binding.state_model == StateModelKind::OrderedLog
        {
            let report = OrderedLog.join_with_issuer_report(&issued);
            if !report.identity_collisions.is_empty() {
                return Err(WireError::Protocol(format!(
                    "Agent PCR cell {cell} contains an Event identity collision"
                )));
            }
        }
        batches_by_cell.entry(cell).or_default().push(issued);
    }

    joined.clear();
    for (cell, batches) in batches_by_cell {
        let binding = registry
            .resolve(&create.realm_id, cell)
            .map_err(|error| WireError::Protocol(format!("Agent PCR cell registry: {error}")))?;
        let state = if binding.execution == EventCellExecution::Security {
            join_cell_seal_batches(binding.model.as_ref(), cell, batches)
        } else {
            join_cell(
                binding.model.as_ref(),
                cell,
                &batches.iter().flatten().cloned().collect::<Vec<_>>(),
            )
        }
        .map_err(|error| WireError::Protocol(format!("Agent PCR cell {cell}: {error}")))?;
        if let ResolvedCellState::Bottom(bottom) = &state {
            return Err(WireError::Protocol(format!(
                "Agent PCR cell {cell} resolved to Bottom: {bottom:?}"
            )));
        }
        joined.insert(cell.clone(), state);
    }
    Ok(())
}

/// The immutable proposal authority a Agent PCR was founded with.
///
/// Genesis authority is fixed by the single accepted `ak.realm.create`, so this
/// type is built from that Event alone. Later transitions belong to
/// [`materialize_agent_pcr_control`], which folds the accepted history
/// and therefore needs whatever frozen pre-state each transition requires.
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
        let material = materialize_agent_pcr_control(std::slice::from_ref(create), project)?;
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
    let material = materialize_agent_pcr_control(events, project)?;
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
    if events.len() != 1 || events[0].kind != EventKind::RealmCreate {
        return Err(WireError::Protocol(
            "Agent PCR bootstrap Seal requires exactly its genesis create".to_owned(),
        ));
    }
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
    let command_result = CommandResult::committed(
        delta[0].clone(),
        delta.clone(),
        material.command_effects,
        digest_suite,
    )?;
    Seal::sign_with_signers(
        UnsignedSeal {
            realm_id: material.realm_id,
            predecessor_ref: None,
            delta,
            control_event_set_root: control_root,
            state_root: material.state_root,
            notary_seq,
            availability_receipt_digests,
            covered_event_digests: material.covered_event_digests,
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: Utc::now(),
            hlc,
            configuration_ref: events[0].event_id.clone(),
            command_results: vec![command_result],
            authorization_closures: Vec::new(),
            existence_anchors: Vec::new(),
            transaction_records: Vec::new(),
        },
        0,
        digest_suite,
        &[signer],
    )
}
