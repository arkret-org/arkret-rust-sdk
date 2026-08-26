//! Managed Agent Principal Control Realm: canonical control materialization
//! and the controller-signed Seal built from it.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::{RealmCreatePayload, RealmGenesis};
use arkret_models_identity::ResolutionCommitment;
use arkret_state::lattice::ordered_log::{IssuedOp, OrderedLog, ensure_unique_ordered_log_slots};
use arkret_state::{
    CellRegistry, CellState, LatticeKind, SealedOp, compute_state_root, control_event_set_root,
    join_cell_seal_batches, resolve_projected_write,
};
use arkret_wire::{
    AuthorizationRef, CellRef, DidCoreId, EncryptionProfile, Event, EventKind, GenesisSalt, Hash,
    Hlc, NotarySig, NotaryValue, PayloadSigner, ProfileId, RealmId, Result, SchemaId, Seal, SealId,
    SealSignature, SecurityClass, TrustDomainId, WireError, event_spec, project_full_id_to_core_id,
};
use chrono::{DateTime, Utc};

use crate::REALM_CREATE_CELL;
use crate::projection::{CellWriteProjector, direct_projection, validate_realm_create_projection};

const MANAGED_AGENT_PCR_DIGEST_SUITE: arkret_canonical::DigestSuite =
    arkret_canonical::DigestSuite::Sha256;

/// Public inputs for the profile-closed managed Agent PCR Realm payload.
#[derive(Clone, Debug)]
pub struct ManagedAgentPcrCreatePayloadInput {
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub notary: NotaryValue,
    /// Exact, already accepted method-native inception position. The Agent
    /// PCR commits this immutable pre-binding head; the Realm service entry is
    /// published only by a later continuous DID update.
    pub initial_resolution: ResolutionCommitment,
    pub genesis_salt: GenesisSalt,
    pub trust_domain: TrustDomainId,
    pub created_at: DateTime<Utc>,
}

/// Build the canonical `ak.realm.create` payload for a managed Agent PCR.
pub fn build_managed_agent_pcr_create_payload(
    input: ManagedAgentPcrCreatePayloadInput,
) -> Result<RealmCreatePayload> {
    if project_full_id_to_core_id(&input.initial_resolution.full_id)? != input.agent_id {
        return Err(WireError::Protocol(
            "managed Agent initial_resolution full_id does not project to agent_id".to_owned(),
        ));
    }
    input.notary.validate()?;
    if !notary_primary_projects_to_actor(&input.notary, &input.agent_id)? {
        return Err(WireError::Protocol(
            "managed Agent notary primary does not match agent_id".to_owned(),
        ));
    }
    let genesis = RealmGenesis::managed_agent_control(
        input.genesis_salt,
        input.initial_resolution,
        input.trust_domain,
        vec![
            SchemaId::REALM_V1.to_owned(),
            ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
        ],
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_canonical::DigestSuite::Sha256,
        SecurityClass::HighAssurance,
        EncryptionProfile::MlsRfc9420,
        input.notary,
    )?;

    let payload = RealmCreatePayload::new(genesis);
    payload.to_value()?;
    Ok(payload)
}

fn notary_primary_projects_to_actor(notary: &NotaryValue, actor_id: &DidCoreId) -> Result<bool> {
    match notary {
        NotaryValue::SingleSigner { signer, .. } | NotaryValue::Mixed { signer, .. } => {
            Ok(&signer.actor_id == actor_id)
        }
        NotaryValue::Threshold { members, .. } | NotaryValue::OpenSet { members } => {
            Ok(members.iter().any(|member| &member.actor_id == actor_id))
        }
    }
}

/// Complete reducer material needed to construct or validate a
/// controller-signed managed Agent PCR Event Seal.
#[derive(Clone, Debug)]
pub struct ManagedAgentPcrControlMaterial {
    pub realm_id: RealmId,
    pub agent_id: DidCoreId,
    pub controller_id: DidCoreId,
    pub authorization_ref: AuthorizationRef,
    /// The founding notary profile, exactly as the accepted create declared it.
    pub notary: NotaryValue,
    pub covered_event_digests: Vec<Hash>,
    pub state_root: Hash,
    pub joined: BTreeMap<CellRef, CellState>,
    /// Sealed effects with their issuer attached, ready for a store that
    /// must keep ordered-log slots keyed by the real actor.
    pub event_ops: Vec<(CellRef, IssuedOp)>,
}

/// Materialize the canonical control state of a managed Agent PCR.
///
/// The delegated create Event derives the six common Realm genesis cells plus
/// its conditional Agent-status genesis cell. Every later managed PCR Event
/// likewise contributes exactly what its registered contract projects. Keeping
/// this materialization in the SDK gives the controller-side Seal builder and
/// receiver admission one byte-identical state-root implementation.
/// Successor Events must already have passed Seal-DAG basis verification; this
/// pure fold groups identical leaf sets but does not resolve Seal objects.
pub fn materialize_managed_agent_pcr_control(
    events: &[Event],
    project: CellWriteProjector<'_>,
) -> Result<ManagedAgentPcrControlMaterial> {
    if events
        .iter()
        .any(|event| event.kind == EventKind::RealmDigestSuiteTransition)
    {
        return Err(WireError::Protocol(
            "managed Agent PCR bootstrap materializer does not accept digest-suite transition Seals"
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
        if effects.iter().any(|effect| effect.cell == managed_cell) {
            creates.push((event, effects));
        }
    }
    if creates.len() != 1 {
        return Err(WireError::Protocol(format!(
            "managed Agent PCR material requires exactly one canonical create Event (found {})",
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
            "managed Agent PCR create must not carry semantic references".to_owned(),
        ));
    }
    let controller_id = create.executed_by.clone().ok_or_else(|| {
        WireError::Protocol("managed Agent PCR create Event omits executed_by".to_owned())
    })?;
    let authorization_ref = create.authorization_ref.clone().ok_or_else(|| {
        WireError::Protocol("managed Agent PCR create Event omits authorization_ref".to_owned())
    })?;
    let payload: RealmCreatePayload = create.typed_payload::<event_spec::RealmCreate>()?;
    let object = payload.object;
    if object.purpose
        != arkret_models_collaboration::events_payloads::RealmPurpose::ManagedAgentControl
    {
        return Err(WireError::Protocol(
            "managed Agent PCR create purpose is inconsistent".to_owned(),
        ));
    }
    let notary_value = object.notary;
    notary_value.validate()?;
    if !notary_primary_projects_to_actor(&notary_value, &create.actor_id)? {
        return Err(WireError::Protocol(
            "managed Agent PCR notary must be the Agent DID".to_owned(),
        ));
    }
    validate_realm_create_projection(create, create_effects)?;

    // A managed PCR is itself a control-only Realm. Effectless protocol
    // anchors such as `ak.mls.genesis` still belong to the notarized history:
    // they change the coverage root even though they do not change a lattice
    // cell. Omitting them would leave the MLS genesis outside its own
    // governance anchor.
    let included = events.iter().collect::<Vec<_>>();
    if included.iter().any(|event| {
        event.realm_id != create.realm_id
            || event.actor_id != create.actor_id
            || event.executed_by.as_ref() != Some(&controller_id)
            || event.authorization_ref.as_deref() != Some(authorization_ref.as_str())
    }) {
        return Err(WireError::Protocol(
            "managed Agent PCR Event authority or Realm differs from its genesis".to_owned(),
        ));
    }

    let mut ordered = included
        .into_iter()
        .map(|event| {
            Ok((
                event,
                Hash::new(event.event_digest_with_digest_suite(MANAGED_AGENT_PCR_DIGEST_SUITE)?)?,
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
            "managed Agent PCR Event history contains duplicate actor_seq".to_owned(),
        ));
    }

    // A first managed-PCR Seal is one closed anchor unit. Every later Event
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
            "managed Agent PCR basis-less Events must form one leading anchor unit".to_owned(),
        ));
    }

    let registry = arkret_lattice_registry::build_sdk_cell_registry();
    let mut covered = BTreeSet::new();
    let mut batches_by_cell = BTreeMap::<CellRef, Vec<Vec<IssuedOp>>>::new();
    let mut event_ops = Vec::new();
    let mut joined = BTreeMap::new();

    apply_managed_agent_batch(
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
            WireError::Protocol("managed Agent PCR successor Event omits seal_basis".to_owned())
        })?;
        let mut end = cursor + 1;
        while end < ordered.len() && ordered[end].0.seal_basis.as_ref() == Some(basis) {
            end += 1;
        }
        apply_managed_agent_batch(
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

    let state_root = compute_state_root(&joined, MANAGED_AGENT_PCR_DIGEST_SUITE)
        .map_err(|error| WireError::Protocol(format!("managed Agent PCR state root: {error}")))?;
    Ok(ManagedAgentPcrControlMaterial {
        realm_id: create.realm_id.clone(),
        agent_id: create.actor_id.clone(),
        controller_id,
        authorization_ref,
        notary: notary_value,
        covered_event_digests: covered.into_iter().collect(),
        state_root,
        joined,
        event_ops,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_managed_agent_batch(
    batch: &[(&Event, Hash)],
    anchor: bool,
    create: &Event,
    project: CellWriteProjector<'_>,
    registry: &dyn CellRegistry,
    covered: &mut BTreeSet<Hash>,
    batches_by_cell: &mut BTreeMap<CellRef, Vec<Vec<IssuedOp>>>,
    event_ops: &mut Vec<(CellRef, IssuedOp)>,
    joined: &mut BTreeMap<CellRef, CellState>,
) -> Result<()> {
    let frozen_pre_state = joined.clone();
    let mut batch_ops = BTreeMap::<CellRef, Vec<IssuedOp>>::new();
    for (event, move_id) in batch {
        if !covered.insert(move_id.clone()) {
            return Err(WireError::Protocol(
                "managed Agent PCR Event material contains duplicate digests".to_owned(),
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
                    "managed Agent PCR cell write projection failed for {}: {error}",
                    event.kind.as_str()
                ))
            })?;
            let mut effects = Vec::new();
            for write in &projected {
                effects.extend(
                    resolve_projected_write(write, &create.realm_id, &frozen_pre_state, registry)
                        .map_err(|error| {
                        WireError::Protocol(format!(
                            "managed Agent PCR frozen-pre-state projection failed for {}: {error}",
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
                "managed Agent PCR Event claims ordered-log slot {}#{} twice",
                conflict.cell, conflict.issuer_seq
            )));
        }
        for effect in effects {
            let issued = IssuedOp {
                issuer: create.actor_id.clone(),
                op: SealedOp::new(move_id.clone(), effect.op),
            };
            batch_ops
                .entry(effect.cell.clone())
                .or_default()
                .push(issued.clone());
            event_ops.push((effect.cell, issued));
        }
    }

    for (cell, issued) in batch_ops {
        if let Ok(binding) = registry.resolve(&create.realm_id, &cell)
            && binding.lattice.kind() == LatticeKind::OrderedLog
        {
            let report = OrderedLog.join_with_issuer_report(&issued);
            if !report.identity_collisions.is_empty() {
                return Err(WireError::Protocol(format!(
                    "managed Agent PCR cell {cell} contains an Event identity collision"
                )));
            }
        }
        batches_by_cell.entry(cell).or_default().push(issued);
    }

    joined.clear();
    for (cell, batches) in batches_by_cell {
        let binding = registry.resolve(&create.realm_id, cell).map_err(|error| {
            WireError::Protocol(format!("managed Agent PCR cell registry: {error}"))
        })?;
        let state = join_cell_seal_batches(binding.lattice.as_ref(), cell, batches);
        if let CellState::Bottom(bottom) = &state {
            return Err(WireError::Protocol(format!(
                "managed Agent PCR cell {cell} resolved to Bottom: {bottom:?}"
            )));
        }
        joined.insert(cell.clone(), state);
    }
    Ok(())
}

/// The immutable proposal authority a managed Agent PCR was founded with.
///
/// Genesis authority is fixed by the single accepted `ak.realm.create`, so this
/// type is built from that Event alone. Later transitions belong to
/// [`materialize_managed_agent_pcr_control`], which folds the accepted history
/// and therefore needs whatever frozen pre-state each transition requires.
/// Keeping the two questions in separate types is what stops a caller that only
/// wants genesis from handing over a full history and failing the moment a
/// replacement adds an `ak.agent.key.revoke`.
#[derive(Clone, Debug)]
pub struct ManagedAgentPcrGenesisAuthority {
    realm_id: RealmId,
    agent_id: DidCoreId,
    controller_id: DidCoreId,
    authorization_ref: AuthorizationRef,
    notary: NotaryValue,
    authority_set_ref: Hash,
}

impl ManagedAgentPcrGenesisAuthority {
    /// Derive the founding authority from a fully validated delegated create.
    ///
    /// The create may be the candidate closed anchor currently undergoing
    /// ingress or the byte-identical accepted genesis loaded for a successor.
    /// Acceptance is deliberately not inferred by this pure materializer; the
    /// caller must establish the appropriate protocol context.
    pub fn from_delegated_create(create: &Event, project: CellWriteProjector<'_>) -> Result<Self> {
        if create.kind != EventKind::RealmCreate {
            return Err(WireError::Protocol(
                "managed Agent PCR genesis authority requires ak.realm.create".to_owned(),
            ));
        }
        let material =
            materialize_managed_agent_pcr_control(std::slice::from_ref(create), project)?;
        let authority_set_ref = Hash::new(arkret_canonical::canonical_sha256(&material.notary)?)?;
        Ok(Self {
            realm_id: material.realm_id,
            agent_id: material.agent_id,
            controller_id: material.controller_id,
            authorization_ref: material.authorization_ref,
            notary: material.notary,
            authority_set_ref,
        })
    }

    /// Derive the authority from the one accepted delegated create Event.
    ///
    /// The complete genesis leaf set is validated exactly as it is for any
    /// other managed PCR bootstrap branch, and the authority digest covers the
    /// whole founding [`NotaryValue`] — recovery members, controller
    /// organization, and every other field — not just the primary DID.
    pub fn from_accepted_create(create: &Event, project: CellWriteProjector<'_>) -> Result<Self> {
        Self::from_delegated_create(create, project)
    }

    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    pub fn agent_id(&self) -> &DidCoreId {
        &self.agent_id
    }

    /// The delegated controller whose device key signs receipts under this
    /// authority.
    pub fn controller_id(&self) -> &DidCoreId {
        &self.controller_id
    }

    pub fn authorization_ref(&self) -> &str {
        &self.authorization_ref
    }

    pub fn notary(&self) -> &NotaryValue {
        &self.notary
    }

    /// Canonical digest of the founding notary profile.
    pub fn authority_set_ref(&self) -> &Hash {
        &self.authority_set_ref
    }
}

/// Build and sign a managed Agent PCR Seal with the controller device named
/// by the accepted Agent DID delegation.
pub fn build_managed_agent_pcr_event_seal<S: PayloadSigner + ?Sized>(
    events: &[Event],
    predecessor: Option<&Seal>,
    hlc: Hlc,
    signer: &S,
    project: CellWriteProjector<'_>,
) -> Result<Seal> {
    let material = materialize_managed_agent_pcr_control(events, project)?;
    if project_full_id_to_core_id(signer.signer_did())? != material.controller_id {
        return Err(WireError::Protocol(
            "managed Agent PCR Seal signer must be the delegated controller".to_owned(),
        ));
    }
    let target = material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let (predecessor_refs, current, notary_seq) = match predecessor {
        Some(seal) => {
            if seal.realm_id != material.realm_id || seal.covered_event_digests.is_empty() {
                return Err(WireError::Protocol(
                    "managed Agent PCR predecessor has incompatible Realm or coverage".to_owned(),
                ));
            }
            let current = seal
                .covered_event_digests
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if !current.is_subset(&target) {
                return Err(WireError::Protocol(
                    "managed Agent PCR predecessor coverage is not a subset of the target"
                        .to_owned(),
                ));
            }
            (
                vec![seal.id.clone()],
                current,
                seal.notary_seq.checked_add(1).ok_or_else(|| {
                    WireError::Protocol("managed Agent PCR notary sequence overflow".to_owned())
                })?,
            )
        }
        None => (Vec::new(), BTreeSet::new(), 0),
    };
    let delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if delta.is_empty() {
        return Err(WireError::Protocol(
            "managed Agent PCR Seal has no new Event delta".to_owned(),
        ));
    }
    let control_root = control_event_set_root(&target, MANAGED_AGENT_PCR_DIGEST_SUITE)
        .map_err(|error| WireError::Protocol(format!("managed Agent PCR control root: {error}")))?;
    let completeness_root = arkret_state::control_event_completeness_root(
        &events
            .iter()
            .cloned()
            .map(|event| (event, MANAGED_AGENT_PCR_DIGEST_SUITE))
            .collect::<Vec<_>>(),
        &target,
        MANAGED_AGENT_PCR_DIGEST_SUITE,
    )
    .map_err(|error| {
        WireError::Protocol(format!("managed Agent PCR completeness root: {error}"))
    })?;
    let sealed_at = Utc::now();
    let zero_hash = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id: material.realm_id,
        predecessor_refs,
        delta,
        control_event_set_root: control_root,
        state_root: material.state_root,
        completeness_root,
        notary_seq,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: material.covered_event_digests,
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(SealSignature {
            verification_method: signer.verification_method_id().clone(),
            payload_digest: zero_hash,
            jws: String::new(),
        }),
        sealed_at,
        hlc,
    };
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&canonical_bytes, MANAGED_AGENT_PCR_DIGEST_SUITE)?;
    seal.notary_signature = NotarySig::Single(
        signer
            .sign_notary_payload_with_digest_suite(
                &canonical_bytes,
                MANAGED_AGENT_PCR_DIGEST_SUITE,
            )?
            .into(),
    );
    seal.validate_structural()?;
    seal.validate_id(MANAGED_AGENT_PCR_DIGEST_SUITE)?;
    Ok(seal)
}
