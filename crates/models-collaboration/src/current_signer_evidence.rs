//! Reusable current signer evidence and compact dependency transport.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_crypto::DeviceProjectionAttestation;
use arkret_models_identity::{
    AgentAdmissionEvidence, AgentAuthorityState, AgentAuthorityStateAttestation,
    AgentAuthorityStateEvidence, AgentEvidenceTransparency, AgentSignerEvidence,
    AuthenticatedSignerResolutionEvidence, ControllerAccountGateAttestation,
};
use arkret_wire::{
    AccountId, ActorId, DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, RealmId, RequestId,
    SignalEnvelope, SignerEvidenceRef, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const CURRENT_SIGNER_EVIDENCE_MAX_SELECTORS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "sender_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CurrentSignerEvidenceSelector {
    AccountDevice {
        account_id: AccountId,
        device_id: DeviceId,
    },
    Agent {
        actor: ActorId,
        verification_method: DidUrl,
    },
}

impl CurrentSignerEvidenceSelector {
    pub fn actor_id(&self) -> ActorId {
        match self {
            Self::AccountDevice { account_id, .. } => ActorId::account(account_id.clone()),
            Self::Agent { actor, .. } => actor.clone(),
        }
    }

    pub fn route_service_id(&self) -> &DidCoreId {
        match self {
            Self::AccountDevice { account_id, .. } => &account_id.station_id,
            Self::Agent { actor, .. } => actor.route_service_id(),
        }
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        match self {
            Self::AccountDevice {
                account_id,
                device_id,
            } => {
                account_id.validate()?;
                if device_id.as_str().is_empty() {
                    return Err(WireError::Protocol(
                        "current signer evidence device selector is empty".to_owned(),
                    ));
                }
            }
            Self::Agent { actor, .. } => {
                actor.validate()?;
                if actor.as_account_id().is_none() {
                    return Err(WireError::Protocol(
                        "current signer evidence Agent selector requires an account ActorId"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn matches_envelope(&self, envelope: &SignalEnvelope) -> bool {
        match (self, envelope.sender_device_id.as_ref()) {
            (
                Self::AccountDevice {
                    account_id,
                    device_id,
                },
                Some(sender_device_id),
            ) => {
                envelope.sender_actor_id.as_account_id() == Some(account_id)
                    && sender_device_id == device_id
            }
            (
                Self::Agent {
                    actor,
                    verification_method,
                },
                None,
            ) => {
                &envelope.sender_actor_id == actor
                    && &envelope.proof.verification_method == verification_method
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentSignerEvidenceQueryRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: AccountId,
    pub queries: Vec<CurrentSignerEvidenceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_agent_state_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_signer_evidence_refs: Vec<SignerEvidenceRef>,
}

impl CurrentSignerEvidenceQueryRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.recipient_account_id.validate()?;
        if self.known_agent_state_digests.len() > 64
            || self.known_signer_evidence_refs.len() > 64
            || self
                .known_agent_state_digests
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.known_agent_state_digests.len()
            || self
                .known_signer_evidence_refs
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.known_signer_evidence_refs.len()
        {
            return Err(WireError::Protocol(
                "known evidence lists must be unique and bounded".to_owned(),
            ));
        }
        if self.queries.is_empty() || self.queries.len() > CURRENT_SIGNER_EVIDENCE_MAX_SELECTORS {
            return Err(WireError::Protocol(
                "current signer evidence selector count is outside 1..=16".to_owned(),
            ));
        }
        let mut identities = BTreeSet::new();
        let mut target = None;
        for selector in &self.queries {
            selector.validate()?;
            let encoded = arkret_canonical::canonical_json_bytes(selector)?;
            if !identities.insert(encoded) {
                return Err(WireError::Protocol(
                    "current signer evidence selectors must be unique".to_owned(),
                ));
            }
            match target {
                Some(expected) if expected != selector.route_service_id() => {
                    return Err(WireError::Protocol(
                        "current signer evidence selectors must share one authority Station"
                            .to_owned(),
                    ));
                }
                None => target = Some(selector.route_service_id()),
                _ => {}
            }
        }
        Ok(())
    }

    pub fn target_station_id(&self) -> arkret_wire::Result<&DidCoreId> {
        self.validate()?;
        Ok(self.queries[0].route_service_id())
    }

    pub fn validate_for_envelope(&self, envelope: &SignalEnvelope) -> arkret_wire::Result<()> {
        self.validate()?;
        envelope.validate_structural()?;
        if self.realm_id != envelope.realm_id
            || self.queries.len() != 1
            || !self.queries[0].matches_envelope(envelope)
        {
            return Err(WireError::Protocol(
                "current signer evidence request does not bind the Signal actor and Realm"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "sender_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// The variants are the wire shapes the schema defines, and the size gap is a
// property of the protocol rather than of this declaration: an Agent carries a
// resolution evidence object plus its dependencies, an account device carries a
// projection attestation. Boxing a variant to even them out would put an
// indirection in a type the schema defines flat, for no wire effect.
#[allow(clippy::large_enum_variant)]
pub enum CurrentSignerEvidence {
    AccountDevice {
        account_id: AccountId,
        device_id: DeviceId,
        device_projection_attestation: DeviceProjectionAttestation,
        signer_evidence_ref: SignerEvidenceRef,
    },
    Agent {
        actor: ActorId,
        verification_method: DidUrl,
        authenticated_signer_evidence: CompactAgentSignerResolutionEvidence,
        dependencies: Vec<AuthenticatedSignerResolutionEvidence>,
    },
}

impl CurrentSignerEvidence {
    pub fn selector(&self) -> CurrentSignerEvidenceSelector {
        match self {
            Self::AccountDevice {
                account_id,
                device_id,
                ..
            } => CurrentSignerEvidenceSelector::AccountDevice {
                account_id: account_id.clone(),
                device_id: device_id.clone(),
            },
            Self::Agent {
                actor,
                verification_method,
                ..
            } => CurrentSignerEvidenceSelector::Agent {
                actor: actor.clone(),
                verification_method: verification_method.clone(),
            },
        }
    }

    /// Merge only the advertised, reachable cached dependencies. Hydration
    /// checks content addresses; callers must still authenticate the closure.
    pub fn hydrate_agent(
        &self,
        request: &CurrentSignerEvidenceQueryRequestBody,
        states: &BTreeMap<Hash, AgentAuthorityState>,
        cached: &[AuthenticatedSignerResolutionEvidence],
    ) -> arkret_wire::Result<(
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    )> {
        let Self::Agent {
            authenticated_signer_evidence,
            dependencies,
            ..
        } = self
        else {
            return Err(WireError::Protocol(
                "selected evidence is not Agent".to_owned(),
            ));
        };
        let root = authenticated_signer_evidence.hydrate(states)?;
        let mut available = BTreeMap::new();
        for dependency in cached {
            if request
                .known_signer_evidence_refs
                .contains(&dependency.evidence_ref()?)
            {
                available.insert(dependency.canonical_sha256_digest()?, dependency);
            }
        }
        resolve_agent_dependency_closure(root, dependencies, available)
    }

    /// Hydrate activation-time Agent evidence without omitted state or cached
    /// dependencies. This is the closed form delivered by pairing status and
    /// retained in the active Agent projection for offline authoring.
    pub fn hydrate_complete_agent(
        &self,
    ) -> arkret_wire::Result<(
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    )> {
        let Self::Agent {
            authenticated_signer_evidence,
            dependencies,
            ..
        } = self
        else {
            return Err(WireError::Protocol(
                "complete Agent evidence requires the Agent branch".to_owned(),
            ));
        };
        let root = authenticated_signer_evidence.hydrate(&BTreeMap::new())?;
        resolve_agent_dependency_closure(root, dependencies, BTreeMap::new())
    }

    fn validate_binding(
        &self,
        request: &CurrentSignerEvidenceQueryRequestBody,
        now: DateTime<Utc>,
        states: &BTreeMap<Hash, AgentAuthorityState>,
        cached_dependencies: &[AuthenticatedSignerResolutionEvidence],
    ) -> arkret_wire::Result<()> {
        if !request.queries.contains(&self.selector()) {
            return Err(WireError::Protocol(
                "unrequested current signer evidence".to_owned(),
            ));
        }
        match self {
            Self::AccountDevice {
                account_id,
                device_id,
                device_projection_attestation,
                ..
            } => {
                let core = &device_projection_attestation.attestation;
                if &core.account_id != account_id
                    || &core.device_id != device_id
                    || core.device_status != arkret_models_crypto::DeviceStatus::Active
                    || now < core.attested_at
                    || now >= core.expires_at
                {
                    return Err(WireError::Protocol(
                        "device projection does not bind a live selected device".to_owned(),
                    ));
                }
            }
            Self::Agent {
                actor,
                verification_method,
                authenticated_signer_evidence,
                dependencies: _,
            } => {
                let root = authenticated_signer_evidence.hydrate(states)?;
                if root.signer_id() != actor.signing_principal_id()
                    || root.verification_method() != verification_method
                {
                    return Err(WireError::Protocol(
                        "Agent evidence does not bind the selected actor".to_owned(),
                    ));
                }
                let AuthenticatedSignerResolutionEvidence::Agent {
                    agent_signer_evidence,
                    ..
                } = &root
                else {
                    unreachable!("compact root is Agent");
                };
                let AgentSignerEvidence::CurrentAdmission {
                    admission_evidence, ..
                } = agent_signer_evidence.as_ref()
                else {
                    unreachable!("compact evidence is current");
                };
                let snapshot = &admission_evidence.agent_authority_state_evidence;
                let gate = &admission_evidence.controller_account_gate_attestation;
                if now < admission_evidence.valid_from()
                    || now >= admission_evidence.expires_at()
                    || snapshot.attestation.issued_at >= snapshot.attestation.expires_at
                    || snapshot.attestation.expires_at - snapshot.attestation.issued_at
                        > chrono::Duration::seconds(300)
                    || gate.issued_at >= gate.expires_at
                    || gate.expires_at - gate.issued_at > chrono::Duration::seconds(300)
                {
                    return Err(WireError::Protocol(
                        "Agent authority current validity window is invalid".to_owned(),
                    ));
                }
                self.hydrate_agent(request, states, cached_dependencies)?;
            }
        }
        Ok(())
    }
}

fn resolve_agent_dependency_closure<'a>(
    root: AuthenticatedSignerResolutionEvidence,
    dependencies: &'a [AuthenticatedSignerResolutionEvidence],
    mut available: BTreeMap<Hash, &'a AuthenticatedSignerResolutionEvidence>,
) -> arkret_wire::Result<(
    AuthenticatedSignerResolutionEvidence,
    Vec<AuthenticatedSignerResolutionEvidence>,
)> {
    let mut supplied = BTreeSet::new();
    for dependency in dependencies {
        let digest = dependency.canonical_sha256_digest()?;
        if !supplied.insert(digest.clone()) {
            return Err(WireError::Protocol(
                "Agent response repeats dependency".to_owned(),
            ));
        }
        available.insert(digest, dependency);
    }
    let mut used = BTreeMap::new();
    let mut stack = referenced_digests(&root, &available)?;
    while let Some(digest) = stack.pop() {
        if used.contains_key(&digest) {
            continue;
        }
        let dependency = available
            .get(&digest)
            .ok_or_else(|| WireError::Protocol("Agent response dependency missing".to_owned()))?;
        stack.extend(referenced_digests(dependency, &available)?);
        used.insert(digest, (*dependency).clone());
        if used.len() > 64 {
            return Err(WireError::Protocol(
                "Agent response dependency bound exceeded".to_owned(),
            ));
        }
    }
    if supplied.iter().any(|digest| !used.contains_key(digest)) {
        return Err(WireError::Protocol(
            "Agent response supplies unrelated dependency".to_owned(),
        ));
    }
    let closure = used.into_values().collect::<Vec<_>>();
    validate_agent_dependency_closure(&root, &closure)?;
    Ok((root, closure))
}

/// Validate a finite, exact, content-addressed dependency DAG rooted at the
/// Agent evidence returned for this request. Service evidence is terminal;
/// Principal and Agent evidence may only advance through the digests embedded
/// in their already-authenticated wire objects.  A bounded explicit stack is
/// used so a response can never trigger another current-evidence operation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DependencyVisit {
    Visiting,
    Complete,
}

fn referenced_digests(
    evidence: &AuthenticatedSignerResolutionEvidence,
    _available: &BTreeMap<Hash, &AuthenticatedSignerResolutionEvidence>,
) -> arkret_wire::Result<Vec<Hash>> {
    Ok(match evidence {
        AuthenticatedSignerResolutionEvidence::Service { .. } => Vec::new(),
        AuthenticatedSignerResolutionEvidence::AccountDevice { .. } => {
            return Err(WireError::Protocol(
                "device history evidence is not an Agent authority dependency".to_owned(),
            ));
        }
        AuthenticatedSignerResolutionEvidence::Principal {
            attester_signer_evidence_ref,
            ..
        } => vec![attester_signer_evidence_ref.content_digest()?],
        AuthenticatedSignerResolutionEvidence::Agent {
            attester_signer_evidence_ref,
            account_authority_signer_evidence_ref,
            agent_signer_evidence,
            ..
        } => {
            let mut refs = vec![
                attester_signer_evidence_ref.content_digest()?,
                account_authority_signer_evidence_ref.content_digest()?,
            ];
            for reference in agent_signer_evidence.required_historical_signer_refs() {
                refs.push(reference.content_digest()?);
            }
            refs
        }
    })
}

fn validate_agent_dependency_closure(
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[AuthenticatedSignerResolutionEvidence],
) -> arkret_wire::Result<()> {
    if dependencies.is_empty() || dependencies.len() > 64 {
        return Err(WireError::Protocol(
            "Agent current evidence dependency closure is outside 1..=64".to_owned(),
        ));
    }
    root.validate_attester_binding()?;
    let mut by_digest = BTreeMap::new();
    for evidence in dependencies {
        evidence.validate_attester_binding()?;
        let digest = evidence.canonical_sha256_digest()?;
        if by_digest.insert(digest, evidence).is_some() {
            return Err(WireError::Protocol(
                "Agent current evidence dependency closure contains a duplicate".to_owned(),
            ));
        }
    }

    let graph = by_digest
        .iter()
        .map(|(digest, evidence)| Ok((digest.clone(), referenced_digests(evidence, &by_digest)?)))
        .collect::<arkret_wire::Result<BTreeMap<_, _>>>()?;
    validate_dependency_graph(referenced_digests(root, &by_digest)?, &graph)
}

fn validate_dependency_graph(
    root_digests: Vec<Hash>,
    graph: &BTreeMap<Hash, Vec<Hash>>,
) -> arkret_wire::Result<()> {
    if graph.is_empty() || graph.len() > 64 {
        return Err(WireError::Protocol(
            "Agent current evidence dependency closure is outside 1..=64".to_owned(),
        ));
    }
    let mut visits = BTreeMap::<Hash, DependencyVisit>::new();
    let mut stack = root_digests
        .into_iter()
        .rev()
        .map(|digest| (digest, false))
        .collect::<Vec<_>>();
    while let Some((digest, exiting)) = stack.pop() {
        if exiting {
            visits.insert(digest, DependencyVisit::Complete);
            continue;
        }
        match visits.get(&digest) {
            Some(DependencyVisit::Complete) => continue,
            Some(DependencyVisit::Visiting) => {
                return Err(WireError::Protocol(
                    "Agent current evidence dependency closure contains a cycle".to_owned(),
                ));
            }
            None => {}
        }
        let children = graph.get(&digest).ok_or_else(|| {
            WireError::Protocol(
                "Agent current evidence dependency closure is incomplete".to_owned(),
            )
        })?;
        visits.insert(digest.clone(), DependencyVisit::Visiting);
        stack.push((digest, true));
        stack.extend(children.iter().cloned().rev().map(|child| (child, false)));
    }
    if visits.len() != graph.len() {
        return Err(WireError::Protocol(
            "Agent current evidence dependency closure contains surplus evidence".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentSignerEvidenceResponseCore {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: AccountId,
    pub evidences: Vec<CurrentSignerEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentSignerEvidenceQueryOutcome {
    pub response: CurrentSignerEvidenceResponseCore,
}

impl CurrentSignerEvidenceQueryOutcome {
    pub fn validate_transport_for_request(
        &self,
        request: &CurrentSignerEvidenceQueryRequestBody,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        let core = &self.response;
        if core.request_id != request.request_id
            || core.realm_id != request.realm_id
            || core.recipient_account_id != request.recipient_account_id
            || core.evidences.len() > request.queries.len()
        {
            return Err(WireError::Protocol(
                "current signer evidence response does not match routing request".to_owned(),
            ));
        }
        let mut selectors = BTreeSet::new();
        for item in &core.evidences {
            let selector = item.selector();
            if !request.queries.contains(&selector)
                || !selectors.insert(arkret_canonical::canonical_json_bytes(&selector)?)
            {
                return Err(WireError::Protocol(
                    "current signer evidence repeats or substitutes a selector".to_owned(),
                ));
            }
            if let CurrentSignerEvidence::Agent {
                authenticated_signer_evidence:
                    CompactAgentSignerResolutionEvidence::Agent {
                        agent_signer_evidence:
                            CompactCurrentAgentSignerEvidence::CurrentAdmission {
                                admission_evidence,
                                ..
                            },
                        ..
                    },
                dependencies,
                ..
            } = item
            {
                let compact = &admission_evidence.agent_authority_state_evidence;
                if compact.state.is_none()
                    && !request
                        .known_agent_state_digests
                        .contains(&compact.state_digest)
                    || dependencies.len() > 64
                {
                    return Err(WireError::Protocol("compact Agent response omits an unadvertised state or exceeds closure bounds".to_owned()));
                }
                let mut refs = BTreeSet::new();
                for dependency in dependencies {
                    let reference = dependency.evidence_ref()?;
                    if !refs.insert(reference) {
                        return Err(WireError::Protocol(
                            "compact Agent response repeats dependency".to_owned(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn validate_for_request(
        &self,
        request: &CurrentSignerEvidenceQueryRequestBody,
        now: DateTime<Utc>,
    ) -> arkret_wire::Result<()> {
        self.validate_with_cache(request, now, &BTreeMap::new(), &[])
    }

    pub fn validate_with_cache(
        &self,
        request: &CurrentSignerEvidenceQueryRequestBody,
        now: DateTime<Utc>,
        states: &BTreeMap<Hash, AgentAuthorityState>,
        dependencies: &[AuthenticatedSignerResolutionEvidence],
    ) -> arkret_wire::Result<()> {
        self.validate_transport_for_request(request)?;
        let core = &self.response;
        let mut selectors = BTreeSet::new();
        for item in &core.evidences {
            item.validate_binding(request, now, states, dependencies)?;
            if !selectors.insert(arkret_canonical::canonical_json_bytes(&item.selector())?) {
                return Err(WireError::Protocol(
                    "current signer evidence repeats selector".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Compact transport preserves the canonical full-root content address by
/// hydrating an omitted state before root hashing or trust verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CompactAgentAuthorityStateEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AgentAuthorityState>,
    pub state_digest: Hash,
    pub attestation: AgentAuthorityStateAttestation,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CompactAgentAdmissionEvidence {
    pub agent_authority_state_evidence: CompactAgentAuthorityStateEvidence,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
    pub admission_evidence_digest: Hash,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "verification_mode",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CompactCurrentAgentSignerEvidence {
    CurrentAdmission {
        schema: NonEmptyString,
        admission_evidence: CompactAgentAdmissionEvidence,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency: Option<AgentEvidenceTransparency>,
    },
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CompactAgentSignerResolutionEvidence {
    Agent {
        signer_id: DidCoreId,
        verification_method: DidUrl,
        agent_signer_evidence: CompactCurrentAgentSignerEvidence,
        attester_signer_evidence_ref: SignerEvidenceRef,
        account_authority_signer_evidence_ref: SignerEvidenceRef,
    },
}
impl Eq for CompactAgentSignerResolutionEvidence {}
impl CompactAgentSignerResolutionEvidence {
    pub fn from_full(
        root: &AuthenticatedSignerResolutionEvidence,
        known: &[Hash],
    ) -> arkret_wire::Result<Self> {
        root.validate_attester_binding()?;
        let AuthenticatedSignerResolutionEvidence::Agent {
            signer_id,
            verification_method,
            agent_signer_evidence,
            attester_signer_evidence_ref,
            account_authority_signer_evidence_ref,
            ..
        } = root
        else {
            return Err(WireError::Protocol(
                "compact transport requires Agent root".to_owned(),
            ));
        };
        let AgentSignerEvidence::CurrentAdmission {
            schema,
            admission_evidence,
            transparency,
        } = agent_signer_evidence.as_ref()
        else {
            return Err(WireError::Protocol(
                "compact transport requires current evidence".to_owned(),
            ));
        };
        let snapshot = &admission_evidence.agent_authority_state_evidence;
        Ok(Self::Agent {
            signer_id: signer_id.clone(),
            verification_method: verification_method.clone(),
            agent_signer_evidence: CompactCurrentAgentSignerEvidence::CurrentAdmission {
                schema: schema.clone(),
                admission_evidence: CompactAgentAdmissionEvidence {
                    agent_authority_state_evidence: CompactAgentAuthorityStateEvidence {
                        state: (!known.contains(&snapshot.state_digest))
                            .then(|| snapshot.state.clone()),
                        state_digest: snapshot.state_digest.clone(),
                        attestation: snapshot.attestation.clone(),
                    },
                    controller_account_gate_attestation: admission_evidence
                        .controller_account_gate_attestation
                        .clone(),
                    admission_evidence_digest: admission_evidence.admission_evidence_digest.clone(),
                },
                transparency: transparency.clone(),
            },
            attester_signer_evidence_ref: attester_signer_evidence_ref.clone(),
            account_authority_signer_evidence_ref: account_authority_signer_evidence_ref.clone(),
        })
    }
    pub fn hydrate(
        &self,
        states: &BTreeMap<Hash, AgentAuthorityState>,
    ) -> arkret_wire::Result<AuthenticatedSignerResolutionEvidence> {
        let Self::Agent {
            signer_id,
            verification_method,
            agent_signer_evidence:
                CompactCurrentAgentSignerEvidence::CurrentAdmission {
                    schema,
                    admission_evidence,
                    transparency,
                },
            attester_signer_evidence_ref,
            account_authority_signer_evidence_ref,
        } = self;
        let compact = &admission_evidence.agent_authority_state_evidence;
        let state = compact
            .state
            .as_ref()
            .or_else(|| states.get(&compact.state_digest))
            .ok_or_else(|| {
                WireError::Protocol(
                    "compact Agent evidence is missing its state dependency".to_owned(),
                )
            })?;
        if Hash::new(arkret_canonical::canonical_sha256(state)?)? != compact.state_digest {
            return Err(WireError::Protocol(
                "compact Agent state digest mismatch".to_owned(),
            ));
        }
        let root = AuthenticatedSignerResolutionEvidence::Agent {
            signer_id: signer_id.clone(),
            verification_method: verification_method.clone(),
            agent_signer_evidence: Box::new(AgentSignerEvidence::CurrentAdmission {
                schema: schema.clone(),
                admission_evidence: AgentAdmissionEvidence {
                    agent_authority_state_evidence: AgentAuthorityStateEvidence {
                        state: state.clone(),
                        state_digest: compact.state_digest.clone(),
                        attestation: compact.attestation.clone(),
                    },
                    controller_account_gate_attestation: admission_evidence
                        .controller_account_gate_attestation
                        .clone(),
                    admission_evidence_digest: admission_evidence.admission_evidence_digest.clone(),
                },
                transparency: transparency.clone(),
            }),
            attester_signer_evidence_ref: attester_signer_evidence_ref.clone(),
            account_authority_signer_evidence_ref: account_authority_signer_evidence_ref.clone(),
        };
        root.validate_attester_binding()?;
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hash(n: usize) -> Hash {
        Hash::new(format!("sha256:{n:064x}")).unwrap()
    }
    fn request() -> CurrentSignerEvidenceQueryRequestBody {
        serde_json::from_value(serde_json::json!({
            "request_id": "ak:request:019b0000-0000-7000-8000-000000000001",
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "recipient_account_id": {"principal_id":"ak:did_core:web:owner.example", "station_id":"ak:did_core:web:station.example"},
            "queries":[{"sender_kind":"agent", "actor":{"kind":"account", "account_id":{"principal_id":"ak:did_core:web:agent.example", "station_id":"ak:did_core:web:station.example"}}, "verification_method":"did:web:agent.example#runtime"}]
        })).unwrap()
    }
    #[test]
    fn request_rejects_deleted_signal_challenge_and_unknown_state_lists() {
        let request = request();
        request.validate().unwrap();
        for field in ["operation_id", "request_digest", "challenge"] {
            let mut value = serde_json::to_value(&request).unwrap();
            value[field] = serde_json::json!("old-binding");
            assert!(
                serde_json::from_value::<CurrentSignerEvidenceQueryRequestBody>(value).is_err()
            );
        }
        let mut repeated = request;
        repeated.known_agent_state_digests = vec![hash(1), hash(1)];
        assert!(repeated.validate().is_err());
    }
    #[test]
    fn response_transport_has_no_second_signature_or_freshness_clock() {
        let request = request();
        let outcome = CurrentSignerEvidenceQueryOutcome {
            response: CurrentSignerEvidenceResponseCore {
                request_id: request.request_id.clone(),
                realm_id: request.realm_id.clone(),
                recipient_account_id: request.recipient_account_id.clone(),
                evidences: Vec::new(),
            },
        };
        outcome.validate_transport_for_request(&request).unwrap();
        let mut value = serde_json::to_value(outcome).unwrap();
        value["proof"] = serde_json::json!({});
        assert!(serde_json::from_value::<CurrentSignerEvidenceQueryOutcome>(value).is_err());
    }
    #[test]
    fn dependency_graph_rejects_cycles_missing_and_surplus_objects() {
        let good = BTreeMap::from([(hash(1), vec![hash(2)]), (hash(2), Vec::new())]);
        validate_dependency_graph(vec![hash(1)], &good).unwrap();
        let cycle = BTreeMap::from([(hash(1), vec![hash(2)]), (hash(2), vec![hash(1)])]);
        assert!(validate_dependency_graph(vec![hash(1)], &cycle).is_err());
        assert!(validate_dependency_graph(vec![hash(3)], &good).is_err());
        assert!(validate_dependency_graph(vec![hash(2)], &good).is_err());
    }
}

// The own-Station self query that used to live here is now the single unified
// `ak.self.signer_keys.read.resolve.v1` contract in
// `arkret_models_identity::signer_key_operations`. This module keeps only the
// peer surface (`ak.peer.current_signer_evidence.read.resolve.v1`), which has
// its own registered request and outcome shapes.
