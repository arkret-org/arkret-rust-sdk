//! Request-bound current signer evidence for cold Signal recipients.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_crypto::DeviceProjectionAttestation;
use arkret_models_identity::{
    AgentCurrentObservation, AgentSignerEvidence, AuthenticatedSignerResolutionEvidence,
};
use arkret_wire::{
    AccountId, ActorId, DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, ProtocolOperationId,
    ProtocolSignature, RealmId, RequestId, ServiceOperationId, SignalEnvelope, WireError,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

pub const CURRENT_SIGNER_EVIDENCE_RESPONSE_DOMAIN: &str = "ak.current_signer_evidence_response.v1";
pub const CURRENT_SIGNER_EVIDENCE_SIGNAL_OPERATION: &str = "ak.self.signal.command.send.v1";
pub const CURRENT_SIGNER_EVIDENCE_MAX_SELECTORS: usize = 16;
pub const CURRENT_SIGNER_EVIDENCE_MAX_LIFETIME_SECONDS: i64 = 30;

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
    pub operation_id: ServiceOperationId,
    pub request_digest: Hash,
    pub recipient_account_id: AccountId,
    pub challenge: NonEmptyString,
    pub queries: Vec<CurrentSignerEvidenceSelector>,
}

impl CurrentSignerEvidenceQueryRequestBody {
    /// Retype this request's UUID payload as the instance-level operation id
    /// bound by an Agent current observation.
    pub fn agent_observation_operation_id(&self) -> arkret_wire::Result<ProtocolOperationId> {
        let payload = self
            .request_id
            .as_str()
            .strip_prefix(RequestId::KIND_PREFIX)
            .ok_or_else(|| {
                WireError::Protocol(
                    "current signer evidence request id has an invalid kind prefix".to_owned(),
                )
            })?;
        ProtocolOperationId::new(format!("ak:operation:{payload}")).map_err(|error| {
            WireError::Protocol(format!(
                "current signer evidence request cannot derive an Agent observation operation id: {error}"
            ))
        })
    }

    fn agent_observation_binds_request(
        &self,
        observation: &AgentCurrentObservation,
    ) -> arkret_wire::Result<bool> {
        let expected_operation_id = self.agent_observation_operation_id()?;
        Ok(observation.operation_id == expected_operation_id
            && observation.request_digest == self.request_digest
            && observation.verifier_id == self.recipient_account_id.station_id
            && observation.audience_id == self.recipient_account_id.principal_id
            && observation.challenge == self.challenge)
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.recipient_account_id.validate()?;
        if self.operation_id != ServiceOperationId::SelfSignalCommandSendV1 {
            return Err(WireError::Protocol(
                "current signer evidence operation must be Signal send".to_owned(),
            ));
        }
        if !(24..=512).contains(&self.challenge.as_str().len()) {
            return Err(WireError::Protocol(
                "current signer evidence challenge length is outside 24..=512".to_owned(),
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
        let digest = Hash::new(arkret_canonical::sha256_digest(
            &arkret_canonical::canonical_json_bytes(envelope)?,
        ))?;
        if self.realm_id != envelope.realm_id
            || self.request_digest != digest
            || self.queries.len() != 1
            || !self.queries[0].matches_envelope(envelope)
        {
            return Err(WireError::Protocol(
                "current signer evidence request does not bind the exact Signal envelope"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "sender_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CurrentSignerEvidenceItem {
    AccountDevice {
        account_id: AccountId,
        device_id: DeviceId,
        device_projection_attestation: DeviceProjectionAttestation,
    },
    Agent {
        actor: ActorId,
        verification_method: DidUrl,
        authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence,
        dependencies: Vec<AuthenticatedSignerResolutionEvidence>,
    },
}

impl CurrentSignerEvidenceItem {
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

    fn validate_binding(
        &self,
        request: &CurrentSignerEvidenceQueryRequestBody,
        issuer_id: &DidCoreId,
        expires_at: DateTime<Utc>,
    ) -> arkret_wire::Result<()> {
        if self.selector().route_service_id() != issuer_id
            || !request.queries.contains(&self.selector())
        {
            return Err(WireError::Protocol(
                "current signer evidence item does not match request authority/selector".to_owned(),
            ));
        }
        match self {
            Self::AccountDevice {
                account_id,
                device_id,
                device_projection_attestation,
            } => {
                let core = &device_projection_attestation.attestation;
                if &core.account_id != account_id
                    || &core.device_id != device_id
                    || core.device_status != arkret_models_crypto::DeviceStatus::Active
                    || core.expires_at < expires_at
                {
                    return Err(WireError::Protocol(
                        "device projection does not bind the outer current evidence item"
                            .to_owned(),
                    ));
                }
            }
            Self::Agent {
                actor,
                verification_method,
                authenticated_signer_evidence,
                dependencies,
            } => {
                let AuthenticatedSignerResolutionEvidence::Agent {
                    signer_id,
                    verification_method: root_method,
                    agent_signer_evidence,
                    ..
                } = authenticated_signer_evidence
                else {
                    return Err(WireError::Protocol(
                        "Agent current evidence item contains a non-Agent root".to_owned(),
                    ));
                };
                let AgentSignerEvidence::CurrentAdmission {
                    current_observation,
                    outer_attestation,
                    ..
                } = agent_signer_evidence.as_ref()
                else {
                    return Err(WireError::Protocol(
                        "Signal current evidence cannot contain historical Agent evidence"
                            .to_owned(),
                    ));
                };
                if signer_id != actor.signing_principal_id()
                    || root_method != verification_method
                    || !request.agent_observation_binds_request(current_observation)?
                    || outer_attestation.expires_at < expires_at
                    || dependencies.is_empty()
                    || dependencies.len() > 64
                {
                    return Err(WireError::Protocol(
                        "Agent evidence does not bind the exact cold-recipient request".to_owned(),
                    ));
                }
                validate_agent_dependency_closure(authenticated_signer_evidence, dependencies)?;
            }
        }
        Ok(())
    }
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

    fn referenced_digests(
        evidence: &AuthenticatedSignerResolutionEvidence,
    ) -> arkret_wire::Result<Vec<Hash>> {
        Ok(match evidence {
            AuthenticatedSignerResolutionEvidence::Service { .. } => Vec::new(),
            AuthenticatedSignerResolutionEvidence::Principal {
                attester_signer_evidence_ref,
                ..
            } => vec![attester_signer_evidence_ref.content_digest()?],
            AuthenticatedSignerResolutionEvidence::Agent {
                attester_signer_evidence_ref,
                controller_signer_evidence_ref,
                account_authority_signer_evidence_ref,
                receiver_signer_evidence_ref,
                ..
            } => vec![
                attester_signer_evidence_ref.content_digest()?,
                controller_signer_evidence_ref.content_digest()?,
                account_authority_signer_evidence_ref.content_digest()?,
                receiver_signer_evidence_ref.content_digest()?,
            ],
        })
    }

    let graph = by_digest
        .iter()
        .map(|(digest, evidence)| Ok((digest.clone(), referenced_digests(evidence)?)))
        .collect::<arkret_wire::Result<BTreeMap<_, _>>>()?;
    validate_dependency_graph(referenced_digests(root)?, &graph)
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
        stack.extend(
            children
                .iter()
                .cloned()
                .into_iter()
                .rev()
                .map(|child| (child, false)),
        );
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
    pub operation_id: ServiceOperationId,
    pub request_digest: Hash,
    pub recipient_account_id: AccountId,
    pub challenge: NonEmptyString,
    pub verifier_id: DidCoreId,
    pub issuer_id: DidCoreId,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub evidences: Vec<CurrentSignerEvidenceItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentSignerEvidenceQueryOutcome {
    pub response: CurrentSignerEvidenceResponseCore,
    pub proof: ProtocolSignature,
}

impl CurrentSignerEvidenceQueryOutcome {
    pub fn proof_signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        let mut bytes = CURRENT_SIGNER_EVIDENCE_RESPONSE_DOMAIN.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes.extend(arkret_canonical::canonical_json_bytes(&self.response)?);
        Ok(bytes)
    }

    pub fn validate_for_request(
        &self,
        request: &CurrentSignerEvidenceQueryRequestBody,
        now: DateTime<Utc>,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        let core = &self.response;
        if core.request_id != request.request_id
            || core.realm_id != request.realm_id
            || core.operation_id != request.operation_id
            || core.request_digest != request.request_digest
            || core.recipient_account_id != request.recipient_account_id
            || core.challenge != request.challenge
            || core.verifier_id != request.recipient_account_id.station_id
            || core.issuer_id != *request.target_station_id()?
        {
            return Err(WireError::Protocol(
                "current signer evidence response does not echo the exact request context"
                    .to_owned(),
            ));
        }
        if core.issued_at >= core.expires_at
            || core.expires_at
                > core.issued_at + Duration::seconds(CURRENT_SIGNER_EVIDENCE_MAX_LIFETIME_SECONDS)
            || now >= core.expires_at
            || self.proof.created_at != core.issued_at
        {
            return Err(WireError::Protocol(
                "current signer evidence response freshness window is invalid".to_owned(),
            ));
        }
        if self.proof.verification_method.as_str().split('#').next()
            == Some(core.verifier_id.as_str())
            && core.verifier_id != core.issuer_id
        {
            return Err(WireError::Protocol(
                "proxy Station must not sign the authority response".to_owned(),
            ));
        }
        let mut selectors = BTreeSet::new();
        for item in &core.evidences {
            item.validate_binding(request, &core.issuer_id, core.expires_at)?;
            if !selectors.insert(arkret_canonical::canonical_json_bytes(&item.selector())?) {
                return Err(WireError::Protocol(
                    "current signer evidence outcome repeats a selector".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Base64UrlString, SealId};
    use chrono::TimeZone as _;

    use super::*;

    fn account(principal: &str, station: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new(station).unwrap(),
        )
    }

    fn request() -> CurrentSignerEvidenceQueryRequestBody {
        CurrentSignerEvidenceQueryRequestBody {
            request_id: RequestId::new("ak:request:019b0000-0000-7000-8000-000000000001").unwrap(),
            realm_id: RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5")
                .unwrap(),
            operation_id: ServiceOperationId::SelfSignalCommandSendV1,
            request_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            recipient_account_id: account(
                "ak:did_core:webvh:z6mkrecipient",
                "ak:did_core:webvh:z6mkstation-b",
            ),
            challenge: NonEmptyString::new(format!("ak.challenge.{}", "A".repeat(24))).unwrap(),
            queries: vec![CurrentSignerEvidenceSelector::AccountDevice {
                account_id: account(
                    "ak:did_core:webvh:z6mksender",
                    "ak:did_core:webvh:z6mkstation-a",
                ),
                device_id: DeviceId::new("ak:device:019b0000-0000-7000-8000-000000000002").unwrap(),
            }],
        }
    }

    fn agent_observation(
        request: &CurrentSignerEvidenceQueryRequestBody,
    ) -> AgentCurrentObservation {
        let evaluated_at = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).single().unwrap();
        AgentCurrentObservation {
            operation_id: request.agent_observation_operation_id().unwrap(),
            request_digest: request.request_digest.clone(),
            verifier_id: request.recipient_account_id.station_id.clone(),
            audience_id: request.recipient_account_id.principal_id.clone(),
            challenge: request.challenge.clone(),
            agent_snapshot_digest: graph_hash(10),
            agent_key_seal_id: SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).unwrap(),
            agent_status_seal_id: SealId::new(format!("ak:seal:sha256:{}", "c".repeat(64)))
                .unwrap(),
            controller_gate_attestation_digest: graph_hash(11),
            evaluated_at,
            expires_at: evaluated_at + Duration::seconds(30),
        }
    }

    #[test]
    fn agent_observation_operation_id_retypes_the_request_payload() {
        let request = request();

        assert_eq!(
            request.agent_observation_operation_id().unwrap().as_str(),
            "ak:operation:019b0000-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn agent_observation_binding_rejects_a_different_operation_instance() {
        let request = request();
        let mut observation = agent_observation(&request);
        assert!(
            request
                .agent_observation_binds_request(&observation)
                .unwrap()
        );

        observation.operation_id =
            ProtocolOperationId::new("ak:operation:019b0000-0000-7000-8000-000000000099").unwrap();
        assert!(
            !request
                .agent_observation_binds_request(&observation)
                .unwrap()
        );
    }

    fn outcome(
        request: &CurrentSignerEvidenceQueryRequestBody,
    ) -> CurrentSignerEvidenceQueryOutcome {
        let issued_at = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).single().unwrap();
        CurrentSignerEvidenceQueryOutcome {
            response: CurrentSignerEvidenceResponseCore {
                request_id: request.request_id.clone(),
                realm_id: request.realm_id.clone(),
                operation_id: request.operation_id.clone(),
                request_digest: request.request_digest.clone(),
                recipient_account_id: request.recipient_account_id.clone(),
                challenge: request.challenge.clone(),
                verifier_id: request.recipient_account_id.station_id.clone(),
                issuer_id: request.target_station_id().unwrap().clone(),
                issued_at,
                expires_at: issued_at + Duration::seconds(30),
                evidences: Vec::new(),
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new("did:webvh:z6mkstation-a#notary-key").unwrap(),
                created_at: issued_at,
                jws: Base64UrlString::new("AAAA").unwrap(),
            },
        }
    }

    #[test]
    fn agent_selector_rejects_service_actor_and_batch_rejects_mixed_stations() {
        let mut body = request();
        body.queries = vec![CurrentSignerEvidenceSelector::Agent {
            actor: ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkservice").unwrap()),
            verification_method: DidUrl::new("did:webvh:z6mkservice#runtime").unwrap(),
        }];
        assert!(body.validate().is_err());

        body = request();
        body.queries
            .push(CurrentSignerEvidenceSelector::AccountDevice {
                account_id: account(
                    "ak:did_core:webvh:z6mkother",
                    "ak:did_core:webvh:z6mkstation-c",
                ),
                device_id: DeviceId::new("ak:device:019b0000-0000-7000-8000-000000000003").unwrap(),
            });
        assert!(body.validate().is_err());
    }

    #[test]
    fn response_rejects_replayed_or_rewritten_request_context() {
        let request = request();
        let now = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 1).single().unwrap();
        let valid = outcome(&request);
        valid.validate_for_request(&request, now).unwrap();

        let mut changed_challenge = valid.clone();
        changed_challenge.response.challenge =
            NonEmptyString::new(format!("ak.challenge.{}", "B".repeat(24))).unwrap();
        assert!(
            changed_challenge
                .validate_for_request(&request, now)
                .is_err()
        );

        let mut proxy_issuer = valid;
        proxy_issuer.response.issuer_id = request.recipient_account_id.station_id.clone();
        assert!(proxy_issuer.validate_for_request(&request, now).is_err());
    }

    fn graph_hash(index: usize) -> Hash {
        Hash::new(format!("sha256:{index:064x}")).unwrap()
    }

    #[test]
    fn agent_dependency_graph_is_cycle_free_exact_and_bounded() {
        let root = graph_hash(1);
        let leaf = graph_hash(2);
        let valid = BTreeMap::from([
            (root.clone(), vec![leaf.clone()]),
            (leaf.clone(), Vec::new()),
        ]);
        validate_dependency_graph(vec![root.clone()], &valid).unwrap();

        let cycle = BTreeMap::from([
            (root.clone(), vec![leaf.clone()]),
            (leaf.clone(), vec![root.clone()]),
        ]);
        assert!(validate_dependency_graph(vec![root.clone()], &cycle).is_err());

        let surplus = BTreeMap::from([(root.clone(), Vec::new()), (leaf.clone(), Vec::new())]);
        assert!(validate_dependency_graph(vec![root], &surplus).is_err());

        let too_many = (1..=65)
            .map(|index| (graph_hash(index), Vec::new()))
            .collect();
        assert!(validate_dependency_graph(vec![graph_hash(1)], &too_many).is_err());
    }
}
