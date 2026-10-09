//! Closed portable Agent authority closure and its peer producer sibling.

use arkret_canonical::canonical::{canonical_json_bytes, sha256_digest};
use arkret_wire::{
    AccountId, Base64UrlString, DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyString,
    RealmAuthorityTransition, RealmCommit, RealmCommitId, RealmId, Result, SignerEvidenceRef,
    TypedCurrentRow, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::agent_signer_evidence::{AgentDetachedJws, ControllerAccountGateAttestation};
use crate::{
    AccountDeviceSignerEvidence, AuthenticatedServiceResolution,
    AuthenticatedSignerResolutionEvidence,
};

pub const AGENT_AUTHORITY_EVIDENCE_MAX_CANONICAL_BYTES: usize = 262144;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimePublicKey {
    pub kty: NonEmptyString,
    pub kid: NonEmptyString,
    pub algorithm: NonEmptyString,
    pub key: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorization {
    pub agent_id: DidCoreId,
    pub agent_key_id: NonEmptyString,
    pub verification_method: DidUrl,
    pub public_key: AgentRuntimePublicKey,
    pub public_key_digest: Hash,
    pub controller_principal_id: DidCoreId,
    pub accepted_commit_id: RealmCommitId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyStateWitness {
    pub commit_id: RealmCommitId,
    pub commit: RealmCommit,
    pub result: TypedCurrentRow,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentLifecycleProvenance {
    Genesis { realm_create_event_id: EventId },
    Pause { pause_event_id: EventId },
    Resume { resume_event_id: EventId },
    Deactivate { deactivate_event_id: EventId },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleWitness {
    pub commit_id: RealmCommitId,
    pub commit: RealmCommit,
    pub result: TypedCurrentRow,
    pub accepted_status_event: Event,
    pub provenance: AgentLifecycleProvenance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCommitLineage {
    pub witness_commit_id: RealmCommitId,
    pub predecessor_commit_ids: Vec<RealmCommitId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAcceptedAuthorityBundle {
    pub realm_id: RealmId,
    pub genesis_event: Event,
    pub genesis_commit: RealmCommit,
    pub authority_transitions: Vec<RealmAuthorityTransition>,
    pub signer_histories: Vec<AuthenticatedServiceResolution>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum AgentSignerDependency {
    AccountDevice {
        signer_resolution_evidence_ref: SignerEvidenceRef,
        account_device_signer_evidence: AccountDeviceSignerEvidence,
    },
    Service {
        signer_resolution_evidence_ref: SignerEvidenceRef,
        authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence,
        service_resolution: AuthenticatedServiceResolution,
    },
    Agent {
        signer_resolution_evidence_ref: SignerEvidenceRef,
        agent_evidence: Box<AgentProducerEvidence>,
    },
}

impl AgentSignerDependency {
    pub fn reference(&self) -> &SignerEvidenceRef {
        match self {
            Self::AccountDevice {
                signer_resolution_evidence_ref,
                ..
            }
            | Self::Service {
                signer_resolution_evidence_ref,
                ..
            }
            | Self::Agent {
                signer_resolution_evidence_ref,
                ..
            } => signer_resolution_evidence_ref,
        }
    }
    pub fn computed_reference(&self) -> Result<SignerEvidenceRef> {
        match self {
            Self::AccountDevice {
                account_device_signer_evidence,
                ..
            } => account_device_signer_evidence.signer_evidence_ref(),
            Self::Service {
                authenticated_signer_evidence,
                ..
            } => authenticated_signer_evidence.signer_evidence_ref(),
            Self::Agent { agent_evidence, .. } => agent_evidence
                .authenticated_signer_evidence
                .signer_evidence_ref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorityState {
    pub authority_id: DidCoreId,
    pub agent_id: DidCoreId,
    pub source_commit_id: RealmCommitId,
    pub pcr_genesis_event: Event,
    pub key_authorization_event: Event,
    pub authorization: AgentKeyAuthorization,
    pub key_state_witness: AgentKeyStateWitness,
    pub agent_lifecycle_witness: AgentLifecycleWitness,
    pub commit_lineages: Vec<AgentCommitLineage>,
    pub commits: Vec<RealmCommit>,
    pub authority_bundle: AgentAcceptedAuthorityBundle,
    pub signer_dependencies: Vec<AgentSignerDependency>,
    pub producer_bindings: Vec<AgentProducerBinding>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProducerBinding {
    pub event_ref: EventId,
    pub accepted_commit_id: RealmCommitId,
    pub signer_resolution_evidence_ref: SignerEvidenceRef,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorityStateAttestation {
    pub authority_id: DidCoreId,
    pub verification_method: DidUrl,
    pub state_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

impl AgentAuthorityStateAttestation {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value["proof"]
            .as_object_mut()
            .ok_or_else(|| invalid("missing proof"))?
            .remove("jws");
        let mut bytes = arkret_wire::DomainSeparationId::AGENT_AUTHORITY_STATE_EVIDENCE_V1
            .as_bytes()
            .to_vec();
        bytes.push(b'\n');
        bytes.extend(canonical_json_bytes(&value)?);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorityStateEvidence {
    pub schema: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AgentAuthorityState>,
    pub state_digest: Hash,
    pub attestation: AgentAuthorityStateAttestation,
}

impl AgentAuthorityStateEvidence {
    /// Restore from a previously verified exact digest only. The caller owns
    /// the verified cache; a network response is never a cache hit.
    pub fn restore(&mut self, verified_state: Option<&AgentAuthorityState>) -> Result<()> {
        if self.state.is_none() {
            self.state = Some(
                verified_state
                    .ok_or_else(|| WireError::ProtocolCode {
                        code: arkret_wire::ErrorCode::DependencyMissing,
                        message: "compact Agent state has no verified exact digest cache".into(),
                    })?
                    .clone(),
            );
        }
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| invalid("missing Agent state"))?;
        if self.schema.as_str() != arkret_wire::SchemaId::AGENT_AUTHORITY_STATE_EVIDENCE_V1
            || state.digest()? != self.state_digest
            || self.attestation.state_digest != self.state_digest
            || self.attestation.authority_id != state.authority_id
        {
            return Err(invalid("Agent state digest or attestation binding differs"));
        }
        if canonical_json_bytes(self)?.len() > AGENT_AUTHORITY_EVIDENCE_MAX_CANONICAL_BYTES {
            return Err(invalid("Agent evidence exceeds canonical byte limit"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProducerEvidence {
    pub authenticated_signer_evidence: AuthenticatedSignerResolutionEvidence,
    pub agent_authority_state_evidence: AgentAuthorityStateEvidence,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
    pub authority_resolution: AuthenticatedServiceResolution,
}

impl AgentAuthorityState {
    pub fn digest(&self) -> Result<Hash> {
        Ok(Hash::new(sha256_digest(canonical_json_bytes(self)?))?)
    }
    /// Byte-local complete bindings. Cryptographic validation is owned by
    /// arkret-identity, never by a service-specific duplicate DTO.
    pub fn validate_binding(&self, account: &AccountId) -> Result<()> {
        let genesis = &self.pcr_genesis_event;
        let realm = &genesis.realm_id;
        if self.authority_id != account.station_id
            || self.agent_id != account.principal_id
            || genesis.actor_id.as_account_id() != Some(account)
            || genesis.kind != arkret_wire::EventKind::RealmCreate
            || self.authority_bundle.realm_id != *realm
            || self.authority_bundle.genesis_event != *genesis
            || self.commits.first() != Some(&self.authority_bundle.genesis_commit)
            || self.commits.last().map(|c| &c.commit_id) != Some(&self.source_commit_id)
        {
            return Err(invalid(
                "Agent account, genesis, authority or source cut differs",
            ));
        }
        for (position, commit) in self.commits.iter().enumerate() {
            commit.validate_content_address()?;
            if commit.realm_id != *realm
                || commit.stream_ref != self.authority_bundle.genesis_commit.stream_ref
                || commit.stream_position != position as u64
                || commit.previous_commit_ref.as_ref()
                    != position.checked_sub(1).map(|p| &self.commits[p].commit_id)
            {
                return Err(invalid("Agent Commit closure is discontinuous or forked"));
            }
        }
        let key = &self.key_state_witness;
        let lifecycle = &self.agent_lifecycle_witness;
        for (id, witness) in [
            (&key.commit_id, &key.commit),
            (&lifecycle.commit_id, &lifecycle.commit),
        ] {
            if id != &witness.commit_id
                || self.commits.iter().find(|c| &c.commit_id == id) != Some(witness)
            {
                return Err(invalid("Agent witness has no exact Commit in closure"));
            }
        }
        if self.commit_lineages.len()
            != if key.commit_id == lifecycle.commit_id {
                1
            } else {
                2
            }
        {
            return Err(invalid(
                "Agent lineage set has missing or surplus witnesses",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for lineage in &self.commit_lineages {
            if !seen.insert(&lineage.witness_commit_id)
                || (lineage.witness_commit_id != key.commit_id
                    && lineage.witness_commit_id != lifecycle.commit_id)
            {
                return Err(invalid("Agent lineage is duplicated or surplus"));
            }
            let start = self
                .commits
                .iter()
                .position(|c| c.commit_id == lineage.witness_commit_id)
                .ok_or_else(|| invalid("missing lineage start"))?;
            if lineage.predecessor_commit_ids
                != self.commits[start..]
                    .iter()
                    .map(|c| c.commit_id.clone())
                    .collect::<Vec<_>>()
            {
                return Err(invalid("Agent lineage omits an intermediate Commit"));
            }
        }
        if !self
            .signer_dependencies
            .windows(2)
            .all(|p| p[0].reference() < p[1].reference())
        {
            return Err(invalid(
                "Agent signer dependencies are not sorted and unique",
            ));
        }
        for dependency in &self.signer_dependencies {
            if dependency.computed_reference()? != *dependency.reference() {
                return Err(invalid("Agent signer dependency content ref differs"));
            }
        }
        let authorized = crate::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
            &self.key_authorization_event,
        )?;
        let binding = &self.authorization;
        if authorized.agent_id != self.agent_id
            || authorized.agent_key_id != binding.agent_key_id
            || authorized.verification_method != binding.verification_method
            || authorized.public_key_digest != binding.public_key_digest
            || authorized.controller_principal_id != binding.controller_principal_id
            || authorized.issued_at != binding.issued_at
            || authorized.expires_at != binding.expires_at
            || binding.agent_id != self.agent_id
            || binding.public_key.kid.as_str() != binding.verification_method.as_str()
            || binding.public_key.kty != authorized.public_key.kty
            || binding.public_key.algorithm != authorized.public_key.algorithm
            || binding.public_key.key != authorized.public_key.key
            || binding.accepted_commit_id != key.commit_id
            || binding.accepted_at != key.commit.committed_at
            || key.commit.event_ref != self.key_authorization_event.event_id
            || self.key_authorization_event.realm_id != *realm
            || self.key_authorization_event.actual_signer().as_account_id()
                != Some(&AccountId::new(
                    binding.controller_principal_id.clone(),
                    account.station_id.clone(),
                ))
        {
            return Err(invalid(
                "Agent authorization differs from its accepted controller Event",
            ));
        }
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &key.result;
        if !matches!(selector, arkret_wire::CurrentSelector::AgentKey { agent_id, agent_key_id }
                if agent_id == &self.agent_id && agent_key_id.as_str() == binding.agent_key_id.as_str())
            || source_stream_ref != &key.commit.stream_ref
            || revision.commit_id != key.commit_id
            || revision.stream_position != key.commit.stream_position
        {
            return Err(invalid(
                "Agent key current result has another locator or revision",
            ));
        }
        let entries = value
            .get("authorizations")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| invalid("Agent key result omits authorizations"))?;
        let event = &self.key_authorization_event;
        // agent.key.authorize result_writes[1] is the registered add;
        // result_writes[0] is the optional supersedes loop, not its length.
        let expected_tag = format!("{}:1", event.event_id);
        if value.as_object().is_none_or(|v| v.len() != 1)
            || !entries.iter().any(|entry| {
                entry.get("tag_id").and_then(serde_json::Value::as_str)
                    == Some(expected_tag.as_str())
                    && entry.get("value")
                        == Some(
                            &serde_json::to_value(&event.payload)
                                .unwrap_or(serde_json::Value::Null),
                        )
            })
        {
            return Err(invalid(
                "Agent key result omits the accepted canonical authorization dot",
            ));
        }
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &lifecycle.result;
        let status = &lifecycle.accepted_status_event;
        let (expected_event, expected_kind, expected_status) = match &lifecycle.provenance {
            AgentLifecycleProvenance::Genesis {
                realm_create_event_id,
            } => (
                realm_create_event_id,
                arkret_wire::EventKind::RealmCreate,
                "active",
            ),
            AgentLifecycleProvenance::Pause { pause_event_id } => (
                pause_event_id,
                arkret_wire::EventKind::SelfAgentPause,
                "paused",
            ),
            AgentLifecycleProvenance::Resume { resume_event_id } => (
                resume_event_id,
                arkret_wire::EventKind::SelfAgentResume,
                "active",
            ),
            AgentLifecycleProvenance::Deactivate {
                deactivate_event_id,
            } => (
                deactivate_event_id,
                arkret_wire::EventKind::SelfAgentDeactivate,
                "deactivated",
            ),
        };
        if !matches!(selector, arkret_wire::CurrentSelector::AgentStatus { agent_id } if agent_id == &self.agent_id)
            || source_stream_ref != &lifecycle.commit.stream_ref
            || revision.commit_id != lifecycle.commit_id
            || revision.stream_position != lifecycle.commit.stream_position
            || value.as_str() != Some(expected_status)
            || status.event_id != *expected_event
            || status.kind != expected_kind
            || status.realm_id != *realm
            || lifecycle.commit.event_ref != status.event_id
            || (expected_kind == arkret_wire::EventKind::RealmCreate
                && (status != genesis
                    || status
                        .payload
                        .get("object")
                        .and_then(|o| o.get("purpose"))
                        .and_then(serde_json::Value::as_str)
                        != Some("agent_control")))
        {
            return Err(invalid(
                "Agent lifecycle result differs from its accepted provenance",
            ));
        }
        let mut events = std::collections::BTreeMap::new();
        for event in [genesis, &self.key_authorization_event, status]
            .into_iter()
            .chain(
                self.authority_bundle
                    .authority_transitions
                    .iter()
                    .map(|t| &t.change_event),
            )
        {
            if events
                .insert(&event.event_id, event)
                .is_some_and(|prior| prior != event)
            {
                return Err(invalid("Agent producer Event has conflicting bytes"));
            }
        }
        if self.producer_bindings.len() != events.len()
            || !self
                .producer_bindings
                .windows(2)
                .all(|p| p[0].event_ref < p[1].event_ref)
        {
            return Err(invalid(
                "Agent producer bindings are incomplete, surplus or unordered",
            ));
        }
        let mut used = std::collections::BTreeSet::new();
        for producer in &self.producer_bindings {
            if !events.contains_key(&producer.event_ref)
                || !self.commits.iter().any(|c| {
                    c.commit_id == producer.accepted_commit_id && c.event_ref == producer.event_ref
                })
                || !self
                    .signer_dependencies
                    .iter()
                    .any(|d| d.reference() == &producer.signer_resolution_evidence_ref)
            {
                return Err(invalid(
                    "Agent producer binding has no exact accepted Event, Commit or dependency",
                ));
            }
            used.insert(&producer.signer_resolution_evidence_ref);
        }
        if used.len() != self.signer_dependencies.len() {
            return Err(invalid("Agent signer closure includes unused evidence"));
        }
        Ok(())
    }
}

fn invalid(message: &str) -> WireError {
    WireError::ProtocolCode {
        code: arkret_wire::ErrorCode::SchemaViolation,
        message: message.into(),
    }
}
