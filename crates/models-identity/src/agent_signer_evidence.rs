//! Current and historical portable Agent signer-evidence wire models.
//!
//! Current admission and historical verification are deliberately different
//! enum branches. Historical validity applies the verified authorization
//! closure observed with the publication.

use arkret_wire::{
    Base64UrlString, DidCoreId, DidUrl, Event, EventId, Hash, NonEmptyString, RealmId, RequestId,
    Seal, SealId, SignerEvidenceRef,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const AGENT_KEY_COMPONENT: &str = arkret_wire::CellFamilyId::AGENT_KEY_V1;
pub const AGENT_STATUS_COMPONENT: &str = arkret_wire::CellFamilyId::AGENT_STATUS_V1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSigningPublicKey {
    pub kty: NonEmptyString,
    pub algorithm: NonEmptyString,
    pub key: Base64UrlString,
}

/// In-memory projection of the key authenticated by one complete authorize Event.
/// This view is never a second wire certificate or an authority source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAuthorizedSigningKey {
    pub agent_id: DidCoreId,
    pub agent_key_id: NonEmptyString,
    pub verification_method: DidUrl,
    pub public_key: AgentSigningPublicKey,
    pub public_key_digest: Hash,
    pub agent_key_authorize_event_id: EventId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub controller_principal_id: DidCoreId,
}

impl AgentAuthorizedSigningKey {
    /// Parse public key material; callers must separately verify Event/Seal authority.
    pub fn from_event(event: &Event) -> Result<Self, arkret_wire::WireError> {
        let invalid = |reason: &str| arkret_wire::WireError::Protocol(reason.to_owned());
        if event.kind != arkret_wire::EventKind::AgentKeyAuthorize {
            return Err(invalid("Agent key source must be an authorize Event"));
        }
        let field = |name: &str| {
            event
                .payload
                .get(name)
                .cloned()
                .ok_or_else(|| invalid("authorize Event omits key material"))
        };
        let verification_method: DidUrl = serde_json::from_value(field("verification_method")?)?;
        let key = field("public_key")?;
        if key.get("kid").and_then(Value::as_str) != Some(verification_method.as_str())
            || key.get("kty").and_then(Value::as_str) != Some("OKP")
            || key.get("algorithm").and_then(Value::as_str) != Some("Ed25519")
            || key.as_object().is_none_or(|key| key.len() != 4)
        {
            return Err(invalid(
                "authorize Event has an invalid Ed25519 key profile",
            ));
        }
        let public_key = AgentSigningPublicKey {
            kty: serde_json::from_value(key["kty"].clone())?,
            algorithm: serde_json::from_value(key["algorithm"].clone())?,
            key: serde_json::from_value(key["key"].clone())?,
        };
        let raw = arkret_canonical::base64url_decode(public_key.key.as_str())?;
        if raw.len() != 32 || arkret_canonical::base64url_encode(&raw) != public_key.key.as_str() {
            return Err(invalid(
                "authorize Event key is not canonical Ed25519 material",
            ));
        }
        Ok(Self {
            agent_id: serde_json::from_value(field("agent_id")?)?,
            agent_key_id: serde_json::from_value(field("key_id")?)?,
            verification_method,
            public_key,
            public_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&raw))
                .map_err(|error| invalid(&error.to_string()))?,
            agent_key_authorize_event_id: event.event_id.clone(),
            issued_at: serde_json::from_value(field("issued_at")?)?,
            expires_at: event
                .payload
                .get("expires_at")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            controller_principal_id: serde_json::from_value(field("accountable_principal_id")?)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorizationStatus {
    Active,
    Revoked,
    Superseded,
    Expired,
    Conflicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationEvidence {
    pub status: AgentAuthorizationStatus,
    pub authorized_event_id: EventId,
    pub accepted_seal_id: SealId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_seal_id: Option<SealId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentKeyCellEntry {
    pub tag: NonEmptyString,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationStateWitness {
    pub component: NonEmptyString,
    pub agent_id: DidCoreId,
    pub authorization_event_id: EventId,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub seal: Seal,
    pub cell_ref: NonEmptyString,
    pub cell_value: Vec<AgentKeyCellEntry>,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationTransitionWitness {
    pub component: NonEmptyString,
    pub agent_id: DidCoreId,
    pub authorization_event_id: EventId,
    pub transition_event_id: EventId,
    pub transition_key_id: NonEmptyString,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub seal: Seal,
    pub cell_ref: NonEmptyString,
    pub cell_value: Vec<AgentKeyCellEntry>,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentLifecycleStatus {
    Active,
    Paused,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentLifecycleProvenance {
    DelegatedPcrGenesis { realm_create_event_id: EventId },
    PauseAccepted { pause_event_id: EventId },
    ResumeAccepted { resume_event_id: EventId },
    DeactivateAccepted { deactivate_event_id: EventId },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentLifecycleWitness {
    pub component: NonEmptyString,
    pub agent_id: DidCoreId,
    pub provenance: AgentLifecycleProvenance,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub accepted_status_event: Event,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub seal: Seal,
    pub cell_ref: NonEmptyString,
    pub cell_value: AgentLifecycleStatus,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub inclusion_proof: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentDetachedJws {
    pub kind: NonEmptyString,
    pub jws: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAuthorityStateAttestation {
    pub authority_kind: NonEmptyString,
    pub authority_id: DidCoreId,
    pub verification_method: DidUrl,
    pub state_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAuthorityState {
    pub authority_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub pcr_genesis_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub key_authorization_event: Event,
    pub frontier_seal_id: SealId,
    pub frontier_state_root: Hash,
    pub authorization: AgentAuthorizationEvidence,
    pub key_state_witness: AgentAuthorizationStateWitness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_transition_witness: Option<AgentAuthorizationTransitionWitness>,
    pub agent_lifecycle_witness: AgentLifecycleWitness,
    pub seal_lineages: Vec<Seal>,
    pub accepted_delegated_notary_signers: Vec<arkret_wire::NotarySignerDescriptor>,
}

impl AgentAuthorityState {
    pub fn authorized_key(&self) -> Result<AgentAuthorizedSigningKey, arkret_wire::WireError> {
        AgentAuthorizedSigningKey::from_event(&self.key_authorization_event)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAuthorityStateEvidence {
    pub state: AgentAuthorityState,
    pub state_digest: Hash,
    pub attestation: AgentAuthorityStateAttestation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountGateBasis {
    AccountBindingDefault {
        binding_version: u64,
        binding_frontier_digest: Hash,
    },
    AccountStatusEvent {
        status_event_id: EventId,
        status_frontier_digest: Hash,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountEligibility {
    Active,
    Inactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestation {
    pub schema: NonEmptyString,
    pub principal_id: DidCoreId,
    pub eligibility: ControllerAccountEligibility,
    pub status: ControllerAccountStatus,
    pub basis: ControllerAccountGateBasis,
    pub basis_digest: Hash,
    pub authority_id: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

/// Authenticated S2S request used by an Agent PCR authority to obtain
/// the Account Authority-owned controller lifecycle gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestationIssueRequestBody {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub agent_authority_id: DidCoreId,
    pub agent_authority_resolution: crate::AuthenticatedServiceResolution,
}

/// Byte-stable result of controller gate attestation issuance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestationIssueOutcome {
    pub request_id: RequestId,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentAdmissionEvidence {
    pub agent_authority_state_evidence: AgentAuthorityStateEvidence,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
    pub admission_evidence_digest: Hash,
}

impl AgentAdmissionEvidence {
    /// Earliest instant at which all independently signed sources apply.
    pub fn valid_from(&self) -> DateTime<Utc> {
        let state = &self.agent_authority_state_evidence;
        [
            state.attestation.issued_at,
            self.controller_account_gate_attestation.issued_at,
            state.state.authorization.accepted_at,
            state.state.authorization.not_before,
        ]
        .into_iter()
        .max()
        .expect("authority attestation has an observation time")
    }
    /// End of the initial current-query consumption window. Persisted
    /// publication evidence retains the original observation after this time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        let state = &self.agent_authority_state_evidence;
        [
            Some(state.attestation.expires_at),
            Some(self.controller_account_gate_attestation.expires_at),
            state.state.authorization.expires_at,
        ]
        .into_iter()
        .flatten()
        .min()
        .expect("authority attestation has an expiry")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentEvidenceTransparency {
    pub profile: NonEmptyString,
    pub log_id: NonEmptyString,
    pub leaf_count: u64,
    pub tree_root: Hash,
    pub inclusion_proof: Vec<Hash>,
    pub consistency_proof: Vec<Hash>,
    pub witness_signatures: Vec<NonEmptyString>,
}

/// Closed `current_admission_evidence` branch used when a peer KeyPackage
/// response must carry target Agent authority without permitting the
/// historical-event branch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "verification_mode",
    rename = "current_admission",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentAgentSignerEvidence {
    pub schema: NonEmptyString,
    pub admission_evidence: AgentAdmissionEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<AgentEvidenceTransparency>,
}

impl From<CurrentAgentSignerEvidence> for AgentSignerEvidence {
    fn from(value: CurrentAgentSignerEvidence) -> Self {
        Self::CurrentAdmission {
            schema: value.schema,
            admission_evidence: value.admission_evidence,
            transparency: value.transparency,
        }
    }
}

impl From<&CurrentAgentSignerEvidence> for AgentSignerEvidence {
    fn from(value: &CurrentAgentSignerEvidence) -> Self {
        value.clone().into()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "verification_mode",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentSignerEvidence {
    CurrentAdmission {
        schema: NonEmptyString,
        admission_evidence: AgentAdmissionEvidence,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency: Option<AgentEvidenceTransparency>,
    },
    HistoricalEvent {
        schema: NonEmptyString,
        admission_evidence: AgentAdmissionEvidence,
        authorization_closure_refs: Vec<SealId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency: Option<AgentEvidenceTransparency>,
    },
}

impl AgentSignerEvidence {
    pub fn admission_evidence(&self) -> &AgentAdmissionEvidence {
        match self {
            Self::CurrentAdmission {
                admission_evidence, ..
            }
            | Self::HistoricalEvent {
                admission_evidence, ..
            } => admission_evidence,
        }
    }
    pub fn required_historical_signer_refs(&self) -> Vec<&SignerEvidenceRef> {
        let state = &self
            .admission_evidence()
            .agent_authority_state_evidence
            .state;
        [
            &state.pcr_genesis_event,
            &state.key_authorization_event,
            &state.agent_lifecycle_witness.accepted_status_event,
        ]
        .into_iter()
        .filter_map(|event| event.proofs.first())
        .filter_map(|proof| proof.signer_resolution_evidence_ref.as_ref())
        .collect()
    }
}

pub use arkret_wire::StationSigningKey;
pub const SELF_SIGNER_REQUEST_MAX_BYTES: usize = 64 * 1024;
pub const SELF_SIGNER_OUTCOME_MAX_BYTES: usize = 1024 * 1024;
pub const SELF_SIGNER_RESULT_MAX_BYTES: usize = 16 * 1024;
pub fn self_signer_error(code: arkret_wire::ErrorCode, message: &str) -> arkret_wire::WireError {
    arkret_wire::WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}
pub fn validate_self_signer_bytes<T: Serialize>(
    value: &T,
    limit: usize,
    request: bool,
) -> arkret_wire::Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > limit {
        return Err(self_signer_error(
            if request {
                arkret_wire::ErrorCode::PayloadTooLarge
            } else {
                arkret_wire::ErrorCode::LimitExceeded
            },
            "self signer canonical byte budget exceeded",
        ));
    }
    Ok(())
}
// The self-path query surface that used to live here - selectors, request
// body, per-selector results and outcome - is now the single unified
// `ak.self.signer_keys.read.resolve.v1` contract in
// `crate::signer_key_operations`. The old `self/agent-signer-evidence/query`
// and `self/current-signer-evidence/query` operations no longer exist, so their
// DTOs are gone rather than kept as a second shape. The key and status types
// below stay: the unified surface reuses them verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerEvidenceResolvedStatus {
    Resolved,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerEvidenceUnavailableStatus {
    Unavailable,
}
#[cfg(test)]
mod self_signer_tests {
    use super::*;

    fn key() -> StationSigningKey {
        StationSigningKey {
            actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            verification_method: DidUrl::new("did:web:agent.example#agent-key").unwrap(),
            public_key_b64u: Base64UrlString::new("A".repeat(43)).unwrap(),
            authorization_ref: EventId::new(
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            )
            .unwrap(),
        }
    }

    #[test]
    fn self_signer_key_rejects_wrong_method_principal_and_noncanonical_padding_bits() {
        let mut value = key();
        value.verification_method = DidUrl::new("did:web:other.example#agent-key").unwrap();
        assert!(value.validate().is_err());
        value = key();
        if let Ok(noncanonical) = Base64UrlString::new(format!("{}B", "A".repeat(42))) {
            value.public_key_b64u = noncanonical;
            assert!(value.validate().is_err());
        }
    }

    #[test]
    fn self_signer_key_requires_an_account_actor() {
        let mut value = key();
        value.actor =
            arkret_wire::ActorId::service(DidCoreId::new("ak:did_core:web:agent.example").unwrap());
        assert!(value.validate().is_err());
    }
}
