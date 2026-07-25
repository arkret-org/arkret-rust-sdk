//! Portable Native Agent signer-evidence wire models.
//!
//! These closed DTOs are the Rust counterparts of
//! `agent-signing-key-binding.schema.json`,
//! `agent-signer-evidence.schema.json`, and
//! `agent-signer-evidence-operations.schema.json`.

use arkret_wire::{Base64UrlString, Did, DidUrl, EventId, Hash, NonEmptyString, RealmId, SealId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const AGENT_SIGNING_KEY_BINDING_SCHEMA: &str = "ak.schema.agent_signing_key_binding.v1";
pub const AGENT_SIGNER_EVIDENCE_SCHEMA: &str = "ak.schema.agent_signer_evidence.v1";
pub const AGENT_SIGNER_EVIDENCE_BUNDLE_SCHEMA: &str = "ak.schema.agent_signer_evidence_bundle.v1";
pub const AGENT_SIGNING_KEY_BINDING_CONTEXT: &str = "ak.agent-signing-key-binding-v1\n";
pub const AGENT_KEY_COMPONENT: &str = "ak.component.agent.key.v1";
pub const KEY_TRANSPARENCY_PROFILE: &str = "ak.profile.key_transparency.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSigningPublicKey {
    pub kty: NonEmptyString,
    pub alg: NonEmptyString,
    pub key: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentControllerProof {
    pub kind: NonEmptyString,
    pub verification_method: DidUrl,
    pub jws: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSigningKeyBinding {
    pub schema: NonEmptyString,
    pub agent_id: Did,
    pub verification_method: DidUrl,
    pub public_key: AgentSigningPublicKey,
    pub public_key_digest: Hash,
    pub agent_key_authorize_event_id: EventId,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub controller_id: Did,
    pub controller_proof: AgentControllerProof,
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
    pub accepted_frontier: NonEmptyString,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub accepted_at: DateTime<Utc>,
    pub valid_from_frontier: NonEmptyString,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_frontier: Option<NonEmptyString>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_event_id: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationStateWitness {
    pub component: NonEmptyString,
    pub agent_id: Did,
    pub authorization_event_id: EventId,
    pub accepted_frontier: NonEmptyString,
    pub seal_id: SealId,
    pub state_root: Hash,
    pub leaf_digest: Hash,
    pub inclusion_proof: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentEvidenceFreshnessAttestation {
    pub source_service_id: Did,
    pub observed_frontier: NonEmptyString,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub http_message_signature: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentEvidenceTransparency {
    pub profile: NonEmptyString,
    pub log_id: NonEmptyString,
    pub tree_size: u64,
    pub root_hash: Hash,
    pub inclusion_proof: Vec<Hash>,
    pub consistency_proof: Vec<Hash>,
    pub witness_signatures: Vec<NonEmptyString>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSignerEvidence {
    pub schema: NonEmptyString,
    pub signing_key_binding: AgentSigningKeyBinding,
    pub authorization: AgentAuthorizationEvidence,
    pub state_witness: AgentAuthorizationStateWitness,
    pub freshness_attestation: AgentEvidenceFreshnessAttestation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<AgentEvidenceTransparency>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSignerEvidenceQuerySelector {
    pub agent_id: Did,
    pub verification_method: DidUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_accepted_frontier: Option<NonEmptyString>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSignerEvidenceQueryRequest {
    pub realm_id: RealmId,
    pub queries: Vec<AgentSignerEvidenceQuerySelector>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSignerEvidenceQueryFailureReason {
    AgentSignerEvidenceMissing,
    AgentSignerEvidenceStale,
    AgentAuthorizationInactive,
    AgentAuthorizationConflicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSignerEvidenceQueryFailure {
    pub selector: AgentSignerEvidenceQuerySelector,
    pub reason: AgentSignerEvidenceQueryFailureReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSignerEvidenceQueryOutcome {
    pub evidence: Vec<AgentSignerEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<AgentSignerEvidenceQueryFailure>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSignerEvidenceBundle {
    pub schema: NonEmptyString,
    pub evidence: Vec<AgentSignerEvidence>,
}
