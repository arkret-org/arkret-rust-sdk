//! Agent-lifecycle and agent-key payloads.

use arkret_wire::serde_helpers::{
    deserialize_canonical_timestamp, deserialize_optional_canonical_timestamp,
    serialize_canonical_timestamp, serialize_optional_canonical_timestamp,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_approve_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionApprovePayload {
    pub approval_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
    pub agent_id: Did,
    pub controller_id: Did,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub approved_payload_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_content_digest: Option<Hash>,
    pub approval_nonce: String,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub approved_at: DateTime<Utc>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_reject_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionRejectPayload {
    pub rejection_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
    pub agent_id: Did,
    pub controller_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub rejected_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_request_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionRequestPayload {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
    pub agent_id: Did,
    pub controller_id: Did,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub request_canonical_digest: Hash,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_target`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionTarget {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data_key: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_deactivate_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDeactivatePayload {
    pub agent_id: Did,
    pub controller_id: Did,
    pub transition: String,
    pub previous_status: String,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_draft_propose_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftProposePayload {
    pub draft_id: String,
    pub agent_id: Did,
    pub controller_id: Did,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub content_digest: Hash,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data_key: Option<String>,
}
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`
/// `kind` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyApprovalEvidenceKind {
    CapabilityGrant,
    ApprovalEvent,
    ProposalEvent,
    PolicyEvent,
    PairingRequest,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyApprovalEvidence {
    pub kind: AgentKeyApprovalEvidenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    /// Profile-local pairing artifact. Present only when this authorization
    /// accepts an agent runtime pairing request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<Did>,
}

/// Counterpart for the `agent_key_scope.resources[].kind` enum in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyScopeResourceKind {
    Realm,
    Space,
    Circle,
    Strand,
    Message,
    Morph,
    Object,
    Relation,
    View,
    Event,
    Actor,
    Schema,
    Policy,
    Invite,
    Notification,
    ReadCursor,
    Blob,
    Operation,
    Service,
}

/// Counterpart for the `agent_key_scope.resources[]` item shape in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyScopeResource {
    pub kind: AgentKeyScopeResourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`
/// (also `agent-operations.schema.json#/$defs/agent_key_scope` via `$ref`).
///
/// Scope object used as the required immutable provision ceiling and as a
/// narrower per-key ceiling. `actions` may include service operation ids and
/// content capability action tokens. Provisioning records it but grants no
/// Realm access; later key scopes, Realm grants, participation and sessions
/// must remain subsets, and provision constraints stay mandatory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyScope {
    pub actions: Vec<String>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub resources: Vec<AgentKeyScopeResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub constraints: Vec<GrantConstraint>,
}

/// Counterpart for the `runtime_attestation.kind` enum in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
/// v1 registers only `self_asserted`; unknown kinds fail closed at decode
/// (AKP-0008 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentKeyRuntimeAttestationKind {
    SelfAsserted,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`
/// `runtime_attestation` object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyAuthorizePayloadRuntimeAttestation {
    pub kind: AgentKeyRuntimeAttestationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<ObjectRef>,
}

/// One active authorization dot atomically replaced by a controller-signed
/// runtime re-pairing authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeySupersession {
    pub key_id: String,
    pub authorized_event_ref: EventId,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizePayload {
    pub agent_id: Did,
    pub key_id: String,
    /// DID URL for the runtime signing key, including its key fragment.
    pub verification_method: String,
    pub public_key_digest: Hash,
    pub signing_key_binding_digest: Hash,
    pub accountable_principal_id: Did,
    pub agent_key_scope: AgentKeyScope,
    pub audience: Vec<String>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    /// Optional: absent means the key authorization is non-expiring and
    /// governed solely by revocation (key-management.md §3.6.1).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub approval_evidence: AgentKeyApprovalEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<AgentKeySupersession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_check_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyRevokePayload {
    pub agent_id: Did,
    pub key_id: String,
    pub revoked_by: Did,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub revoked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_pause_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPausePayload {
    pub agent_id: Did,
    pub controller_id: Did,
    pub transition: String,
    pub previous_status: String,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_resume_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResumePayload {
    pub agent_id: Did,
    pub controller_id: Did,
    pub transition: String,
    pub previous_status: String,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub status_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_exposure_ack: Option<AgentSidecarExposureAck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_sidecar_exposure_ack`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSidecarExposureAck {
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub acknowledged_at: DateTime<Utc>,
    pub acknowledged_by: Did,
    pub sidecar_refs: Vec<ObjectRef>,
}
