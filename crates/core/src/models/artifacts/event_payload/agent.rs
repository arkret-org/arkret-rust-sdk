//! Agent-lifecycle, agent-key, and agent-interop-session payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

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
    pub agent_principal_id: Did,
    pub controller_principal_id: Did,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub approved_payload_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_content_digest: Option<Hash>,
    pub approval_nonce: String,
    pub approved_at: DateTime<Utc>,
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
    pub agent_principal_id: Did,
    pub controller_principal_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    pub agent_principal_id: Did,
    pub controller_principal_id: Did,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub request_canonical_digest: Hash,
    pub expires_at: DateTime<Utc>,
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
    pub r#ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data_key: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_deactivate_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDeactivatePayload {
    pub agent_principal_id: Did,
    pub controller_principal_id: Did,
    pub transition: String,
    pub previous_status: String,
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
    pub agent_principal_id: Did,
    pub controller_principal_id: Did,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub content_digest: Hash,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data_key: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_endpoint_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEndpointPayload {
    pub agent_id: Did,
    pub endpoints: Vec<BTreeMap<String, Value>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// agent_interop_session_result_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInteropSessionResultPayload {
    pub session_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_objects: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_retention: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_artifact_stub: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_transcript_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_cancel_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_required: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// agent_interop_session_start_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInteropSessionStartPayload {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_strand_id: Option<StrandId>,
    pub counterparty_agent: Did,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    pub capability_grant: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_artifact_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_mode: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// agent_interop_session_status_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInteropSessionStatusPayload {
    pub session_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_basis_points: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_by: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_at: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_cancel_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_required: Option<Vec<String>>,
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
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyApprovalEvidence {
    pub kind: AgentKeyApprovalEvidenceKind,
    pub r#ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<Did>,
}

/// Counterpart for the `agent_key_scope.resources[].kind` enum in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyScopeResourceKind {
    Realm,
    Strand,
    Space,
    Object,
    Operation,
    Service,
}

/// Counterpart for the `agent_key_scope.resources[]` item shape in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentKeyScopeResource {
    pub kind: AgentKeyScopeResourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_scope`
/// (also `agent-operations.schema.json#/$defs/agent_key_scope` via `$ref`).
///
/// Closed authorization scope for an agent signing key: `actions` and
/// `resources` are both explicit so the key cannot silently widen its
/// authority through omitted dimensions. `actions` may include service
/// operation ids and content capability action tokens; service-surface scope
/// is not derived solely from content capability grants.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentKeyScope {
    pub actions: Vec<String>,
    pub resources: Vec<AgentKeyScopeResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
}

/// Counterpart for the `runtime_attestation.kind` enum in
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
/// v1 registers only `self_asserted`; unknown kinds fail closed at decode
/// (CKP-0008 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyRuntimeAttestationKind {
    SelfAsserted,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`
/// `runtime_attestation` object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizePayloadRuntimeAttestation {
    pub kind: AgentKeyRuntimeAttestationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<ObjectRef>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizePayload {
    pub agent_principal_id: Did,
    pub key_id: String,
    /// DID URL for the runtime signing key, including its key fragment.
    pub verification_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_digest: Option<Hash>,
    pub accountable_principal_id: Did,
    pub agent_key_scope: AgentKeyScope,
    pub audience: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approval_evidence: AgentKeyApprovalEvidence,
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
    pub agent_principal_id: Did,
    pub key_id: String,
    pub revoked_by: Did,
    pub revoked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_rotate_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyRotatePayload {
    pub agent_principal_id: Did,
    pub key_id: String,
    pub replacement_key_id: String,
    /// DID URL for the replacement runtime signing key, including its key fragment.
    pub replacement_verification_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_public_key_digest: Option<Hash>,
    pub accountable_principal_id: Did,
    pub agent_key_scope: AgentKeyScope,
    pub audience: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approval_evidence: AgentKeyApprovalEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_authorization_ref: Option<EventRef>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_lifecycle_frontier`.
pub type AgentLifecycleFrontier = BTreeMap<String, Value>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_pause_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPausePayload {
    pub agent_principal_id: Did,
    pub controller_principal_id: Did,
    pub transition: String,
    pub previous_status: String,
    pub status_changed_at: DateTime<Utc>,
    pub freshness_frontier: AgentLifecycleFrontier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_resume_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResumePayload {
    pub agent_principal_id: Did,
    pub controller_principal_id: Did,
    pub transition: String,
    pub previous_status: String,
    pub status_changed_at: DateTime<Utc>,
    pub freshness_frontier: AgentLifecycleFrontier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_exposure_ack: Option<AgentSidecarExposureAck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_sidecar_exposure_ack`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExposureAck {
    pub acknowledged_at: DateTime<Utc>,
    pub acknowledged_by: Did,
    pub sidecar_refs: Vec<ObjectRef>,
}
