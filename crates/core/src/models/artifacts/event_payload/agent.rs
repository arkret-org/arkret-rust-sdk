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

/// External protocol carried on `ck.agent.interop_session.start`
/// (`event-payload.schema.json#/$defs/agent_interop_session_start_payload`
/// `protocol` enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentInteropProtocol {
    A2a,
    Acp,
    McpBridge,
    HttpCustom,
}

impl AgentInteropProtocol {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::A2a => "a2a",
            Self::Acp => "acp",
            Self::McpBridge => "mcp_bridge",
            Self::HttpCustom => "http_custom",
        }
    }
}

/// Canonical session state for `ck.agent.interop_session.status`
/// (`event-payload.schema.json#/$defs/agent_interop_session_status_payload`
/// `status` enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentInteropSessionStatus {
    Negotiating,
    Accepted,
    Working,
    InputRequired,
    Blocked,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

impl AgentInteropSessionStatus {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Negotiating => "negotiating",
            Self::Accepted => "accepted",
            Self::Working => "working",
            Self::InputRequired => "input_required",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

/// Terminal status for `ck.agent.interop_session.result`
/// (`event-payload.schema.json#/$defs/agent_interop_session_result_payload`
/// `status` enum: the closed terminal subset of the session state machine).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentInteropResultStatus {
    Completed,
    Failed,
    Cancelled,
    Expired,
}

impl AgentInteropResultStatus {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

impl AgentInteropSessionStartPayload {
    /// Build a `ck.agent.interop_session.start` payload. Required per spec:
    /// `session_id`, `counterparty_agent`, `protocol`, `capability_grant`.
    pub fn new(
        session_id: impl Into<String>,
        counterparty_agent: Did,
        protocol: AgentInteropProtocol,
        capability_grant: GrantId,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            task_strand_id: None,
            counterparty_agent,
            protocol: protocol.as_wire().to_owned(),
            external_protocol_version: None,
            endpoint_ref: None,
            capability_grant,
            allowed_artifact_types: None,
            max_duration_seconds: None,
            audit_mode: None,
        }
    }

    pub fn with_task_strand_id(mut self, task_strand_id: StrandId) -> Self {
        self.task_strand_id = Some(task_strand_id);
        self
    }

    pub fn with_external_protocol_version(mut self, version: impl Into<String>) -> Self {
        self.external_protocol_version = Some(version.into());
        self
    }

    pub fn with_endpoint_ref(mut self, endpoint_ref: impl Into<String>) -> Self {
        self.endpoint_ref = Some(endpoint_ref.into());
        self
    }

    pub fn with_allowed_artifact_types(mut self, allowed_artifact_types: Vec<String>) -> Self {
        self.allowed_artifact_types = Some(allowed_artifact_types);
        self
    }

    pub fn with_max_duration_seconds(mut self, max_duration_seconds: u64) -> Self {
        self.max_duration_seconds = Some(max_duration_seconds);
        self
    }

    pub fn with_audit_mode(mut self, audit_mode: impl Into<String>) -> Self {
        self.audit_mode = Some(audit_mode.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|err| {
            Error::Protocol(format!(
                "agent interop session start payload serialize: {err}"
            ))
        })
    }
}

impl AgentInteropSessionStatusPayload {
    /// Build a `ck.agent.interop_session.status` payload. Required per spec:
    /// `session_id`, `status`.
    pub fn new(session_id: impl Into<String>, status: AgentInteropSessionStatus) -> Self {
        Self {
            session_id: session_id.into(),
            status: status.as_wire().to_owned(),
            external_task_id: None,
            last_update_at: None,
            progress_basis_points: None,
            summary: None,
            cancelled_by: None,
            cancelled_at: None,
            reason_code: None,
            external_cancel_ref: None,
            cleanup_required: None,
        }
    }

    pub fn with_external_task_id(mut self, external_task_id: impl Into<String>) -> Self {
        self.external_task_id = Some(external_task_id.into());
        self
    }

    pub fn with_last_update_at(mut self, last_update_at: DateTime<Utc>) -> Self {
        self.last_update_at = Some(last_update_at);
        self
    }

    /// Progress in basis points (0..=10000). Values above 10000 are rejected by
    /// the spec schema; callers pass the already-scaled integer.
    pub fn with_progress_basis_points(mut self, progress_basis_points: u64) -> Self {
        self.progress_basis_points = Some(progress_basis_points);
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Attach the cancellation surface (spec §5.3): set when `status=cancelled`.
    pub fn with_cancellation(
        mut self,
        cancelled_by: Did,
        cancelled_at: DateTime<Utc>,
        reason_code: impl Into<String>,
    ) -> Self {
        self.cancelled_by = Some(Value::String(cancelled_by.as_str().to_owned()));
        self.cancelled_at = Some(Value::String(cancelled_at.to_rfc3339()));
        self.reason_code = Some(Value::String(reason_code.into()));
        self
    }

    pub fn with_external_cancel_ref(mut self, external_cancel_ref: impl Into<String>) -> Self {
        self.external_cancel_ref = Some(external_cancel_ref.into());
        self
    }

    pub fn with_cleanup_required(mut self, cleanup_required: Vec<String>) -> Self {
        self.cleanup_required = Some(cleanup_required);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|err| {
            Error::Protocol(format!(
                "agent interop session status payload serialize: {err}"
            ))
        })
    }
}

impl AgentInteropSessionResultPayload {
    /// Build a `ck.agent.interop_session.result` payload. Required per spec:
    /// `session_id`, `status`. The schema additionally requires at least one of
    /// `result_objects` / `artifacts` / `reason_code`, and — when
    /// `status=cancelled` — `cancelled_by`, `cancelled_at`, `reason_code`,
    /// `artifact_retention`. [`Self::to_value`] enforces both.
    pub fn new(session_id: impl Into<String>, status: AgentInteropResultStatus) -> Self {
        Self {
            session_id: session_id.into(),
            status: status.as_wire().to_owned(),
            result_objects: None,
            artifacts: None,
            artifact_retention: None,
            external_artifact_stub: None,
            external_transcript_digest: None,
            completed_at: None,
            cancelled_by: None,
            cancelled_at: None,
            reason_code: None,
            external_cancel_ref: None,
            cleanup_required: None,
        }
    }

    pub fn with_result_objects(mut self, result_objects: Vec<BTreeMap<String, Value>>) -> Self {
        self.result_objects = Some(result_objects);
        self
    }

    pub fn with_artifacts(mut self, artifacts: Vec<BTreeMap<String, Value>>) -> Self {
        self.artifacts = Some(artifacts);
        self
    }

    pub fn with_artifact_retention(mut self, artifact_retention: impl Into<String>) -> Self {
        self.artifact_retention = Some(artifact_retention.into());
        self
    }

    pub fn with_external_artifact_stub(mut self, stub: BTreeMap<String, Value>) -> Self {
        self.external_artifact_stub = Some(stub);
        self
    }

    pub fn with_external_transcript_digest(mut self, digest: Hash) -> Self {
        self.external_transcript_digest = Some(digest);
        self
    }

    pub fn with_completed_at(mut self, completed_at: DateTime<Utc>) -> Self {
        self.completed_at = Some(completed_at);
        self
    }

    pub fn with_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        self.reason_code = Some(reason_code.into());
        self
    }

    /// Attach the cancellation surface required when `status=cancelled`:
    /// `cancelled_by` (local/remote/system), `cancelled_at`, `reason_code`,
    /// `artifact_retention`.
    pub fn with_cancellation(
        mut self,
        cancelled_by: impl Into<String>,
        cancelled_at: DateTime<Utc>,
        reason_code: impl Into<String>,
        artifact_retention: impl Into<String>,
    ) -> Self {
        self.cancelled_by = Some(cancelled_by.into());
        self.cancelled_at = Some(cancelled_at);
        self.reason_code = Some(reason_code.into());
        self.artifact_retention = Some(artifact_retention.into());
        self
    }

    pub fn with_cleanup_required(mut self, cleanup_required: bool) -> Self {
        self.cleanup_required = Some(cleanup_required);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        // anyOf: at least one of result_objects / artifacts / reason_code.
        if self.result_objects.is_none() && self.artifacts.is_none() && self.reason_code.is_none() {
            return Err(Error::Protocol(
                "agent interop session result requires one of result_objects, artifacts, or \
                 reason_code"
                    .to_owned(),
            ));
        }
        // allOf: cancelled status pulls in the full cancellation surface.
        if self.status == AgentInteropResultStatus::Cancelled.as_wire()
            && (self.cancelled_by.is_none()
                || self.cancelled_at.is_none()
                || self.reason_code.is_none()
                || self.artifact_retention.is_none())
        {
            return Err(Error::Protocol(
                "cancelled agent interop session result requires cancelled_by, cancelled_at, \
                 reason_code, and artifact_retention"
                    .to_owned(),
            ));
        }
        serde_json::to_value(self).map_err(|err| {
            Error::Protocol(format!(
                "agent interop session result payload serialize: {err}"
            ))
        })
    }
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

#[cfg(test)]
mod interop_builder_tests {
    use serde_json::json;

    use super::*;
    use crate::schema::event_payload_validator_catalog_from_embedded_spec_artifacts;

    fn session_id() -> &'static str {
        "ck:agent_interop_session:01904100-0000-7000-8000-000000000001"
    }

    #[test]
    fn agent_interop_start_builder_validates_against_catalog() {
        let payload = AgentInteropSessionStartPayload::new(
            session_id(),
            Did::new("did:webvh:z6mkfixture:agent.example").unwrap(),
            AgentInteropProtocol::A2a,
            GrantId::new("ck:grant:01904100-0000-7000-8000-000000000002").unwrap(),
        )
        .with_task_strand_id(
            StrandId::new("ck:strand:01904100-0000-7000-8000-000000000003").unwrap(),
        )
        .with_audit_mode("status_only")
        .with_max_duration_seconds(600);
        let value = payload.to_value().unwrap();
        assert_eq!(value["protocol"], json!("a2a"));
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        catalog
            .validate_payload("ck.agent.interop_session.start", &value)
            .unwrap();
    }

    #[test]
    fn agent_interop_status_builder_validates_against_catalog() {
        let payload =
            AgentInteropSessionStatusPayload::new(session_id(), AgentInteropSessionStatus::Working)
                .with_progress_basis_points(5000)
                .with_summary("halfway");
        let value = payload.to_value().unwrap();
        assert_eq!(value["status"], json!("working"));
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        catalog
            .validate_payload("ck.agent.interop_session.status", &value)
            .unwrap();
    }

    #[test]
    fn agent_interop_result_builder_enforces_any_of_and_cancelled_all_of() {
        // Missing result_objects/artifacts/reason_code -> anyOf failure.
        let bare = AgentInteropSessionResultPayload::new(
            session_id(),
            AgentInteropResultStatus::Completed,
        );
        assert!(bare.to_value().is_err());

        // Completed with result_objects validates against the catalog.
        let completed = AgentInteropSessionResultPayload::new(
            session_id(),
            AgentInteropResultStatus::Completed,
        )
        .with_result_objects(vec![
            [("kind".to_owned(), json!("doc"))].into_iter().collect(),
        ]);
        let value = completed.to_value().unwrap();
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        catalog
            .validate_payload("ck.agent.interop_session.result", &value)
            .unwrap();

        // Cancelled without the full cancellation surface -> allOf failure.
        let cancel_missing = AgentInteropSessionResultPayload::new(
            session_id(),
            AgentInteropResultStatus::Cancelled,
        )
        .with_reason_code("user_abort");
        assert!(cancel_missing.to_value().is_err());

        // Cancelled with the full surface validates.
        let cancelled = AgentInteropSessionResultPayload::new(
            session_id(),
            AgentInteropResultStatus::Cancelled,
        )
        .with_cancellation("local", Utc::now(), "user_abort", "none");
        catalog
            .validate_payload(
                "ck.agent.interop_session.result",
                &cancelled.to_value().unwrap(),
            )
            .unwrap();
    }
}
