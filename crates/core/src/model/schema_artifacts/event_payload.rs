//! Event payload schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json`.
pub type EventPayload = GenericStandardPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/account_status_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusPayload {
    pub principal_id: Did,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_status_event_id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_proof: Option<SignatureMaterial>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileCreatePayload {
    pub object: ActorProfile,
}

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
    pub task_flow_id: Option<FlowId>,
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
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyApprovalEvidence {
    pub kind: String,
    pub r#ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<Did>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizePayloadRuntimeAttestation {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_digest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizePayload {
    pub agent_principal_id: Did,
    pub key_id: String,
    pub verification_method: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_digest: Option<Value>,
    pub accountable_principal_id: Did,
    pub agent_key_scope: AgentKeyScope,
    pub audience: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approval_evidence: AgentKeyApprovalEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_check_ref: Option<Value>,
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
    pub replacement_verification_method: Did,
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

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/seal_frontier`.
pub type SealFrontier = Vec<Hash>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_bridge_error_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletBridgeErrorPayload {
    pub applet_id: Value,
    pub realm_id: RealmId,
    pub failed_transaction_ref: Value,
    pub error_class: String,
    pub error_code: Value,
    pub retriable: bool,
    pub visibility_scope: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// applet_interop_session_start_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInteropSessionStartPayload {
    pub applet_id: Value,
    pub session_id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// applet_interop_session_status_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInteropSessionStatusPayload {
    pub applet_id: Value,
    pub session_id: String,
    pub runtime_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_registration_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRegistrationPayload {
    pub applet_id: Value,
    pub service_did: Value,
    pub controller_did: Value,
    pub base_url: String,
    pub bot_actor_id: Did,
    pub protocols: Vec<String>,
    pub namespaces: BTreeMap<String, Value>,
    pub receive_events: bool,
    pub receive_ephemeral: bool,
    pub rate_limited: bool,
    pub requested_scopes: Vec<String>,
    pub registration_epoch: Hash,
    pub webhook_auth: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<BTreeMap<String, Value>>,
    pub proof: BTreeMap<String, Value>,
    pub created_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_accessed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAccessedPayload {
    pub access_kind: String,
    pub writer_actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cell_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_id: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_before: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_head_after: Option<Hash>,
    pub purpose: String,
    pub accessed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ryw_required: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_applet_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingPayloadReleaseWindowPolicy {
    pub retroactive_release: String,
    pub eligibility_basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lookback_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_epoch_span: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_target_classes: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppletBindingPayload {
    pub binding_id: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub applet_id: Value,
    pub service_did: Did,
    pub status: String,
    pub purpose_classes: Vec<String>,
    pub allowed_release_modes: Vec<String>,
    pub audit_assurance_class: String,
    pub notice_policy: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_policy: Option<BTreeMap<String, Value>>,
    pub activation_frontier_digest: Value,
    pub first_auditable_epoch: u64,
    pub release_window_policy: AuditAppletBindingPayloadReleaseWindowPolicy,
    pub policy_version_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    pub created_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_release_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReleasePayloadEligibilityProof {
    pub binding_activation_frontier_digest: Hash,
    pub first_auditable_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_commit_ref: Option<Value>,
    pub policy_snapshot_digest: Value,
    pub target_eligibility_digest: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReleasePayload {
    pub release_id: String,
    pub session_id: String,
    pub binding_id: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub applet_id: Value,
    pub service_did: Did,
    pub release_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<EventRef>,
    pub seal_digest: Hash,
    pub recipient_audit_actor_id: Did,
    pub recipient_public_key_ref: Did,
    pub approver_actor_id: Did,
    pub notice_ref: EventRef,
    pub purpose_class: String,
    pub legal_basis_ref: String,
    pub policy_version_digest: Hash,
    pub eligibility_proof: AuditReleasePayloadEligibilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_by_commit_ref: Option<EventRef>,
    pub wrapped_material_digest: Vec<Hash>,
    pub released_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_authorize_payload`.
pub type AuditSessionAuthorizePayload = AuditSessionPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_close_payload`.
pub type AuditSessionClosePayload = AuditSessionPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_notice_payload`.
pub type AuditSessionNoticePayload = AuditSessionPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSessionPayload {
    pub session_id: String,
    pub binding_id: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closer_actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_release_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_release_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_epoch_range: Option<MlsEpochRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_policy: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_notice_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<Hash>,
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_request_payload`.
pub type AuditSessionRequestPayload = AuditSessionPayload;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_participant`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantBinding {
    pub scheme: String,
    pub realm_id: RealmId,
    pub call_id: String,
    pub focus_id: String,
    pub actor_id: Did,
    pub device_id: String,
    pub participant_identity: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer_kid: Did,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipantMedia {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipant {
    pub actor_id: Did,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foci_preferred: Option<Vec<String>>,
    pub participant_identity: String,
    pub participant_binding: ParticipantBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<CallParticipantMedia>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<BTreeMap<String, Value>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStatePayloadRecordingResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_start_event_id: Option<EventRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStatePayload {
    pub call_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_focus: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participants: Option<Vec<CallParticipant>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_result: Option<CallStatePayloadRecordingResult>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<CapabilityGrant>,
    pub grant_id: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRevokePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<GrantId>,
    pub grant_id: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_seal_commit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleSealCommitPayload {
    pub circle_id: CircleId,
    pub sub_seal_head_digest: Hash,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_seals_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleCreatePayload {
    pub object: Circle,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_member_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleMemberStatePayload {
    pub circle_id: CircleId,
    pub actor_id: Did,
    pub membership: MembershipState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_membership: Option<MembershipState>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CirclePatchPayload {
    pub circle_id: CircleId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/consent_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantPayload {
    pub consent_id: String,
    pub peer: Value,
    pub consent_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_accepted_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactAcceptedPayload {
    pub request_id: EventRef,
    pub requester: Did,
    pub granted_scopes: ContactConsentScopes,
    pub consent_grant_refs: ContactEventRefs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded_scope_reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scope`.
pub type ContactConsentScope = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scopes`.
pub type ContactConsentScopes = Vec<ContactConsentScope>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_event_refs`.
pub type ContactEventRefs = Vec<EventRef>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_rejected_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRejectedPayload {
    pub request_id: EventRef,
    pub requester: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_requested_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestedPayload {
    pub request_id: Value,
    pub target: Did,
    pub requested_scopes: ContactConsentScopes,
    pub requester_consent_refs: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_tombstoned_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactTombstonedPayload {
    pub peer: Did,
    pub revoke_scopes: ContactConsentScopes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_revoke_refs: Option<ContactEventRefs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_peer_revoke: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_revoke: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/container_position_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerPositionPayload {
    pub source_ref: ObjectRef,
    pub target_ref: ObjectRef,
    pub container_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<String>,
    pub rank: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/content_kind`.
pub type ContentKind = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/cross_signing_publish_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSigningPublishPayload {
    pub principal_id: Did,
    pub trust_domain: String,
    pub principal_signing_key: BTreeMap<String, Value>,
    pub self_signing_key: BTreeMap<String, Value>,
    pub user_signing_key: BTreeMap<String, Value>,
    pub expected_previous_generation: u64,
    pub generation: u64,
    pub issued_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_authorize_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBootstrapBinding {
    pub kind: String,
    pub did_method_evidence_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizePayload {
    pub principal_id: Did,
    pub device_id: String,
    pub device_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_algorithm: Option<String>,
    pub authorized_by: DeviceOrPrincipalRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<SignatureMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_signing_binding: Option<DeviceCrossSigningBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_binding: Option<DeviceBootstrapBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_session_id: Option<RecoverySessionId>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_cross_signing_binding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCrossSigningBinding {
    pub verification_method: Value,
    pub alg: String,
    pub ssk_generation: u64,
    pub signature: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_list_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceListUpdatePayload {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_or_principal_ref`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceOrPrincipalRef {
    DeviceId(String),
    Did(Did),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokePayload {
    pub principal_id: Did,
    pub device_id: String,
    pub revoked_by: DeviceOrPrincipalRef,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationBoundPayload {
    pub pair_key: Value,
    pub participants_unordered: Vec<Did>,
    pub realm_id: RealmId,
    pub main_flow_id: FlowId,
    pub contact_refs: ContactEventRefs,
    pub member_event_refs: Value,
    pub main_flow_create_ref: EventRef,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_binding_ref: Option<EventRef>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/encrypted_metadata`.
pub type EncryptedMetadata = EncryptedEnvelope;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/erasure_receipt_payload`.
pub type ErasureReceiptPayload = ErasureReceipt;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/flow_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowCreatePayload {
    pub object: Flow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

// `flow_move_payload` now has a strong type:
// `model::operation_payloads::FlowMovePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration; flat
// board/target Space ids + rank with an optional `expected_position`
// CAS guard, `additionalProperties:false`).

// `flow_reorder_payload` now has a strong type:
// `model::operation_payloads::FlowReorderPayload` (single List-Space
// re-rank; `additionalProperties:false`).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/flow_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStageSetPayload {
    pub flow_id: FlowId,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stage: Option<String>,
}

// `flow_watch_set_payload` now has a strong type:
// `model::operation_payloads::FlowWatchSetPayload` (carries the
// `FlowWatchLevel` enum / nullable `level` clear path and the
// `level_public`/`expected_value` CAS fields; `additionalProperties:false`).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/generic_standard_payload`.
pub type GenericStandardPayload = BTreeMap<String, Value>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/hierarchy_link_status`.
pub type HierarchyLinkStatus = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_sharing_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingPolicyPayloadValueAudit {
    pub share_audit_event_required: bool,
    pub access_audit_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingPolicyPayloadValue {
    pub version: u64,
    pub default_key_share: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_join_history: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_removal_recovery: Option<String>,
    pub allowed_key_sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_receiver_states: Option<Vec<String>>,
    pub audit: HistorySharingPolicyPayloadValueAudit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted_rules: Option<Vec<HistorySharingRestrictedRule>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingPolicyPayload {
    pub value: HistorySharingPolicyPayloadValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_sharing_restricted_rule`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingRestrictedRuleHistoryScope {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<CircleId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySharingRestrictedRule {
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_scope: Option<HistorySharingRestrictedRuleHistoryScope>,
    pub receiver_classes: Vec<String>,
    pub allowed_history_visibility_values: Vec<HistoryVisibilityValue>,
    pub range: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_epoch_span: Option<u64>,
    pub key_sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_required: Option<bool>,
}

// `history_visibility_payload` now has a strong type:
// `model::operation_payloads::HistoryVisibilityPayload` (`{value,
// restricted_policy_digest?, reason?}`, deny_unknown_fields, with the
// `value==restricted ⇒ restricted_policy_digest` conditional enforced by
// `to_value`). NB: the kind→def resolver still routes
// `ck.realm.history_visibility` to `generic_standard_payload` (no resolver arm
// / no `realm_history_visibility_payload` def) — see the type's doc comment.

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_visibility_value`.
pub type HistoryVisibilityValue = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/inheritance_policy_status`.
pub type InheritancePolicyStatus = String;

// `invite_payload` anyOf branches now have strong types in
// `model::operation_payloads`: `InviteCreatePayload` (directed-create) and
// `InviteRefPayload` (invite_id ref, for accept/cancel). The full union is
// not modeled as one type (the remaining anyOf branches — `invite`,
// `third_party_id`, claim-proof — are not constructed by the client wire).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/join_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinPolicyPayloadGatesItem {
    pub gate_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_resolve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_did_methods: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_principal_dids: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_principal_dids: Option<Vec<Did>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinPolicyPayload {
    pub gates: Vec<JoinPolicyPayloadGatesItem>,
    pub combinator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_quorum: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_ttl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_after_reject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_applications_per_actor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicant_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_hint: Option<BTreeMap<String, Value>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/key_backup_active_series_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesAuthData {
    pub verification_method: Did,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
    pub ssk_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupActiveSeries {
    pub schema: String,
    pub actor_id: Did,
    pub backup_class: BackupClass,
    pub active_series_id: BackupSeriesId,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub frontier_ref: Value,
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupActiveSeriesAuthData,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

pub type KeyBackupActiveSeriesPayload = KeyBackupActiveSeries;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/list_reorder_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReorderPayloadExpectedPosition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReorderPayload {
    pub board_space_id: SpaceId,
    pub space_id: SpaceId,
    pub rank: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_position: Option<ListReorderPayloadExpectedPosition>,
}

// `membership_payload` now has a strong type:
// `model::operation_payloads::MembershipPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration; carries the
// `MembershipPayloadState` enum and enforces the join/routable conditional
// required fields).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_metadata_fields`.
pub type MessageMetadataFields = BTreeMap<String, Value>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_redact_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRedactPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_event_id: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserve: Option<Vec<String>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_revise_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRevisePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_of: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mimi_room_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayloadBindingScope {
    pub realm_id: RealmId,
    pub flow_id: FlowId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Value>,
    pub mimi_room_uri: String,
    pub binding_scope: MimiRoomBindingPayloadBindingScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_provider: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_provider_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follower_providers: Option<Vec<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_component_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_commit_failed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCommitFailedPayload {
    pub mls_group_id: String,
    pub commit_ref: EventRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_ref: Option<EventRef>,
    pub epoch: u64,
    pub failure_stage: Value,
    pub reporter_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_digest: Option<Hash>,
    pub failed_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_epoch_range`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsEpochRange {
    pub first_epoch: u64,
    pub last_epoch: u64,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_genesis_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGenesisPayload {
    pub mls_group_id: String,
    pub effective_scope: Value,
    pub epoch: u64,
    pub creator_principal_id: Did,
    pub creator_device_id: String,
    pub cipher_suite: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_info_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_info_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_keypackage_refs: Option<Vec<ObjectRef>>,
    pub governance_binding: MlsGovernanceBinding,
    pub created_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_governance_binding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceBinding {
    pub binding_version: u64,
    pub encoding_profile: String,
    pub realm_id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<Value>,
    pub effective_scope: Value,
    pub mls_group_id: String,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub membership_frontier: Vec<EventRef>,
    pub policy_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discussion_metadata_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reducer_profile: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_keypackage_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsKeypackagePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_id: Option<String>,
    pub principal_id: Did,
    pub device_id: String,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Value,
    pub cipher_suites: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    pub state: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub device_signature: SignatureMaterial,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_proposal_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsProposalPayload {
    pub mls_group_id: String,
    pub base_epoch: u64,
    pub proposal_type: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_message_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_binding: Option<MlsGovernanceBinding>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_welcome_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomePayloadClaimRef {
    pub claim_id: String,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub capabilities_digest: Hash,
    pub ssk_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomePayload {
    pub mls_group_id: String,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<String>,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Value,
    pub claim_id: String,
    pub claim_ref: MlsWelcomePayloadClaimRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_welcome_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_ref: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_binding: Option<MlsGovernanceBinding>,
    pub expires_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_lift_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionLiftPayload {
    pub target_ref: Value,
    pub decision_ref: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionPayload {
    pub target_ref: Value,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_decision_ref: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modify_decision_ref: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_report_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationReportPayload {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<Value>,
    pub target_ref: ObjectRef,
    pub report_reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<ObjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_package: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franking_proof: Option<BTreeMap<String, Value>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphCreatePayload {
    pub object: Morph,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_schema_migrate_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphSchemaMigratePayload {
    pub morph_id: MorphId,
    pub from_schema_refs: Vec<String>,
    pub to_schema_refs: Vec<String>,
    pub compatibility_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformation_rules: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_evidence: Option<BTreeMap<String, Value>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphStageSetPayload {
    pub morph_id: MorphId,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stage: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/nullable_timestamp`.
pub type NullableTimestamp = Option<DateTime<Utc>>;

// `object_lifecycle_payload` now has a strong type:
// `model::operation_payloads::ObjectLifecyclePayload` (generic Flow / Circle /
// Morph archive·restore·tombstone shape, single-sourced by `target_ref`;
// `additionalProperties:false`).

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/object_snapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectSnapshot {
    pub id: ObjectRef,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/object_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectStageSetPayload {
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stage: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_operation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    #[serde(rename = "$op")]
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_match: Option<Hash>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_path`.
pub type PatchPath = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_value`.
pub type PatchValue = BTreeMap<String, Value>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/plaintext_data_class`.
pub type PlaintextDataClass = String;

// `plaintext_visible_services_payload` now has a strong type:
// `model::operation_payloads::PlaintextVisibleServicesPayload` (`{services:
// [PlaintextVisibleService]}`, top-level deny_unknown_fields; item required
// fields strongly typed with `PlaintextDataClassKind` / `PlaintextServiceVisibility`
// enums, item kept open per spec additionalProperties:true). Resolver routes
// the kind to `generic_standard_payload` — see the type's doc comment.

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/preview_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueHistory {
    pub range: String,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_member_events: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_target_digest: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValue {
    pub mode: String,
    pub audiences: Vec<String>,
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<PreviewPolicyPayloadValueHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<PreviewPolicyPayloadValueToken>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayload {
    pub value: PreviewPolicyPayloadValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/profile_realm_override_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRealmOverridePayload {
    pub target_ref: String,
    pub target_realm_id: RealmId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// reaction_encrypted_payload_plaintext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionEncryptedPayloadPlaintext {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_add_event_ids: Option<Vec<EventRef>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/reaction_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionPayload {
    pub target_ref: ObjectRef,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/read_receipt_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptPolicyPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_overrides_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_child_privacy_tightening_against_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_public_receipts_on_world_readable: Option<bool>,
}

// `realm_archive_payload` now has a strong type:
// `model::operation_payloads::RealmArchivePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCreatePayload {
    pub object: Realm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

// `realm_destroy_payload` now has a strong type:
// `model::operation_payloads::RealmDestroyPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_disappearing_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDisappearingPolicyPayload {
    pub enabled: bool,
    pub max_ttl_ms: u64,
    pub allowed_triggers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_grace_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_realms: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmFreezePayload {
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_inheritance_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayloadInherits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_bundles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_defaults: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayload {
    pub source_realm_id: RealmId,
    pub inherits: RealmInheritancePolicyPayloadInherits,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<InheritancePolicyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_scope`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyScope {
    pub effective_scope: Value,
    pub policy_digest: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibilityValue>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_audit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyShareAuditPayload {
    pub share_event_ref: EventRef,
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_digest: Option<Hash>,
    pub recorded_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeySharePayload {
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    pub sender_device_id: String,
    pub sender_device_signature: Value,
    pub key_scope: RealmKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_key_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_withheld_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyWithheldPayload {
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    pub sender_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_scope: Option<RealmKeyScope>,
    pub withheld_reason_code: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_search_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSearchPolicyPayload {
    pub enabled_profile_refs: Vec<String>,
    pub allowed_service_dids: Vec<Did>,
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_retention_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_behavior: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leakage_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_rotation_cadence_ms: Option<u64>,
}

// `realm_tombstone_payload` now has a strong type:
// `model::operation_payloads::RealmTombstonePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

// `relation_create_payload` now has a strong type:
// `model::operation_payloads::RelationCreatePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationUpdatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/signature_material`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignatureMaterial {
    NonEmptyString(String),
    Variant1(BTreeMap<String, Value>),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceCreatePayload {
    pub object: Space,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_parent_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceParentPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    pub expected_parent_space_id: Option<SpaceId>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePatchPayload {
    pub space_id: SpaceId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
}
