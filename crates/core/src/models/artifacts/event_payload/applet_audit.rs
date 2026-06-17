//! Applet-registration, applet-interop-session, audit, and seal-frontier payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

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
