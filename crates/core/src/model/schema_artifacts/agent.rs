//! Agent lifecycle schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentOperations {
    AccountDevicePairRequestBody(crate::AccountDevicePairRequestBody),
    AccountDevicePairOutcome(crate::AccountDevicePairOutcome),
    AgentKeyPairRequestBody(AgentKeyPairRequestBody),
    AgentKeyPairOutcome(AgentKeyPairOutcome),
    AgentProvisionRequestBody(AgentProvisionRequestBody),
    AgentProvisionOutcome(AgentProvisionOutcome),
    AgentList(AgentList),
    AgentView(AgentView),
    AgentPauseRequestBody(AgentPauseRequestBody),
    AgentLifecycleState(AgentLifecycleOutcome),
    AgentResumeRequestBody(AgentResumeRequestBody),
    AgentDeactivateRequestBody(AgentDeactivateRequestBody),
    AgentRotateKeyRequestBody(AgentRotateKeyRequestBody),
    AgentRotateKeyOutcome(AgentRotateKeyOutcome),
    AgentGrantAttachRequestBody(AgentGrantAttachRequestBody),
    AgentGrantAttachOutcome(AgentGrantAttachOutcome),
    AgentGrantDetachOutcome(AgentGrantDetachOutcome),
    AgentSidecarThreadEnsureRequestBody(AgentSidecarThreadEnsureRequestBody),
    AgentSidecarThreadEnsureOutcome(AgentSidecarThreadEnsureOutcome),
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/base64url`.
pub type Base64url = String;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/grant_snapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSnapshot {
    pub grant_id: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/key_state`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyState {
    pub verification_method: Did,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/opaque_local_id`.
pub type OpaqueLocalId = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/operation_status_outcome`.
pub type OperationStatusOutcome = AgentLifecycleOutcome;

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/
/// pending_member_reconciliation_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingMemberReconciliationItem {
    pub agent_principal_id: Did,
    pub reason: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/public_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    pub key: Base64url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<Hash>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/runtime_attestation`.
pub type RuntimeAttestation = AgentKeyAuthorizePayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/sidecar_exposure_ack`.
pub type SidecarExposureAck = AgentSidecarExposureAck;

/// Counterpart for `spec/v1/artifacts/schemas/agent.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentAuditBindingValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Agent {
    pub schema: String,
    pub agent_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_entry_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_binding: Option<AgentAuditBindingValue>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/seal_ref`.
pub type SealRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/event_digest`.
pub type EventDigest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/signature`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub verification_method: Did,
    pub alg: String,
    pub payload_digest: Value,
    pub created_at: DateTime<Utc>,
    pub jws: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
