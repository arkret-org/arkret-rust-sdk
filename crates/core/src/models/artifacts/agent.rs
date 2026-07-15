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
    AgentRuntimeApprovalRequestBody(AgentRuntimeApprovalRequestBody),
    AgentRuntimeApprovalOutcome(AgentRuntimeApprovalOutcome),
    AgentProvisionRequestBody(AgentProvisionRequestBody),
    AgentProvisionOutcome(AgentProvisionOutcome),
    AgentRenewPairingRequestBody(AgentRenewPairingRequestBody),
    AgentRenewPairingOutcome(AgentRenewPairingOutcome),
    AgentPairingBootstrap(AgentPairingBootstrap),
    AgentList(AgentList),
    AgentView(AgentView),
    AgentPauseRequestBody(AgentPauseRequestBody),
    AgentLifecycleState(AgentLifecycleOutcome),
    AgentResumeRequestBody(AgentResumeRequestBody),
    AgentDeactivateRequestBody(AgentDeactivateRequestBody),
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<NonEmptyString>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/agent_key_authorization_state`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentKeyAuthorizationState {
    pub key_id: String,
    pub verification_method: String,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/key_state`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyState {
    pub agent_id: Did,
    pub controller_id: Did,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: String,
    pub status: AgentStatus,
    pub pcr_recovery: AgentPcrRecoveryState,
    /// Immutable global Agent ceiling captured by provisioning.
    pub requested_scope: AgentKeyScope,
    /// Digest of the immutable ceiling committed by the accepted Agent DID.
    pub requested_scope_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_runtime_key_request: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_requested_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_authorizations: Vec<AgentKeyAuthorizationState>,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/opaque_local_id`.
pub type OpaqueLocalId = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/operation_status_outcome`.
pub type OperationStatusOutcome = AgentLifecycleOutcome;

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/
/// pending_member_reconciliation_item`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PendingMemberReconciliationItem {
    pub agent_id: Did,
    pub reason: NonEmptyString,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/public_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub kty: NonEmptyString,
    pub kid: NonEmptyString,
    pub alg: NonEmptyString,
    pub key: Base64UrlString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<Hash>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/runtime_attestation`
/// (`$ref` to `event-payload.schema.json#/$defs/agent_key_authorize_payload`
/// `properties/runtime_attestation`).
pub type RuntimeAttestation = AgentKeyAuthorizePayloadRuntimeAttestation;

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/sidecar_exposure_ack`.
pub type SidecarExposureAck = AgentSidecarExposureAck;

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/seal_ref`.
pub type SealRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/event_digest`.
pub type EventDigest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/signature`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub verification_method: Did,
    pub alg: String,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub jws: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
