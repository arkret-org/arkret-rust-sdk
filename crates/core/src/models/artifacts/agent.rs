//! Agent lifecycle schema artifact counterparts.
//!
//! The public-key / grant-snapshot / device-metadata / key-authorization /
//! seal-signature leaf shapes migrated to `arkret-models-collaboration`
//! (`governance::agent_artifacts`, re-exported below). The `AgentOperations`
//! aggregation enum and `KeyState` stay here because they bind the agent
//! lifecycle status/scope enums (`AgentStatus`, `AgentPcrRecoveryState`,
//! `AgentPairingMode`) that remain core-resident.

pub use arkret_models_collaboration::governance::agent_artifacts::*;

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentOperations {
    AccountDevicePairRequestBody(crate::AccountDevicePairRequestBody),
    AccountDevicePairOutcome(crate::AccountDevicePairOutcome),
    AgentKeyPairRequestBody(Box<AgentKeyPairRequestBody>),
    AgentKeyPairOutcome(AgentKeyPairOutcome),
    AgentRuntimeApprovalRequestBody(AgentRuntimeApprovalRequestBody),
    AgentRuntimeApprovalOutcome(AgentRuntimeApprovalOutcome),
    AgentProvisionRequestBody(Box<AgentProvisionRequestBody>),
    AgentProvisionOutcome(AgentProvisionOutcome),
    AgentRenewPairingRequestBody(AgentRenewPairingRequestBody),
    AgentRenewPairingOutcome(AgentRenewPairingOutcome),
    AgentPairingBootstrap(AgentPairingBootstrap),
    AgentList(AgentList),
    AgentView(Box<AgentView>),
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
    /// Branch of the current unconsumed, unexpired pairing handle. Present
    /// exactly when `pairing_request_id` and `pairing_expires_at` are present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_mode: Option<AgentPairingMode>,
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
