//! Current Agent lifecycle HTTP DTOs.
//!
//! All durable mutations carry producer Events for submission to the governing
//! authority. There is no prepare/reservation phase and no client-authored
//! acceptance or history checkpoint.

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, AuditReasonText, BlobRef, CommittedEventRef, DidCoreId, DidUrl,
    EventCommitSubmission, OpaqueLocalId, RealmId, SidecarId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::agent_scope::AgentKeyPairRequestBody;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycleState {
    #[default]
    Active,
    Paused,
    Deactivated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyPairOutcome {
    pub authorize_ref: CommittedEventRef,
    pub status: AgentLifecycleState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionRequestBody {
    pub provision_event: EventCommitSubmission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionOutcome {
    pub agent_id: DidCoreId,
    pub provision_ref: CommittedEventRef,
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    #[serde(with = "canonical_timestamp")]
    pub pairing_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingOutcome {
    pub agent_id: DidCoreId,
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPauseRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    pub lifecycle_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResumeRequestBody {
    pub lifecycle_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDeactivateRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    pub lifecycle_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleOutcome {
    pub status: AgentLifecycleState,
    pub lifecycle_ref: CommittedEventRef,
}

/// Read projection. Its business projection remains server-owned JSON; durable
/// coordinates are carried separately as an accepted commit reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProjection {
    pub agent_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub lifecycle: AgentLifecycleState,
    pub readiness: AgentReadiness,
    pub presence: AgentPresence,
    pub provision_ref: CommittedEventRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRuntimeState {
    PendingRuntimeKey,
    Ready,
    Replacing,
    PairingExpired,
}

impl AgentRuntimeState {
    pub fn derive(has_active_authorization: bool, has_open_pairing_handle: bool) -> Self {
        match (has_active_authorization, has_open_pairing_handle) {
            (true, true) => Self::Replacing,
            (true, false) => Self::Ready,
            (false, true) => Self::PendingRuntimeKey,
            (false, false) => Self::PairingExpired,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentReadinessState {
    Ready,
    NotReady,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentReadinessBlocker {
    RuntimeKeyMissing,
    PairingOpen,
    RecoveryStale,
    SessionMissing,
    KeypackageEmpty,
    ReplyCapabilityMissing,
    MlsRejoinRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReadiness {
    pub state: AgentReadinessState,
    pub blockers: Vec<AgentReadinessBlocker>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPresenceState {
    Online,
    Offline,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPresence {
    pub state: AgentPresenceState,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub refresh_after: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingRuntimeIdentity {
    pub controller_account_id: AccountId,
    pub verification_method: DidUrl,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingBootstrap {
    pub arkret_base_url: String,
    pub service_id: DidCoreId,
    pub agent_id: DidCoreId,
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    #[serde(with = "canonical_timestamp")]
    pub pairing_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_identity: Option<AgentPairingRuntimeIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairingResolveRequestBody {
    pub pairing_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyState {
    pub agent_id: DidCoreId,
    pub controller_account_id: AccountId,
    pub principal_control_realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_authorization_ref: Option<CommittedEventRef>,
    pub runtime_state: AgentRuntimeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_request_id: Option<OpaqueLocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub pairing_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentList {
    pub agent_projections: Vec<AgentProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentView {
    pub agent: AgentProjection,
    #[serde(default)]
    pub grants: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_state: Option<KeyState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarView {
    pub sidecar_id: SidecarId,
    pub realm_id: RealmId,
    pub sidecar_head: arkret_wire::CommitStreamHead,
    #[serde(default)]
    pub desired_agent_ids: Vec<DidCoreId>,
    #[serde(default)]
    pub effective_agent_ids: Vec<DidCoreId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarList {
    pub agent_sidecar_views: Vec<AgentSidecarView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}
