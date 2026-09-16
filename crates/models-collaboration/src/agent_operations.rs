//! Current Agent lifecycle HTTP DTOs.
//!
//! All durable mutations carry producer Events for submission to the governing
//! authority. There is no prepare/reservation phase and no client-authored
//! acceptance or history frontier.

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AuditReasonText, CommittedEventRef, DidCoreId, EventCommitSubmission, Hash, OpaqueLocalId,
    RealmId, SidecarId,
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
    pub display_name: String,
    pub slug: String,
    pub status: AgentLifecycleState,
    pub provision_ref: CommittedEventRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_scope_digest: Option<Hash>,
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
    pub key_state: Option<Value>,
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
