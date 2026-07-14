//! Account-status and actor-profile payloads, plus the top-level EventPayload alias.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json`.
pub type EventPayload = GenericStandardPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/account_status_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusPayload {
    pub principal_id: Did,
    pub status: AccountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_status_event_id: Option<EventId>,
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
