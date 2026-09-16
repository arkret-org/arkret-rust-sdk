//! Audit access event payload.

use arkret_wire::{ActorId, EventId, NonEmptyString, ObjectRef};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAccessedKind {
    WatchSetOthers,
    WatchAuditRead,
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
    PolicyAuditRead,
    Other,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_accessed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAccessedPayload {
    pub access_kind: AuditAccessedKind,
    pub writer_actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<ActorId>,
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    pub purpose: NonEmptyString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accessed_at: DateTime<Utc>,
}
