//! Audit access event payload.

use arkret_wire::{ActorId, EventId, NonEmptyString, ObjectRef};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAccessedKind {
    WatchSetOthers,
    CircleMemberSetOthers,
    WatchAuditRead,
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
    PolicyAuditRead,
    Other,
}

include!("generated/audit_contracts.rs");
