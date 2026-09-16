use arkret_wire::{DidCoreId, EventId, RealmId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Plaintext,
    Audit,
    Erasure,
    Backup,
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPolicyAccessPayload {
    pub realm_id: RealmId,
    pub actor: DidCoreId,
    pub access_kind: AccessKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
}

impl AuditPolicyAccessPayload {
    pub fn validate_minimal(&self) -> Result<()> {
        match (self.access_kind, &self.late_recovery_original_event_id) {
            (AccessKind::E2EELateRecovery, None) => Err(WireError::Protocol("ak.audit.policy_access access_kind=e2ee_late_recovery requires late_recovery_original_event_id (schema_violation)".to_owned())),
            (kind, Some(_)) if !matches!(kind, AccessKind::E2EELateRecovery) => {
                Err(WireError::Protocol("ak.audit.policy_access late_recovery_original_event_id is only valid for access_kind=e2ee_late_recovery (schema_violation)".to_owned()))
            }
            _ => Ok(()),
        }
    }
}
