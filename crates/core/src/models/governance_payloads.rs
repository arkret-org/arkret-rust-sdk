//! Governance and audit event payload helpers.

use super::*;

// ── AccessKind (ck.audit.policy_access) ────────────────────────────────
/// Round 4 (commit 7fae9ba) — `ck.audit.policy_access.access_kind`
/// enum. Round 4 adds `E2EELateRecovery`; deployments emitting it
/// MUST also populate `late_recovery_original_event_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Plaintext,

    Audit,

    Erasure,

    Backup,
    /// Round 4 — late-key-recovery path. Carried alongside
    /// `late_recovery_original_event_id` on the payload.
    #[serde(rename = "e2ee_late_recovery")]
    E2EELateRecovery,
}
/// Round 4 — typed `ck.audit.policy_access` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuditPolicyAccessPayload {
    pub realm_id: RealmId,

    pub actor: Did,

    pub access_kind: AccessKind,
    /// REQUIRED when `access_kind == E2EELateRecovery`. References the
    /// original event the late recovery targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,

    pub observed_at: DateTime<Utc>,
}

impl AuditPolicyAccessPayload {
    pub fn validate_minimal(&self) -> Result<()> {
        match (self.access_kind, &self.late_recovery_original_event_id) {
            (AccessKind::E2EELateRecovery, None) => Err(Error::Protocol(format!(
                "ak.audit.policy_access access_kind=e2ee_late_recovery requires late_recovery_original_event_id ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            ))),

            (kind, Some(_)) if !matches!(kind, AccessKind::E2EELateRecovery) => {
                Err(Error::Protocol(format!(
                    "ak.audit.policy_access late_recovery_original_event_id is only valid for access_kind=e2ee_late_recovery ({})",
                    crate::ERROR_CODE_SCHEMA_VIOLATION
                )))
            }

            _ => Ok(()),
        }
    }
}

// ── ConsentRevokePayload (observed_dots required) ──────────────────────
/// Round 4 (commit 7fae9ba) — Dot identifier for `observed_dots`.
///
/// Wire shape: `(actor_id, actor_seq)` per zh/identity/consent-model.md
/// §3.3.1. Receivers MUST NOT silently cascade revoke to dots not
/// explicitly observed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Dot {
    pub actor_id: Did,

    pub actor_seq: u64,
}
/// Round 4 — typed `ck.consent.revoke` payload with REQUIRED
/// `observed_dots`. Reducers MUST reject envelopes that omit this
/// field with `schema_violation` (it would otherwise enable implicit
/// cascade revoke).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConsentRevokePayload {
    pub consent_id: String,

    pub peer: Did,

    pub scope: String,

    pub observed_dots: Vec<Dot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ConsentRevokePayload {
    pub fn validate_minimal(&self) -> Result<()> {
        if self.observed_dots.is_empty() {
            return Err(Error::Protocol(format!(
                "ak.consent.revoke MUST carry non-empty observed_dots ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )));
        }

        Ok(())
    }
}
