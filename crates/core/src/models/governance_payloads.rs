//! Governance and audit event payload helpers.

use super::*;

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
/// Round 4 — typed `ak.consent.revoke` payload with REQUIRED
/// `observed_dots`. Reducers MUST reject envelopes that omit this
/// field with `schema_violation` (it would otherwise enable implicit
/// cascade revoke).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConsentRevokePayload {
    pub consent_id: ConsentId,

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
                crate::ErrorCode::SCHEMA_VIOLATION
            )));
        }

        Ok(())
    }
}
