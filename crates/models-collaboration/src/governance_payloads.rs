//! Governance and audit event payload helpers.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use arkret_wire::{ConsentId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Typed `ak.consent.revoke` command payload. The stable consent identifier
/// selects the current authority projection and `expected_revision` provides
/// optimistic concurrency without exposing reducer internals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRevokePayload {
    pub consent_id: ConsentId,
    pub expected_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ConsentRevokePayload {
    pub fn validate_minimal(&self) -> Result<()> {
        if self.reason.as_deref().is_some_and(str::is_empty) {
            return Err(WireError::Protocol(
                "consent revoke reason must be absent or non-empty".to_owned(),
            ));
        }
        Ok(())
    }
}
