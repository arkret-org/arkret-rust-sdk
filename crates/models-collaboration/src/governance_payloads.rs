//! Governance and audit event payload helpers.
//!
//! Migrated from `arkret-core` (`models/governance_payloads.rs`); a shim
//! there re-exports these shapes to preserve the `arkret_core::` path.

use std::collections::BTreeSet;

use arkret_wire::{ConsentId, Error, ErrorCode, EventId, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical consent add-dot reference.
///
/// Mirrors `event-payload.schema.json#/$defs/consent_revoke_payload`
/// `observed_dots[]`: `<canonical event ref>:<actor sequence>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(try_from = "String", into = "String")]
pub struct ConsentObservedDot(String);

impl ConsentObservedDot {
    pub fn new(value: String) -> Result<Self> {
        let (event_ref, actor_seq) = value.rsplit_once(':').ok_or_else(|| {
            Error::Protocol("consent observed dot must contain an actor sequence".to_owned())
        })?;
        EventId::new(event_ref.to_owned()).map_err(|_| {
            Error::Protocol("consent observed dot must start with a canonical event ref".to_owned())
        })?;
        if actor_seq.is_empty() || !actor_seq.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Protocol(
                "consent observed dot actor sequence must contain decimal digits".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConsentObservedDot {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<ConsentObservedDot> for String {
    fn from(value: ConsentObservedDot) -> Self {
        value.0
    }
}

/// Typed `ak.consent.revoke` payload with REQUIRED
/// `observed_dots`. Reducers MUST reject envelopes that omit this
/// field with `schema_violation` (it would otherwise enable implicit
/// cascade revoke).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentRevokePayload {
    pub consent_id: ConsentId,

    pub observed_dots: Vec<ConsentObservedDot>,
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
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        let unique = self
            .observed_dots
            .iter()
            .map(ConsentObservedDot::as_str)
            .collect::<BTreeSet<_>>();
        if unique.len() != self.observed_dots.len() {
            return Err(Error::Protocol(format!(
                "ak.consent.revoke observed_dots MUST be unique ({})",
                ErrorCode::SCHEMA_VIOLATION
            )));
        }

        Ok(())
    }
}
