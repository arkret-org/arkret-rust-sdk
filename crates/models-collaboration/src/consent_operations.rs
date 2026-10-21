//! Holder-private exact-peer consent replacement and summary carriers.
use arkret_wire::{
    AccountId, ConsentRequestScope, ConsentScope, CurrentRevision, EventAdmissionSubmission,
    EventKind, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::consent::ConsentPeer;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentView {
    pub peer: ConsentPeer,
    pub permission_scopes: Vec<ConsentScope>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub revision: CurrentRevision,
}
impl ConsentView {
    pub fn validate(&self) -> Result<()> {
        crate::events_payloads::consent::validate_scope_order(
            self.permission_scopes.iter().copied(),
        )
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentList {
    pub consents: Vec<ConsentView>,
}
impl ConsentList {
    pub fn validate(&self) -> Result<()> {
        for consent in &self.consents {
            consent.validate()?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentReplaceRequestBody {
    pub consent_event: EventAdmissionSubmission,
}
impl ConsentReplaceRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.consent_event.event.validate_for_submit_structural()?;
        if self.consent_event.event.kind != EventKind::ConsentReplace {
            return Err(WireError::Protocol(
                "consent replacement requires ak.consent.replace".into(),
            ));
        }
        let payload: crate::events_payloads::consent::ConsentReplacePayload =
            serde_json::from_value(serde_json::to_value(&self.consent_event.event.payload)?)?;
        payload.validate()
    }
}

// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_request_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestRequestBody {
    pub holder_account_id: AccountId,
    pub consent_scope: ConsentRequestScope,
}

impl ConsentRequestRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.holder_account_id.validate()?;
        Ok(())
    }
}

/// Constant anti-enumeration response. Missing holder, denial, rate-limit drop
/// and quarantine acceptance all return this exact shape.
// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_request_outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestOutcome {
    pub accepted_for_processing: bool,
}

impl ConsentRequestOutcome {
    #[must_use]
    pub const fn accepted() -> Self {
        Self {
            accepted_for_processing: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.accepted_for_processing {
            return Err(WireError::Protocol(
                "consent request outcome is pinned to accepted_for_processing = true".to_owned(),
            ));
        }
        Ok(())
    }
}

include!("generated/consent_operations_contracts.rs");
impl ConsentValue {
    pub fn validate(&self) -> Result<()> {
        crate::events_payloads::consent::validate_permissions(&self.permissions)
    }
    pub fn permits(&self, scope: ConsentScope, now: DateTime<Utc>) -> bool {
        self.validate().is_ok()
            && self
                .permissions
                .iter()
                .any(|permission| permission.consent_scope == scope && permission.permits(now))
    }
}
pub use crate::call_invitation::{
    ConsentCurrentReadOutcome, ConsentCurrentReadProof, ConsentCurrentReadRequestBody,
    ConsentCurrentReadState, ConsentCurrentRow, ConsentCurrentSelector, ConsentCurrentSelectorKind,
};
