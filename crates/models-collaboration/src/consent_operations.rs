//! Holder-private consent self-management request/outcome DTOs.
//!
//! The consent state itself is a current state serialized by the current
//! governance Station. Replacement carries one caller-signed Event through
//! the single Event submission DTO; the Station submits those exact bytes and
//! never co-signs, rebuilds or synthesizes the Event.

use arkret_wire::{
    AccountId, ConsentRequestScope, ConsentScope, CurrentRevision, EventAdmissionSubmission,
    EventKind, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::consent::ConsentPeer;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
        if self.permission_scopes.len() > 4
            || self
                .permission_scopes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(WireError::Protocol(
                "Consent summary scopes require canonical unique order".into(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentList {
    pub consents: Vec<ConsentView>,
}
impl ConsentList {
    pub fn validate(&self) -> Result<()> {
        let mut peers = std::collections::BTreeSet::new();
        for consent in &self.consents {
            consent.validate()?;
            let ConsentPeer::Actor { actor_id } = &consent.peer;
            if !peers.insert(actor_id) {
                return Err(WireError::Protocol(
                    "Consent list repeats an exact peer".into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentReplaceRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub consent_event: EventAdmissionSubmission,
}
impl ConsentReplaceRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.consent_event.validate()?;
        if self.consent_event.event.kind != EventKind::ConsentReplace {
            return Err(WireError::Protocol(
                "Consent replacement requires ak.consent.replace".into(),
            ));
        }
        let payload: crate::events_payloads::consent::ConsentReplacePayload =
            serde_json::from_value(serde_json::to_value(&self.consent_event.event.payload)?)?;
        payload.validate_minimal()
    }
}

// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_request_request_body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
// consent-operations.schema.json#/$defs/consent_request_response_body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestResponseBody {
    pub accepted_for_processing: bool,
}

impl ConsentRequestResponseBody {
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

pub use crate::call_invitation::{
    ConsentCurrentReadProof, ConsentCurrentReadRequestBody, ConsentCurrentReadResponseBody,
    ConsentCurrentReadState, ConsentCurrentSelector, ConsentCurrentSelectorKind, CurrentConsent,
};

impl ConsentValue {
    pub fn validate(&self) -> Result<()> {
        crate::events_payloads::consent::validate_permissions(&self.permissions)
    }
}
