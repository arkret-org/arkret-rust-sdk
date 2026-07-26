//! Contact event payloads.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_accepted_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactAcceptedPayload {
    pub request_id: EventId,
    pub requester: Did,
    pub granted_scopes: ContactConsentScopes,
    pub consent_grant_refs: ContactEventRefs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded_scope_reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scope`.
pub type ContactConsentScope = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scopes`.
pub type ContactConsentScopes = Vec<ContactConsentScope>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_event_refs`.
pub type ContactEventRefs = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_rejected_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRejectedPayload {
    pub request_id: EventId,
    pub requester: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_requested_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequestedPayload {
    pub request_id: EventId,
    pub target: Did,
    pub requested_scopes: ContactConsentScopes,
    pub requester_consent_refs: ContactEventRefs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction_evidence_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_tombstoned_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactTombstonedPayload {
    pub peer: Did,
    pub revoke_scopes: ContactConsentScopes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_revoke_refs: Option<ContactEventRefs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_peer_revoke: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_revoke: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
