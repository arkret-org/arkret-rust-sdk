//! Contact and directory schema artifact counterparts (pure `$defs`
//! shapes shared by the directory operation DTOs).

use std::collections::BTreeMap;

use arkret_wire::{EventId, MessageId, NonEmptyString, Proof, StrandId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::directory::DirectoryIntent;

/// Counterpart for `spec/v1/artifacts/schemas/calendar-event.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/calendar-event.schema.json#/$defs/attendee`.
/// Counterpart for `spec/v1/artifacts/schemas/common-ids.schema.json`.
pub type CommonIds = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scope`.
pub type ConsentScope = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scope_list`.
pub type ConsentScopeList = Vec<ConsentScope>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scopes`.
pub type ConsentScopes = Vec<ConsentScope>;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/event_refs`.
pub type EventRefs = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/freshness_fields`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessFields {
    pub as_of: DateTime<Utc>,
    pub source_refs: SourceRefs,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/intent`.
pub type Intent = DirectoryIntent;

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/invite_consent_handoff_stub`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteConsentHandoffStub {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<String>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/object_preview`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ObjectPreview {
    pub object_id: ObjectPreviewId,
    pub object_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub as_of: DateTime<Utc>,
    pub source_refs: SourceRefs,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum ObjectPreviewId {
    Strand(StrandId),
    Message(MessageId),
    Event(EventId),
}

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/proofs`.
pub type Proofs = Vec<Proof>;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/source_refs`.
pub type SourceRefs = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/subscription_id`.
pub type SubscriptionId = String;
