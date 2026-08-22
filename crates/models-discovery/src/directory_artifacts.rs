//! Contact and directory schema artifact counterparts (pure `$defs`
//! shapes shared by the directory operation DTOs).

use arkret_wire::{EventId, MessageId, NonEmptyString, StrandId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/freshness_fields`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessFields {
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    pub source_refs: Vec<EventId>,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/invite_consent_handoff_stub`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/object_preview`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectPreview {
    pub object_id: ObjectPreviewId,
    pub object_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    pub source_refs: Vec<EventId>,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObjectPreviewId {
    Strand(StrandId),
    Message(MessageId),
    Event(EventId),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/subscription_id`.
pub use arkret_wire::SubscriptionId;
