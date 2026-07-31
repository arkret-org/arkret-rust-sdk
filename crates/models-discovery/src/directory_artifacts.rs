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

// The `ConsentScope` family moved to `arkret-wire` so the account consent-cell
// bodies in `arkret-models-collaboration` reach it within their layering edge;
// re-exported here to keep the discovery artifact path stable.
pub use arkret_wire::{ConsentScope, ConsentScopeList, ConsentScopes};

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/event_refs`.
pub type EventRefs = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/freshness_fields`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessFields {
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    pub source_refs: SourceRefs,
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

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/proofs`.
pub type Proofs = Vec<Proof>;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/source_refs`.
pub type SourceRefs = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/subscription_id`.
pub use arkret_wire::SubscriptionId;
