//! Contact and directory schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/calendar-event.schema.json`.
pub type CalendarEvent = CalendarEventFields;

/// Counterpart for `spec/v1/artifacts/schemas/calendar-event.schema.json#/$defs/attendee`.
pub type Attendee = CalendarAttendee;

/// Counterpart for `spec/v1/artifacts/schemas/common-ids.schema.json`.
pub type CommonIds = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ContactOperations {
    ContactRequestRequestBody(crate::ContactRequestRequestBody),
    ContactRequestOutcome(crate::ContactRequestOutcome),
    ContactRespondRequestBody(crate::ContactRespondRequestBody),
    ContactRespondOutcome(crate::ContactRespondOutcome),
    ContactList(crate::ContactList),
    ContactTombstoneRequestBody(crate::ContactTombstoneRequestBody),
    ContactTombstone(crate::ContactTombstone),
    DirectConversationResolveRequestBody(crate::DirectConversationResolveRequestBody),
    DirectConversationResolveOutcome(crate::DirectConversationResolveOutcome),
}

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

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum DirectoryOperations {
    DirectorySearchRealmsRequestBody(DirectorySearchRealmsRequestBody),
    DirectoryRealmSearchOutcome(DirectoryRealmSearchOutcome),
    DirectoryResolveRealmRequestBody(DirectoryResolveRealmRequestBody),
    DirectoryRealmResolutionOutcome(DirectoryRealmResolutionOutcome),
    DirectoryResolveTargetRequestBody(DirectoryResolveTargetRequestBody),
    DirectoryTargetResolutionOutcome(DirectoryTargetResolutionOutcome),
    DirectorySearchOrganizationsRequestBody(DirectorySearchOrganizationsRequestBody),
    DirectoryOrganizationSearchOutcome(DirectoryOrganizationSearchOutcome),
    DirectoryResolveOrganizationRequestBody(DirectoryResolveOrganizationRequestBody),
    DirectoryOrganizationResolutionOutcome(DirectoryOrganizationResolutionOutcome),
    DirectorySearchActorsRequestBody(DirectorySearchActorsRequestBody),
    DirectoryActorSearchOutcome(DirectoryActorSearchOutcome),
    DirectorySearchUsersRequestBody(DirectorySearchUsersRequestBody),
    DirectoryUserSearchOutcome(DirectoryUserSearchOutcome),
    DirectoryResolveHandleRequestBody(DirectoryResolveHandleRequestBody),
    DirectoryHandleResolutionOutcome(DirectoryHandleResolutionOutcome),
    DirectoryResolveAgentSelectorRequestBody(DirectoryResolveAgentSelectorRequestBody),
    DirectoryAgentSelectorResolutionOutcome(DirectoryAgentSelectorResolutionOutcome),
    DirectoryListHandlesForSubjectRequestBody(DirectoryListHandlesForSubjectRequestBody),
    DirectoryPrivateContactDiscoveryRequestBody(crate::DirectoryPrivateContactDiscoveryRequestBody),
    DirectoryPrivateContactDiscoveryOutcome(crate::DirectoryPrivateContactDiscoveryOutcome),
    DirectoryPushRegisterRequestBody(DirectoryPushRegisterRequestBody),
    DirectoryPushRegisterOutcome(DirectoryPushRegisterOutcome),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/blinded_contact`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlindedContact {
    pub contact_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier_kind: Option<String>,
    pub identifier_commitment: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<BTreeMap<String, Value>>,
}

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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum ObjectPreviewId {
    Strand(StrandId),
    Message(MessageId),
    Event(EventId),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/pagination_request`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<crate::Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/private_contact_match`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PrivateContactMatch {
    pub contact_ref: String,
    pub match_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<Handle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_refs: Option<SourceRefs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_stub: Option<InviteConsentHandoffStub>,
}

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/proofs`.
pub type Proofs = Vec<Proof>;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/source_refs`.
pub type SourceRefs = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/subscription_id`.
pub type SubscriptionId = String;

/// Counterpart for `spec/v1/artifacts/schemas/list-handles-for-subject-response.schema.json`.
pub type ListHandlesForSubjectOutcome = DirectorySubjectHandleList;
