//! Contact and directory schema artifact counterparts retained by
//! `arkret-core`.
//!
//! The pure `$defs` shapes migrated to `arkret-models-discovery`
//! (re-exported below). The operation aggregation enums stay because
//! they reference core HTTP body DTOs; [`PaginationRequest`] stays
//! because it embeds the structured core [`crate::Cursor`].

pub use arkret_models_discovery::directory_artifacts::*;

use super::*;

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
/// `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/pagination_request`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<crate::Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}
