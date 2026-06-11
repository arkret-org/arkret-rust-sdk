//! Cokret client-server wire type exports.
//!
//! This crate is deliberately framework-free. It exports protocol wire types
//! and product-local API models without maintaining an HTTP endpoint catalog.
//!
//! Admission rule for new local DTOs: a type belongs here only when it is
//! consumed by two or more repos, is a spec-defined cross-service wire
//! contract, or is a producer/consumer contract that must be shared to prevent
//! drift. Otherwise keep it in the owning service or SDK feature module.

/// Product-local client API contracts.
///
/// These endpoints are product API metadata, not the canonical Cokret service
/// operation registry.
pub mod client;
pub mod product {
    //! Product-local API surfaces outside the canonical service operation registry.

    pub use crate::client;
}
pub mod federation;
pub mod identity;
pub mod integration;
pub mod ops;
pub mod principal;
pub mod push;

/// Protocol request/response types grouped behind the API boundary.
pub mod protocol {
    pub use cokret_core::{
        AccountCursorRevokeOutcome, AccountCursorRevokeRequestBody, AccountSubscribeFrame,
        AccountSubscribeFrameKind, AccountSubscribeRealms, AgentSelectorClaim, AppletActorView,
        AppletDescription, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
        AppletTransactionOutcome, AppletTransactionRequestBody, AuthzCheckOutcome,
        AuthzCheckRequestBody, AuthzInviteList, BlobMetadata, BlobUploadMetadata,
        BlobUploadOutcome, CursorRevokeScope, DeviceMessagesAckOutcome,
        DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesPutOutcome,
        DeviceMessagesPutRequestBody, DidOperationSubmitOutcome, DidOperationSubmitRequestBody,
        DirectoryActorSearchOutcome, DirectoryAgentSelectorResolutionOutcome,
        DirectoryAnnounceOutcome, DirectoryAnnounceRequestBody, DirectoryDescription,
        DirectoryHandleResolutionOutcome, DirectoryListHandlesForSubjectRequestBody,
        DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
        DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
        DirectoryResolveAgentSelectorRequestBody, DirectoryResolveHandleRequestBody,
        DirectoryResolveOrganizationRequestBody, DirectoryResolveRealmRequestBody,
        DirectoryResolveTargetRequestBody, DirectorySearchActorsRequestBody,
        DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
        DirectorySearchUsersRequestBody, DirectorySubjectHandleList,
        DirectoryTargetResolutionOutcome, DirectoryUserSearchOutcome, DirectoryWithdrawOutcome,
        DirectoryWithdrawRequestBody, FederationPullOperationsOutcome,
        FederationPushOperationsOutcome, FederationPushOperationsRequestBody,
        FederationRealmMemberList, FederationTransactionOutcome, FederationTransactionRequestBody,
        FederationVerifyActorOutcome, FederationVerifyActorRequestBody, GrantList,
        IdentityDescription, IdentityDocumentView, IdentityLogOutcome, IdentityReceiptsOutcome,
        IdentityResolveOutcome, IdentityResolveRequestBody, KeyBackup, KeyBackupPath,
        KeyBackupSummary, KeyBackupsListQuery, KeysBackupsDeleteOutcome,
        KeysBackupsDeleteRequestBody, KeysBackupsList, KeysBackupsPutOutcome, KeysClaimOutcome,
        KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody, KeysUploadOutcome,
        KeysUploadRequestBody, MediaIceConfigOutcome, MediaIceConfigRequestBody,
        ModerationReportOutcome, ModerationReportRequestBody, OkOutcome, PolicyCheckOutcome,
        PolicyCheckRequestBody, PushNotifyOutcome, PushNotifyRequestBody,
        PushRegisterDeviceOutcome, PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
        ServerDescription, SnapshotHeadState, SyncBackfillOutcome, SyncDescription, SyncOutcome,
        SyncRequestBody,
    };
}

#[cfg(test)]
mod tests;
