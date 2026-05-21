//! Contrix client-server wire type exports.
//!
//! This crate is deliberately framework-free. It exports protocol wire types
//! and product-local API models without maintaining an HTTP endpoint catalog.

/// Product-local client API contracts.
///
/// These endpoints are product API metadata, not the canonical Contrix service
/// operation registry.
pub mod client;
pub mod product {
    //! Product-local API surfaces outside the canonical service operation registry.

    pub use crate::client;
}
pub mod federation;
pub mod identity;
pub mod push;

/// Protocol request/response types grouped behind the API boundary.
pub mod protocol {
    pub use contrix_core::{
        AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
        AppletActorResBody, AppletDescription, AppletPingResBody, AppletProtocolResBody,
        AppletSpaceResBody, AppletTransactionReqBody, AppletTransactionResBody, AuthzCheckReqBody,
        AuthzCheckResBody, AuthzInvitesResBody, BlobMetadata, BlobUploadMetadata,
        BlobUploadResBody, DeviceMessagesReceiveResBody, DeviceMessagesSendReqBody,
        DeviceMessagesSendResBody, DirectoryAnnounceReqBody, DirectoryAnnounceResBody,
        DirectoryDescription, DirectoryResolveHandleReqBody, DirectoryResolveHandleResBody,
        DirectoryResolveOrganizationReqBody, DirectoryResolveOrganizationResBody,
        DirectoryResolveSpaceReqBody, DirectoryResolveSpaceResBody, DirectorySearchActorsReqBody,
        DirectorySearchActorsResBody, DirectorySearchOrganizationsReqBody,
        DirectorySearchOrganizationsResBody, DirectorySearchSpacesReqBody,
        DirectorySearchSpacesResBody, DirectorySearchUsersReqBody, DirectorySearchUsersResBody,
        DirectoryWithdrawReqBody, DirectoryWithdrawResBody, EffectiveGrantsResBody,
        FederationPullOperationsResBody, FederationPushOperationsReqBody,
        FederationPushOperationsResBody, FederationSpaceMembersResBody,
        FederationTransactionReqBody, FederationTransactionResBody, FederationVerifyActorReqBody,
        FederationVerifyActorResBody, IdentityDescription, IdentityDocumentResBody,
        IdentityLogResBody, IdentityReceiptsResBody, IdentityResolveReqBody,
        IdentityResolveResBody, KeyBackup, KeyBackupDeleteReqBody, KeyBackupDeleteResBody,
        KeyBackupPath, KeyBackupPutResBody, KeyBackupSummary, KeyBackupsListQuery,
        KeyBackupsListResBody, KeysClaimReqBody, KeysClaimResBody, KeysQueryReqBody,
        KeysQueryResBody, KeysUploadReqBody, KeysUploadResBody, MediaIceConfigReqBody,
        MediaIceConfigResBody, ModerationReportReqBody, ModerationReportResBody, OkResBody,
        PolicyCheckReqBody, PolicyCheckResBody, PushNotifyReqBody, PushNotifyResBody,
        PushRegisterDeviceReqBody, PushRegisterDeviceResBody, PushUnregisterDeviceReqBody,
        ServerDescription, SubmitDidOperationReqBody, SubmitDidOperationResBody,
        SyncBackfillResBody, SyncDescription, SyncReqBody, SyncResBody, SyncSnapshotHeadResBody,
    };
}

#[cfg(test)]
mod tests;
