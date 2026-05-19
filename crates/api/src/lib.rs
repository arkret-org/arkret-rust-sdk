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
        AppletActorOutput, AppletDescription, AppletPingOutput, AppletProtocolOutput,
        AppletSpaceOutput, AppletTransactionReqBody, AppletTransactionOutput,
        AuthzCheckReqBody, AuthzCheckOutput, AuthzInvitesOutput, BlobMetadata,
        BlobUploadMetadata, BlobUploadOutput, DeviceMessagesReceiveOutput,
        DeviceMessagesSendReqBody, DeviceMessagesSendOutput, DirectoryAnnounceReqBody,
        DirectoryAnnounceOutput, DirectoryDescription, DirectoryResolveHandleReqBody,
        DirectoryResolveHandleOutput, DirectoryResolveOrganizationReqBody,
        DirectoryResolveOrganizationOutput, DirectoryResolveSpaceReqBody,
        DirectoryResolveSpaceOutput, DirectorySearchActorsReqBody, DirectorySearchActorsOutput,
        DirectorySearchOrganizationsReqBody, DirectorySearchOrganizationsOutput,
        DirectorySearchSpacesReqBody, DirectorySearchSpacesOutput, DirectorySearchUsersReqBody,
        DirectorySearchUsersOutput, DirectoryWithdrawReqBody, DirectoryWithdrawOutput,
        EffectiveGrantsOutput, FederationPullOperationsOutput, FederationPushOperationsReqBody,
        FederationPushOperationsOutput, FederationSpaceMembersOutput,
        FederationTransactionReqBody, FederationTransactionOutput, FederationVerifyActorReqBody,
        FederationVerifyActorOutput, IdentityDescription, IdentityDocumentOutput,
        IdentityLogOutput, IdentityReceiptsOutput, IdentityResolveReqBody,
        IdentityResolveOutput, KeyBackup, KeyBackupDeleteReqBody, KeyBackupDeleteOutput,
        KeyBackupPath, KeyBackupPutOutput, KeyBackupSummary, KeyBackupsListQuery,
        KeyBackupsListOutput, KeysClaimReqBody, KeysClaimOutput, KeysQueryReqBody,
        KeysQueryOutput, KeysUploadReqBody, KeysUploadOutput, MediaIceConfigReqBody,
        MediaIceConfigOutput, ModerationReportReqBody, ModerationReportOutput, OkOutput,
        PolicyCheckReqBody, PolicyCheckOutput, PushNotifyReqBody, PushNotifyOutput,
        PushRegisterDeviceReqBody, PushRegisterDeviceOutput, PushUnregisterDeviceReqBody,
        ServerDescription, SubmitDidOperationReqBody, SubmitDidOperationOutput,
        SyncBackfillOutput, SyncDescription, SyncReqBody, SyncOutput, SyncSnapshotHeadOutput,
    };
}

#[cfg(test)]
mod tests;
