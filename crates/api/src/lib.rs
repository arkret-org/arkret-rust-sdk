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
        AppletActorResponse, AppletDescription, AppletPingResponse, AppletProtocolResponse,
        AppletSpaceResponse, AppletTransactionRequest, AppletTransactionResponse,
        AuthzCheckRequest, AuthzCheckResponse, AuthzInvitesResponse, BlobMetadata,
        BlobUploadMetadata, BlobUploadResponse, DeviceMessagesReceiveResponse,
        DeviceMessagesSendRequest, DeviceMessagesSendResponse, DirectoryAnnounceRequest,
        DirectoryAnnounceResponse, DirectoryDescription, DirectoryResolveHandleRequest,
        DirectoryResolveHandleResponse, DirectoryResolveOrganizationRequest,
        DirectoryResolveOrganizationResponse, DirectoryResolveSpaceRequest,
        DirectoryResolveSpaceResponse, DirectorySearchActorsRequest, DirectorySearchActorsResponse,
        DirectorySearchOrganizationsRequest, DirectorySearchOrganizationsResponse,
        DirectorySearchSpacesRequest, DirectorySearchSpacesResponse, DirectorySearchUsersResponse,
        DirectoryWithdrawRequest, DirectoryWithdrawResponse, EffectiveGrantsResponse,
        FederationPullOperationsResponse, FederationPushOperationsRequest,
        FederationPushOperationsResponse, FederationSpaceMembersResponse,
        FederationTransactionRequest, FederationTransactionResponse, FederationVerifyActorRequest,
        FederationVerifyActorResponse, IdentityDescription, IdentityDocumentResponse,
        IdentityLogResponse, IdentityReceiptsResponse, IdentityResolveRequest,
        IdentityResolveResponse, KeyBackup, KeyBackupDeleteRequest, KeyBackupDeleteResponse,
        KeyBackupPath, KeyBackupPutResponse, KeyBackupSummary, KeyBackupsListQuery,
        KeyBackupsListResponse, KeysClaimRequest, KeysClaimResponse, KeysQueryRequest,
        KeysQueryResponse, KeysUploadRequest, KeysUploadResponse, MediaIceConfigRequest,
        MediaIceConfigResponse, ModerationReportRequest, ModerationReportResponse, OkResponse,
        PolicyCheckRequest, PolicyCheckResponse, PushNotifyRequest, PushNotifyResponse,
        PushRegisterDeviceRequest, PushRegisterDeviceResponse, PushUnregisterDeviceRequest,
        ServerDescription, SubmitDidOperationRequest, SubmitDidOperationResponse,
        SyncBackfillResponse, SyncDescription, SyncRequest, SyncResponse, SyncSnapshotHeadResponse,
    };
}

#[cfg(test)]
mod tests;
