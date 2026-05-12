//! Contrix client-server API catalog and wire type exports.
//!
//! This crate is deliberately framework-free. Servers can use it to register
//! routes, clients can use it to discover operation IDs and conformance tests
//! can use the same catalog without depending on the Salvo adapter.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Product-local client API contracts.
///
/// These endpoints are not the canonical Contrix service operation registry.
/// Use [`endpoints`] / [`ENDPOINTS`] for protocol conformance and discovery.
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

mod catalog;
#[cfg(test)]
mod tests;

pub use catalog::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiSurface {
    Server,
    Identity,
    Sync,
    Federation,
    Directory,
    Blob,
    Push,
    DeviceMessages,
    Keys,
    Authz,
    Policy,
    Media,
    Moderation,
    Mimi,
    Account,
    Admin,
    Applet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
}

impl EndpointMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Post => "post",
            Self::Put => "put",
            Self::Delete => "delete",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub operation_id: &'static str,
    pub surface: ApiSurface,
    pub method: EndpointMethod,
    pub path: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
}

impl Endpoint {
    pub fn request_body_content_type(self) -> Option<&'static str> {
        match self.method {
            EndpointMethod::Post | EndpointMethod::Put => Some("application/json"),
            EndpointMethod::Get | EndpointMethod::Head | EndpointMethod::Delete => None,
        }
    }

    pub fn response_body_content_type(self) -> Option<&'static str> {
        match self.operation_id {
            "cx.blob.head" => None,
            "cx.blob.get" => Some("application/octet-stream"),
            "cx.events.subscribe" => Some("application/x-ndjson"),
            _ => Some("application/json"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointParameterLocation {
    Path,
    Query,
    Header,
}

impl EndpointParameterLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointParameter {
    pub name: &'static str,
    pub location: EndpointParameterLocation,
    pub required: bool,
    pub schema: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSchemaBinding {
    pub operation_id: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
    pub request_body_content_type: Option<&'static str>,
    pub response_body_content_type: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedEndpoint<'a> {
    pub endpoint: &'a Endpoint,
    pub path_parameters: BTreeMap<String, String>,
}
