//! Server-side protocol contract types.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts without pulling a web stack into the SDK.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use contrix_api as api;
pub use contrix_api::federation as federation_api;
pub use contrix_api::identity as identity_api;
pub use contrix_api::push as push_gateway_api;
pub use contrix_signatures as signatures;

use contrix_core::{
    AppletActorResponse, AppletDescription, AppletPingResponse, AppletProtocolResponse,
    AppletSpaceResponse, AppletTransactionRequest, AppletTransactionResponse, AuthzCheckRequest,
    AuthzCheckResponse, AuthzInvitesResponse, BlobMetadata, BlobUploadMetadata, BlobUploadResponse,
    DeviceMessagesReceiveResponse, DeviceMessagesSendRequest, DeviceMessagesSendResponse,
    DirectoryDescription, DirectoryResolveHandleRequest, DirectoryResolveHandleResponse,
    DirectoryResolveOrganizationRequest, DirectoryResolveOrganizationResponse,
    DirectoryResolveSpaceRequest, DirectoryResolveSpaceResponse, DirectorySearchActorsRequest,
    DirectorySearchActorsResponse, DirectorySearchOrganizationsRequest,
    DirectorySearchOrganizationsResponse, DirectorySearchSpacesRequest,
    DirectorySearchSpacesResponse, DirectorySearchUsersResponse, EffectiveGrantsResponse,
    FederationPullOperationsResponse, FederationPushOperationsRequest,
    FederationPushOperationsResponse, FederationSpaceMembersResponse, FederationTransactionRequest,
    FederationTransactionResponse, FederationVerifyActorRequest, FederationVerifyActorResponse,
    IdentityDescription, IdentityDocumentResponse, IdentityLogResponse, IdentityReceiptsResponse,
    IdentityResolveRequest, IdentityResolveResponse, KeysClaimRequest, KeysClaimResponse,
    KeysQueryRequest, KeysQueryResponse, KeysUploadRequest, KeysUploadResponse,
    MediaIceConfigRequest, MediaIceConfigResponse, ModerationReportRequest,
    ModerationReportResponse, OkResponse, PolicyCheckRequest, PolicyCheckResponse,
    PushNotifyRequest, PushNotifyResponse, PushRegisterDeviceRequest, PushRegisterDeviceResponse,
    PushUnregisterDeviceRequest, Result, ServerDescription, SubmitDidOperationRequest,
    SubmitDidOperationResponse, SyncBackfillResponse, SyncDescription, SyncRequest, SyncResponse,
    SyncSnapshotHeadResponse,
};

mod fixtures;
mod openapi;
mod protocol;
mod registry;
#[cfg(test)]
mod tests;

pub use fixtures::*;
pub use openapi::*;
pub use protocol::*;
pub use registry::*;
