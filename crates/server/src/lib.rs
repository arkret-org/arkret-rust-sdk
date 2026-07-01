//! Server-side protocol contract types.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts without pulling a web stack into the SDK.

use std::collections::{BTreeMap, BTreeSet};

use cokret_core::{
    AccountCursorRevokeOutcome, AccountCursorRevokeRequestBody, AppletActorView, AppletDescription,
    AppletPingOutcome, AppletProtocolMetadata, AppletRealmView, AppletTransactionOutcome,
    AppletTransactionRequestBody, AuthzCheckOutcome, AuthzCheckRequestBody, AuthzInviteList,
    BlobMetadata, BlobUploadMetadata, BlobUploadOutcome, DeviceMessagesAckOutcome,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesPutOutcome,
    DeviceMessagesPutRequestBody, DidOperationSubmitOutcome, DidOperationSubmitRequestBody,
    DirectoryActorSearchOutcome, DirectoryDescription, DirectoryHandleResolutionOutcome,
    DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveHandleRequestBody, DirectoryResolveOrganizationRequestBody,
    DirectoryResolveRealmRequestBody, DirectorySearchActorsRequestBody,
    DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
    DirectorySearchUsersRequestBody, DirectoryUserSearchOutcome, FederationPullOperationsOutcome,
    FederationPushOperationsOutcome, FederationPushOperationsRequestBody,
    FederationRealmMemberList, FederationTransactionOutcome, FederationTransactionRequestBody,
    FederationVerifyActorOutcome, FederationVerifyActorRequestBody, GrantList, IdentityDescription,
    IdentityDocumentView, IdentityLogListOutcome, IdentityReceiptListOutcome,
    IdentityResolveOutcome, IdentityResolveRequestBody, KeysClaimOutcome, KeysClaimRequestBody,
    KeysQueryOutcome, KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody,
    MediaIceConfigOutcome, MediaIceConfigRequestBody, ModerationReportOutcome,
    ModerationReportRequestBody, OkOutcome, PolicyCheckOutcome, PolicyCheckRequestBody,
    PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody, Result, ServerDescription,
    SnapshotManifest, SyncBackfillOutcome, SyncDescription, SyncOutcome, SyncRequestBody,
};
pub use cokret_core::{AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms};
// Shared protocol/product wire contracts now live in `cokret-core`; re-export
// them under stable `*_api` aliases for server-side consumers.
pub use cokret_core::{
    federation as federation_api, identity as identity_api, integration as integration_api,
    ops as ops_api, push as push_gateway_api,
};
pub use cokret_signatures as signatures;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod fixtures;
mod protocol;
mod registry;
#[cfg(test)]
mod tests;

pub use fixtures::*;
pub use protocol::*;
pub use registry::*;
