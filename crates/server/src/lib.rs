//! Server-side protocol contract types.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts without pulling a web stack into the SDK.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use cokret_contracts as api;
pub use cokret_contracts::federation as federation_api;
pub use cokret_contracts::identity as identity_api;
pub use cokret_contracts::integration as integration_api;
pub use cokret_contracts::principal as principal_api;
pub use cokret_contracts::push as push_gateway_api;
pub use cokret_core::{AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms};
pub use cokret_signatures as signatures;

use cokret_core::{
    AccountCursorRevokeOutcome, AccountCursorRevokeRequestBody, AppletActorView, AppletDescription,
    AppletPingOutcome, AppletProtocolMetadata, AppletRealmView, AppletTransactionOutcome,
    AppletTransactionRequestBody, AuthzCheckOutcome, AuthzCheckRequestBody, AuthzInviteList,
    BlobMetadata, BlobUploadMetadata, BlobUploadOutcome, DeviceMessagesGetOutcome,
    DeviceMessagesPutOutcome, DeviceMessagesPutRequestBody, DidOperationSubmitOutcome,
    DidOperationSubmitRequestBody, DirectoryActorSearchOutcome, DirectoryDescription,
    DirectoryHandleResolutionOutcome, DirectoryOrganizationResolutionOutcome,
    DirectoryOrganizationSearchOutcome, DirectoryRealmResolutionOutcome,
    DirectoryRealmSearchOutcome, DirectoryResolveHandleRequestBody,
    DirectoryResolveOrganizationRequestBody, DirectoryResolveRealmRequestBody,
    DirectorySearchActorsRequestBody, DirectorySearchOrganizationsRequestBody,
    DirectorySearchRealmsRequestBody, DirectorySearchUsersRequestBody, DirectoryUserSearchOutcome,
    FederationPullOperationsOutcome, FederationPushOperationsOutcome,
    FederationPushOperationsRequestBody, FederationRealmMemberList, FederationTransactionOutcome,
    FederationTransactionRequestBody, FederationVerifyActorOutcome,
    FederationVerifyActorRequestBody, GrantList, IdentityDescription, IdentityDocumentView,
    IdentityLogOutcome, IdentityReceiptsOutcome, IdentityResolveOutcome,
    IdentityResolveRequestBody, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody, MediaIceConfigOutcome,
    MediaIceConfigRequestBody, ModerationReportOutcome, ModerationReportRequestBody, OkOutcome,
    PolicyCheckOutcome, PolicyCheckRequestBody, PushNotifyOutcome, PushNotifyRequestBody,
    PushRegisterDeviceOutcome, PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
    Result, ServerDescription, SnapshotHeadState, SyncBackfillOutcome, SyncDescription,
    SyncOutcome, SyncRequestBody,
};

mod fixtures;
mod protocol;
mod registry;
#[cfg(test)]
mod tests;

pub use fixtures::*;
pub use protocol::*;
pub use registry::*;
