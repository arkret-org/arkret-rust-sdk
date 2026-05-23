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
pub use contrix_core::{AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms};
pub use contrix_signatures as signatures;

use contrix_core::{
    AccountCursorRevokeReqBody, AccountCursorRevokeResBody, AppletActorResBody, AppletDescription,
    AppletPingResBody, AppletProtocolResBody, AppletRealmResBody, AppletTransactionReqBody,
    AppletTransactionResBody, AuthzCheckReqBody, AuthzCheckResBody, AuthzInvitesResBody,
    BlobMetadata, BlobUploadMetadata, BlobUploadResBody, DeviceMessagesReceiveResBody,
    DeviceMessagesSendReqBody, DeviceMessagesSendResBody, DirectoryDescription,
    DirectoryResolveHandleReqBody, DirectoryResolveHandleResBody,
    DirectoryResolveOrganizationReqBody, DirectoryResolveOrganizationResBody,
    DirectoryResolveRealmReqBody, DirectoryResolveRealmResBody, DirectorySearchActorsReqBody,
    DirectorySearchActorsResBody, DirectorySearchOrganizationsReqBody,
    DirectorySearchOrganizationsResBody, DirectorySearchRealmsReqBody,
    DirectorySearchRealmsResBody, DirectorySearchUsersReqBody, DirectorySearchUsersResBody,
    EffectiveGrantsResBody, FederationPullOperationsResBody, FederationPushOperationsReqBody,
    FederationPushOperationsResBody, FederationSpaceMembersResBody, FederationTransactionReqBody,
    FederationTransactionResBody, FederationVerifyActorReqBody, FederationVerifyActorResBody,
    IdentityDescription, IdentityDocumentResBody, IdentityLogResBody, IdentityReceiptsResBody,
    IdentityResolveReqBody, IdentityResolveResBody, KeysClaimReqBody, KeysClaimResBody,
    KeysQueryReqBody, KeysQueryResBody, KeysUploadReqBody, KeysUploadResBody,
    MediaIceConfigReqBody, MediaIceConfigResBody, ModerationReportReqBody, ModerationReportResBody,
    OkResBody, PolicyCheckReqBody, PolicyCheckResBody, PushNotifyReqBody, PushNotifyResBody,
    PushRegisterDeviceReqBody, PushRegisterDeviceResBody, PushUnregisterDeviceReqBody, Result,
    ServerDescription, SubmitDidOperationReqBody, SubmitDidOperationResBody, SyncBackfillResBody,
    SyncDescription, SyncReqBody, SyncResBody, SyncSnapshotHeadResBody,
};

mod fixtures;
mod protocol;
mod registry;
#[cfg(test)]
mod tests;

pub use fixtures::*;
pub use protocol::*;
pub use registry::*;
