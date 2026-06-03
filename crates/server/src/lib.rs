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
    FederationPushOperationsResBody, FederationRealmMembersResBody, FederationTransactionReqBody,
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
