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
    AppletActorOutput, AppletDescription, AppletPingOutput, AppletProtocolOutput,
    AppletSpaceOutput, AppletTransactionReqBody, AppletTransactionOutput, AuthzCheckReqBody,
    AuthzCheckOutput, AuthzInvitesOutput, BlobMetadata, BlobUploadMetadata, BlobUploadOutput,
    DeviceMessagesReceiveOutput, DeviceMessagesSendReqBody, DeviceMessagesSendOutput,
    DirectoryDescription, DirectoryResolveHandleReqBody, DirectoryResolveHandleOutput,
    DirectoryResolveOrganizationReqBody, DirectoryResolveOrganizationOutput,
    DirectoryResolveSpaceReqBody, DirectoryResolveSpaceOutput, DirectorySearchActorsReqBody,
    DirectorySearchActorsOutput, DirectorySearchOrganizationsReqBody,
    DirectorySearchOrganizationsOutput, DirectorySearchSpacesReqBody,
    DirectorySearchSpacesOutput, DirectorySearchUsersReqBody, DirectorySearchUsersOutput,
    EffectiveGrantsOutput, FederationPullOperationsOutput, FederationPushOperationsReqBody,
    FederationPushOperationsOutput, FederationSpaceMembersOutput, FederationTransactionReqBody,
    FederationTransactionOutput, FederationVerifyActorReqBody, FederationVerifyActorOutput,
    IdentityDescription, IdentityDocumentOutput, IdentityLogOutput, IdentityReceiptsOutput,
    IdentityResolveReqBody, IdentityResolveOutput, KeysClaimReqBody, KeysClaimOutput,
    KeysQueryReqBody, KeysQueryOutput, KeysUploadReqBody, KeysUploadOutput,
    MediaIceConfigReqBody, MediaIceConfigOutput, ModerationReportReqBody,
    ModerationReportOutput, OkOutput, PolicyCheckReqBody, PolicyCheckOutput,
    PushNotifyReqBody, PushNotifyOutput, PushRegisterDeviceReqBody, PushRegisterDeviceOutput,
    PushUnregisterDeviceReqBody, Result, ServerDescription, SubmitDidOperationReqBody,
    SubmitDidOperationOutput, SyncBackfillOutput, SyncDescription, SyncReqBody, SyncOutput,
    SyncSnapshotHeadOutput,
};

mod fixtures;
mod protocol;
mod registry;
#[cfg(test)]
mod tests;

pub use fixtures::*;
pub use protocol::*;
pub use registry::*;
