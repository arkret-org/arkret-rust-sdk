//! Server-side protocol contract types.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts without pulling a web stack into the SDK.

use std::collections::{BTreeMap, BTreeSet};

use arkret_core::{
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
    SyncBackfillOutcome, SyncDescription, SyncOutcome, SyncRequestBody,
};
pub use arkret_core::{AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms};
use arkret_state::SnapshotManifest;
// Shared protocol/product wire contracts now live in `arkret-core`; re-export
// them under stable `*_api` aliases for server-side consumers.
pub use arkret_core::{
    federation as federation_api, identity as identity_api, integration as integration_api,
    ops as ops_api, push as push_gateway_api,
};
pub use arkret_signatures as signatures;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub mod applet;
mod fixtures;
pub mod idempotency;
mod protocol;
mod registry;
#[cfg(test)]
mod tests;

#[cfg(feature = "salvo")]
pub use applet::router as applet_router;
pub use applet::{AppletHandler, AppletService, ServiceRoute, TransactionDispatch, service_routes};
pub use fixtures::*;
pub use idempotency::{
    APPLET_TRANSACTION_OPERATION_ID, IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity,
    IdempotencyWindow,
};
pub use protocol::*;
pub use registry::*;
