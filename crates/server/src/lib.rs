//! Server-side protocol contract types.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts without pulling a web stack into the SDK.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::federation::wire_dtos::{
    FederationRealmMemberList, FederationVerifyActorOutcome, FederationVerifyActorRequestBody,
};
use arkret_models_collaboration::governance::authorization::{
    AuthzCheckOutcome, AuthzCheckRequestBody, AuthzInviteList, GrantList,
};
use arkret_models_collaboration::governance::moderation::{
    ModerationReportOutcome, ModerationReportRequestBody,
};
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckOutcome, PolicyCheckRequestBody,
};
use arkret_models_collaboration::http_bodies::{AppletTransactionRequestBody, EventsQueryOutcome};
use arkret_models_collaboration::objects::blob::{Blob, BlobUploadMetadata, BlobUploadOutcome};
use arkret_models_collaboration::objects::media::{
    MediaIceConfigOutcome, MediaIceConfigRequestBody,
};
pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome,
    DeviceMessagesSendOutcome, DeviceMessagesSendRequestBody,
};
use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
use arkret_models_crypto::keys::{
    KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody,
    KeysUploadOutcome, KeysUploadRequestBody,
};
use arkret_models_discovery::directory::{
    DirectoryActorSearchOutcome, DirectoryHandleResolutionOutcome,
    DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveHandleRequestBody, DirectoryResolveOrganizationRequestBody,
    DirectoryResolveRealmRequestBody, DirectorySearchActorsRequestBody,
    DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
    DirectorySearchUsersRequestBody, DirectoryUserSearchOutcome,
};
use arkret_models_discovery::service_description::ServiceDescribe;
use arkret_models_identity::account::{AccountCursorRevokeOutcome, AccountCursorRevokeRequestBody};
use arkret_models_identity::identity::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, IdentityDescription,
    IdentityDocumentView, IdentityLogListOutcome, IdentityReceiptListOutcome,
    IdentityResolveOutcome, IdentityResolveRequestBody,
};
use arkret_models_identity::service_identity::{
    ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey, ServiceRegistrationOutcome,
};
use arkret_models_integration::applet_models::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome,
};
use arkret_models_integration::models_push::{
    OkOutcome, PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
};
pub use arkret_signatures as signatures;
use arkret_state::SnapshotManifest;
use arkret_wire::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub mod applet;
pub mod cursor_authority;
mod fixtures;
pub mod idempotency;
mod protocol;
mod registry;
#[cfg(test)]
mod tests;

pub use applet::{AppletHandler, AppletService, ServiceRoute, TransactionDispatch, service_routes};
pub use arkret_rate_limit::{
    FixedWindowConfig, MemoryFixedWindowRateLimiter, MemoryTokenBucketRateLimiter,
    RateLimitRejection, TokenBucketConfig,
};
pub use cursor_authority::{
    CursorAuthority, CursorAuthorityError, CursorBindingContext, CursorBindingRecord,
    MemoryCursorAuthority, cursor_filter_digest,
};
pub use fixtures::*;
pub use idempotency::{
    IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity, IdempotencyWindow,
    TransactionClaim, TransactionIdempotencyStore,
};
pub use protocol::*;
pub use registry::*;
