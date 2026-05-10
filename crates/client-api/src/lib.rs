//! Client-server protocol API contracts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use contrix_api::push::{PushPriority, PushRule, PushRuleSet, Pusher};
use contrix_core::{
    BlobRef, DeviceId, Did, EncryptedPayload, Error, EventId, Hash, Hlc, InviteId, Result, SpaceId,
};
use contrix_crypto::MediaEncryptionInfo;
use contrix_html::{RichTextDocument, RichTextFormat};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientApiSurface {
    Account,
    InteractiveAuth,
    Device,
    Profile,
    Space,
    Membership,
    Messaging,
    State,
    Sync,
    Search,
    Directory,
    Media,
    Push,
    Moderation,
    Call,
    Extensions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClientApiMethod {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientApiEndpoint {
    pub operation_id: &'static str,
    pub surface: ClientApiSurface,
    pub method: ClientApiMethod,
    pub path: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
}

pub const CLIENT_API_ENDPOINTS: &[ClientApiEndpoint] = &[
    ClientApiEndpoint {
        operation_id: "cx.account.register",
        surface: ClientApiSurface::Account,
        method: ClientApiMethod::Post,
        path: "/api/v1/account/register",
        request_schema: "AccountRegisterRequest",
        response_schema: "SessionResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.account.login",
        surface: ClientApiSurface::Account,
        method: ClientApiMethod::Post,
        path: "/api/v1/account/login",
        request_schema: "LoginRequest",
        response_schema: "SessionResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.account.refresh",
        surface: ClientApiSurface::Account,
        method: ClientApiMethod::Post,
        path: "/api/v1/account/refresh",
        request_schema: "TokenRefreshRequest",
        response_schema: "SessionResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.account.logout",
        surface: ClientApiSurface::Account,
        method: ClientApiMethod::Post,
        path: "/api/v1/account/logout",
        request_schema: "LogoutRequest",
        response_schema: "Ok",
    },
    ClientApiEndpoint {
        operation_id: "cx.account.whoami",
        surface: ClientApiSurface::Account,
        method: ClientApiMethod::Get,
        path: "/api/v1/account/whoami",
        request_schema: "Empty",
        response_schema: "WhoamiResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.auth.interactive.submit",
        surface: ClientApiSurface::InteractiveAuth,
        method: ClientApiMethod::Post,
        path: "/api/v1/auth/interactive/submit",
        request_schema: "InteractiveAuthSubmission",
        response_schema: "InteractiveAuthChallenge",
    },
    ClientApiEndpoint {
        operation_id: "cx.devices.list",
        surface: ClientApiSurface::Device,
        method: ClientApiMethod::Get,
        path: "/api/v1/devices",
        request_schema: "Empty",
        response_schema: "DeviceListResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.devices.update",
        surface: ClientApiSurface::Device,
        method: ClientApiMethod::Put,
        path: "/api/v1/devices/{device_id}",
        request_schema: "UpdateDeviceRequest",
        response_schema: "DeviceInfo",
    },
    ClientApiEndpoint {
        operation_id: "cx.profile.get",
        surface: ClientApiSurface::Profile,
        method: ClientApiMethod::Get,
        path: "/api/v1/profile/{user_id}",
        request_schema: "ProfileRequest",
        response_schema: "ProfileResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.profile.set",
        surface: ClientApiSurface::Profile,
        method: ClientApiMethod::Put,
        path: "/api/v1/profile/{user_id}",
        request_schema: "ProfileUpdateRequest",
        response_schema: "ProfileResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.presence.subscribe",
        surface: ClientApiSurface::Profile,
        method: ClientApiMethod::Post,
        path: "/api/v1/presence/subscribe",
        request_schema: "PresenceSubscriptionRequest",
        response_schema: "Ok",
    },
    ClientApiEndpoint {
        operation_id: "cx.spaces.create",
        surface: ClientApiSurface::Space,
        method: ClientApiMethod::Post,
        path: "/api/v1/spaces",
        request_schema: "SpaceCreateRequest",
        response_schema: "SpaceResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.spaces.preview",
        surface: ClientApiSurface::Space,
        method: ClientApiMethod::Get,
        path: "/api/v1/spaces/{space_id}/preview",
        request_schema: "SpacePreviewRequest",
        response_schema: "SpacePreviewResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.membership.action",
        surface: ClientApiSurface::Membership,
        method: ClientApiMethod::Post,
        path: "/api/v1/spaces/{space_id}/membership",
        request_schema: "MembershipActionRequest",
        response_schema: "MembershipActionResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.messages.send",
        surface: ClientApiSurface::Messaging,
        method: ClientApiMethod::Post,
        path: "/api/v1/spaces/{space_id}/messages",
        request_schema: "SendMessageRequest",
        response_schema: "SendEventResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.messages.redact",
        surface: ClientApiSurface::Messaging,
        method: ClientApiMethod::Post,
        path: "/api/v1/spaces/{space_id}/events/{event_id}/redact",
        request_schema: "RedactEventRequest",
        response_schema: "SendEventResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.state.get",
        surface: ClientApiSurface::State,
        method: ClientApiMethod::Get,
        path: "/api/v1/spaces/{space_id}/state/{subject}",
        request_schema: "StateGetRequest",
        response_schema: "StateEventResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.state.set",
        surface: ClientApiSurface::State,
        method: ClientApiMethod::Put,
        path: "/api/v1/spaces/{space_id}/state/{subject}",
        request_schema: "StateSetRequest",
        response_schema: "SendEventResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.search.messages",
        surface: ClientApiSurface::Search,
        method: ClientApiMethod::Post,
        path: "/api/v1/search/messages",
        request_schema: "MessageSearchRequest",
        response_schema: "MessageSearchResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.search.event_context",
        surface: ClientApiSurface::Search,
        method: ClientApiMethod::Get,
        path: "/api/v1/events/{event_id}/context",
        request_schema: "EventContextRequest",
        response_schema: "EventContextResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.directory.search_spaces",
        surface: ClientApiSurface::Directory,
        method: ClientApiMethod::Post,
        path: "/api/v1/directory/spaces/search",
        request_schema: "DirectorySearchRequest",
        response_schema: "DirectorySearchResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.directory.resolve_alias",
        surface: ClientApiSurface::Directory,
        method: ClientApiMethod::Get,
        path: "/api/v1/directory/aliases/{alias}",
        request_schema: "DirectoryAliasRequest",
        response_schema: "DirectoryAliasResponse",
    },
    // C17 (spec 2026-05-08): operation_id renamed cx.sync.subscribe →
    // cx.sync.account; path unchanged. The "POST /api/v1/sync" endpoint here is
    // the account-aggregate sync (to_device / account_data / device_lists /
    // presence / cross-Space delta) — distinct from the per-Event-Envelope
    // streaming surface which is now `cx.events.subscribe` at GET
    // /api/v1/events/subscribe (see contrix-api crate).
    ClientApiEndpoint {
        operation_id: "cx.sync.account",
        surface: ClientApiSurface::Sync,
        method: ClientApiMethod::Post,
        path: "/api/v1/sync",
        request_schema: "SyncRequest",
        response_schema: "SyncEnvelope",
    },
    ClientApiEndpoint {
        operation_id: "cx.sync.sliding",
        surface: ClientApiSurface::Sync,
        method: ClientApiMethod::Post,
        path: "/api/v1/sync/sliding",
        request_schema: "SlidingSyncRequest",
        response_schema: "SyncEnvelope",
    },
    ClientApiEndpoint {
        operation_id: "cx.media.upload",
        surface: ClientApiSurface::Media,
        method: ClientApiMethod::Post,
        path: "/api/v1/media/upload",
        request_schema: "MediaUploadRequest",
        response_schema: "MediaUploadTicket",
    },
    ClientApiEndpoint {
        operation_id: "cx.media.download",
        surface: ClientApiSurface::Media,
        method: ClientApiMethod::Get,
        path: "/api/v1/media/{blob_ref}",
        request_schema: "MediaDownloadRequest",
        response_schema: "MediaDownloadResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.pushers.list",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Get,
        path: "/api/v1/pushers",
        request_schema: "Empty",
        response_schema: "PusherListResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.pushers.set",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Put,
        path: "/api/v1/pushers/{device_id}",
        request_schema: "SetPusherRequest",
        response_schema: "Pusher",
    },
    ClientApiEndpoint {
        operation_id: "cx.pushers.delete",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Delete,
        path: "/api/v1/pushers/{device_id}",
        request_schema: "DeletePusherRequest",
        response_schema: "Ok",
    },
    ClientApiEndpoint {
        operation_id: "cx.push_rules.get",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Get,
        path: "/api/v1/push/rules",
        request_schema: "Empty",
        response_schema: "PushRuleListResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.push_rules.set",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Put,
        path: "/api/v1/push/rules/{rule_id}",
        request_schema: "PushRuleUpdateRequest",
        response_schema: "PushRule",
    },
    ClientApiEndpoint {
        operation_id: "cx.push_rules.delete",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Delete,
        path: "/api/v1/push/rules/{rule_id}",
        request_schema: "PushRuleDeleteRequest",
        response_schema: "Ok",
    },
    ClientApiEndpoint {
        operation_id: "cx.notifications.settings.get",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Get,
        path: "/api/v1/notifications/settings",
        request_schema: "Empty",
        response_schema: "NotificationSettings",
    },
    ClientApiEndpoint {
        operation_id: "cx.notifications.settings.set",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Put,
        path: "/api/v1/notifications/settings",
        request_schema: "NotificationSettings",
        response_schema: "NotificationSettings",
    },
    ClientApiEndpoint {
        operation_id: "cx.notifications.counts",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Post,
        path: "/api/v1/notifications/counts",
        request_schema: "NotificationCountsRequest",
        response_schema: "NotificationCountsResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.notifications.list",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Post,
        path: "/api/v1/notifications",
        request_schema: "NotificationListRequest",
        response_schema: "NotificationListResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.notifications.mark_read",
        surface: ClientApiSurface::Push,
        method: ClientApiMethod::Post,
        path: "/api/v1/notifications/read",
        request_schema: "MarkNotificationsReadRequest",
        response_schema: "Ok",
    },
    ClientApiEndpoint {
        operation_id: "cx.moderation.report",
        surface: ClientApiSurface::Moderation,
        method: ClientApiMethod::Post,
        path: "/api/v1/moderation/reports",
        request_schema: "ReportRequest",
        response_schema: "ReportResponse",
    },
    ClientApiEndpoint {
        operation_id: "cx.call.signal",
        surface: ClientApiSurface::Call,
        method: ClientApiMethod::Post,
        path: "/api/v1/calls/{call_id}/signal",
        request_schema: "CallSignal",
        response_schema: "Ok",
    },
    ClientApiEndpoint {
        operation_id: "cx.extensions.discovery",
        surface: ClientApiSurface::Extensions,
        method: ClientApiMethod::Get,
        path: "/api/v1/extensions",
        request_schema: "Empty",
        response_schema: "ExtensionDiscoveryResponse",
    },
];

pub fn client_api_endpoints() -> &'static [ClientApiEndpoint] {
    CLIENT_API_ENDPOINTS
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRegisterRequest {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_device_display_name: Option<String>,
}

impl AccountRegisterRequest {
    pub fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            return Err(Error::Protocol("account username must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum LoginIdentifier {
    UserName(String),
    Did(Did),
    Email(String),
    Phone(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub identifier: LoginIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRefreshRequest {
    pub refresh_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub device_id: DeviceId,
    #[serde(default)]
    pub all_devices: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoamiResponse {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountDataRequest {
    pub data_type: String,
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountDataResponse {
    pub user_id: Did,
    pub data_type: String,
    pub content: Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeactivateAccountRequest {
    pub auth_session: String,
    #[serde(default)]
    pub erase: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractiveAuthStageKind {
    Password,
    EmailOtp,
    PhoneOtp,
    Passkey,
    DidProof,
    DeviceTrust,
    Terms,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractiveAuthStage {
    pub kind: InteractiveAuthStageKind,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractiveAuthFlow {
    pub flow_id: String,
    pub stages: Vec<InteractiveAuthStage>,
}

impl InteractiveAuthFlow {
    pub fn is_satisfied_by(&self, completed: &BTreeSet<InteractiveAuthStageKind>) -> bool {
        self.stages
            .iter()
            .filter(|stage| !stage.optional)
            .all(|stage| completed.contains(&stage.kind))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InteractiveAuthChallenge {
    pub session: String,
    pub flows: Vec<InteractiveAuthFlow>,
    pub completed: BTreeSet<InteractiveAuthStageKind>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, Value>,
}

impl InteractiveAuthChallenge {
    pub fn select_satisfied_flow(&self) -> Option<&InteractiveAuthFlow> {
        self.flows.iter().find(|flow| flow.is_satisfied_by(&self.completed))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InteractiveAuthSubmission {
    pub session: String,
    pub stage: InteractiveAuthStageKind,
    pub credential: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractiveAuthError {
    pub session: String,
    pub stage: InteractiveAuthStageKind,
    pub retryable: bool,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub user_id: Did,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
    pub verified: bool,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateDeviceRequest {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteDevicesRequest {
    pub devices: Vec<DeviceId>,
    pub auth_session: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DehydratedDevice {
    pub device_id: DeviceId,
    pub device_data: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    Sas,
    Qr,
    DidProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerificationFlow {
    pub transaction_id: String,
    pub from_device: DeviceId,
    pub to_device: DeviceId,
    pub method: VerificationMethod,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceState {
    Online,
    Unavailable,
    Offline,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileResponse {
    pub user_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub presence: PresenceState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceSubscriptionRequest {
    pub users: Vec<Did>,
}

impl PresenceSubscriptionRequest {
    pub fn validate(&self) -> Result<()> {
        if self.users.is_empty() {
            Err(Error::Protocol("presence subscription must include users".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceVisibility {
    Private,
    Knockable,
    Public,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceCreateRequest {
    pub name: String,
    pub visibility: SpaceVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub initial_state: BTreeMap<String, Value>,
}

impl SpaceCreateRequest {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::Protocol("space name must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceResponse {
    pub space_id: SpaceId,
    pub name: String,
    pub visibility: SpaceVisibility,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpacePreviewRequest {
    pub space_id: SpaceId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpacePreviewResponse {
    pub space_id: SpaceId,
    pub name: String,
    pub visibility: SpaceVisibility,
    pub member_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipAction {
    Invite,
    Join,
    Leave,
    Knock,
    Kick,
    Ban,
    Unban,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipActionRequest {
    pub space_id: SpaceId,
    pub action: MembershipAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MembershipActionRequest {
    pub fn validate(&self) -> Result<()> {
        if matches!(
            self.action,
            MembershipAction::Invite
                | MembershipAction::Kick
                | MembershipAction::Ban
                | MembershipAction::Unban
        ) && self.target_user.is_none()
        {
            return Err(Error::Protocol("membership action requires target user".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipActionResponse {
    pub event_id: EventId,
    pub membership: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SendEventRequest {
    pub space_id: SpaceId,
    pub event_kind: String,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

impl SendEventRequest {
    pub fn validate(&self) -> Result<()> {
        if self.event_kind.trim().is_empty() {
            return Err(Error::Protocol("event kind must not be empty".to_owned()));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol("event content must be a JSON object".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub space_id: SpaceId,
    pub body: String,
    pub formatted: Option<RichTextDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

impl SendMessageRequest {
    pub fn plain(space_id: SpaceId, body: impl Into<String>) -> Result<Self> {
        let body = body.into();
        if body.trim().is_empty() {
            return Err(Error::Protocol("message body must not be empty".to_owned()));
        }
        Ok(Self { space_id, body, formatted: None, transaction_id: None })
    }

    pub fn markdown(space_id: SpaceId, markdown: impl Into<String>) -> Result<Self> {
        let body = markdown.into();
        let formatted = RichTextDocument::normalize(&body, RichTextFormat::Markdown)?;
        Ok(Self { space_id, body, formatted: Some(formatted), transaction_id: None })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendEventResponse {
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EditMessageRequest {
    pub target_event_id: EventId,
    pub body: String,
    pub formatted: Option<RichTextDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactEventRequest {
    pub target_event_id: EventId,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionRequest {
    pub target_event_id: EventId,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreadReplyRequest {
    pub root_event_id: EventId,
    pub body: String,
    pub formatted: Option<RichTextDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PollStartRequest {
    pub question: String,
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closes_at: Option<DateTime<Utc>>,
}

impl PollStartRequest {
    pub fn validate(&self) -> Result<()> {
        if self.question.trim().is_empty() || self.options.len() < 2 {
            return Err(Error::Protocol(
                "poll requires a question and at least two options".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRequest {
    pub event_id: EventId,
    #[serde(default)]
    pub private: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkerRequest {
    pub fully_read: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_receipt: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateGetRequest {
    pub space_id: SpaceId,
    /// Cell subject derived from the event's typed payload field
    /// (per the spec event-kind-registry's `cell_subject`). Empty string
    /// addresses the singleton cell for the requested kind.
    pub subject: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateSetRequest {
    pub space_id: SpaceId,
    /// Cell subject — see [`StateGetRequest::subject`].
    pub subject: String,
    pub content: Value,
}

impl StateSetRequest {
    pub fn validate(&self) -> Result<()> {
        if self.subject.trim().is_empty() {
            return Err(Error::Protocol(
                "state subject must not be empty (use the typed subject from payload fields)"
                    .to_owned(),
            ));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol("state content must be a JSON object".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateEventResponse {
    pub event_id: EventId,
    /// State slot subject — see [`StateGetRequest::subject`].
    pub subject: String,
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateBatchRequest {
    pub space_id: SpaceId,
    pub expected_state: Option<Hash>,
    pub events: Vec<EventId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MessageSearchRequest {
    pub query: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl MessageSearchRequest {
    pub fn validate(&self) -> Result<()> {
        if self.query.trim().is_empty() {
            Err(Error::Protocol("message search query must not be empty".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MessageSearchHit {
    pub event_id: EventId,
    pub space_id: SpaceId,
    pub sender: Did,
    pub snippet: String,
    pub score: f32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MessageSearchResponse {
    pub hits: Vec<MessageSearchHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_batch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContextRequest {
    pub event_id: EventId,
    pub before_limit: u32,
    pub after_limit: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventContextResponse {
    pub event_id: EventId,
    pub before: Vec<EventId>,
    pub after: Vec<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearestTimestampRequest {
    pub space_id: SpaceId,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectorySearchRequest {
    pub query: String,
    pub visibility: Option<SpaceVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectorySearchResult {
    pub space_id: SpaceId,
    pub name: String,
    pub visibility: SpaceVisibility,
    pub member_count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectorySearchResponse {
    pub results: Vec<DirectorySearchResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_batch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryAliasRequest {
    pub alias: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryAliasResponse {
    pub alias: String,
    pub space_id: SpaceId,
    pub servers: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncServiceState {
    Offline,
    CatchingUp,
    Live,
    Error,
    Terminated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSubscription {
    pub space_id: SpaceId,
    pub timeline_limit: u32,
    pub include_state: bool,
}

impl SyncSubscription {
    pub fn validate(&self) -> Result<()> {
        if self.timeline_limit == 0 {
            return Err(Error::Protocol("sync timeline limit must be non-zero".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSubscribeRequest {
    pub since: Option<String>,
    pub subscriptions: Vec<SyncSubscription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlidingSyncRequest {
    pub window_start: u32,
    pub window_end: u32,
    pub subscriptions: Vec<SyncSubscription>,
}

impl SlidingSyncRequest {
    pub fn validate(&self) -> Result<()> {
        if self.window_end < self.window_start {
            return Err(Error::Protocol("sliding sync window end must be >= start".to_owned()));
        }
        for subscription in &self.subscriptions {
            subscription.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncEnvelope {
    pub next_batch: String,
    pub state: SyncServiceState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub updates: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineGapRepairRequest {
    pub space_id: SpaceId,
    pub from_event: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaUploadRequest {
    pub filename: Option<String>,
    pub content_type: String,
    pub size: u64,
    pub sha256: Hash,
    #[serde(default)]
    pub encrypted: bool,
}

impl MediaUploadRequest {
    pub fn validate(&self) -> Result<()> {
        if self.content_type.trim().is_empty() {
            return Err(Error::Protocol("media content type must not be empty".to_owned()));
        }
        if self.size == 0 {
            return Err(Error::Protocol("media upload size must be non-zero".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaUploadTicket {
    pub upload_id: String,
    pub upload_url: String,
    pub expires_at: DateTime<Utc>,
    pub chunk_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumableUploadPart {
    pub upload_id: String,
    pub offset: u64,
    pub length: u64,
    pub sha256: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaDownloadRequest {
    pub blob_ref: BlobRef,
    #[serde(default)]
    pub authenticated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MediaDownloadResponse {
    pub blob_ref: BlobRef,
    pub content_type: String,
    pub size: u64,
    pub sha256: Hash,
    pub encrypted_payload: Option<EncryptedPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThumbnailRequest {
    pub blob_ref: BlobRef,
    pub width: u32,
    pub height: u32,
    pub method: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaProgress {
    pub transferred: u64,
    pub total: u64,
}

impl MediaProgress {
    pub fn percent(&self) -> u8 {
        if self.total == 0 {
            return 0;
        }
        ((self.transferred.saturating_mul(100) / self.total).min(100)) as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaScannerVerdict {
    Clean,
    Suspicious,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedMediaDescriptor {
    pub media: MediaEncryptionInfo,
    pub payload: EncryptedPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PusherListResponse {
    pub pushers: Vec<Pusher>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetPusherRequest {
    pub pusher: Pusher,
}

impl SetPusherRequest {
    pub fn validate(&self) -> Result<()> {
        if self.pusher.push_gateway.trim().is_empty() {
            return Err(Error::Protocol("pusher gateway must not be empty".to_owned()));
        }
        if self.pusher.push_key.trim().is_empty() {
            return Err(Error::Protocol("pusher key must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletePusherRequest {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushRuleListResponse {
    pub rules: PushRuleSet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRuleUpdateRequest {
    pub rule_id: String,
    pub rule: PushRule,
}

impl PushRuleUpdateRequest {
    pub fn validate(&self) -> Result<()> {
        if self.rule_id.trim().is_empty() {
            return Err(Error::Protocol("push rule id must not be empty".to_owned()));
        }
        if self.rule.rule_id != self.rule_id {
            return Err(Error::Protocol("push rule path id must match request rule id".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRuleDeleteRequest {
    pub rule_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuietHours {
    pub starts_at: String,
    pub ends_at: String,
    pub timezone: String,
}

impl QuietHours {
    pub fn validate(&self) -> Result<()> {
        if self.starts_at.trim().is_empty()
            || self.ends_at.trim().is_empty()
            || self.timezone.trim().is_empty()
        {
            return Err(Error::Protocol(
                "quiet hours must include start, end and timezone".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceNotificationSettings {
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub mention_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<PushPriority>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSettings {
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub mention_only: bool,
    pub default_priority: PushPriority,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quiet_hours: Option<QuietHours>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub per_space: BTreeMap<SpaceId, SpaceNotificationSettings>,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            muted: false,
            mention_only: false,
            default_priority: PushPriority::Normal,
            quiet_hours: None,
            per_space: BTreeMap::new(),
        }
    }
}

impl NotificationSettings {
    pub fn validate(&self) -> Result<()> {
        if let Some(quiet_hours) = &self.quiet_hours {
            quiet_hours.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationCounts {
    pub notification_count: u64,
    pub highlight_count: u64,
    pub unread_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationCountsRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationCountsResponse {
    pub global: NotificationCounts,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<SpaceId, NotificationCounts>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationListRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default)]
    pub only_highlight: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
}

impl NotificationListRequest {
    pub fn validate(&self) -> Result<()> {
        if self.limit == Some(0) {
            Err(Error::Protocol("notification list limit must be non-zero".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientNotification {
    pub notification_id: String,
    pub event_id: EventId,
    pub space_id: SpaceId,
    pub sender: Did,
    pub event_kind: String,
    pub received_at: DateTime<Utc>,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub highlighted: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationListResponse {
    pub notifications: Vec<ClientNotification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_batch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkNotificationsReadRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_to_event_id: Option<EventId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseCategory {
    Spam,
    Harassment,
    IllegalContent,
    Malware,
    PolicyViolation,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRequest {
    pub category: AbuseCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub reason: String,
}

impl ReportRequest {
    pub fn validate(&self) -> Result<()> {
        if self.event_id.is_none() && self.user_id.is_none() && self.space_id.is_none() {
            return Err(Error::Protocol("moderation report needs a target".to_owned()));
        }
        if self.reason.trim().is_empty() {
            return Err(Error::Protocol("moderation report reason must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportResponse {
    pub report_id: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSessionDescription {
    pub sdp_type: String,
    pub sdp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CallSignal {
    Invite { call_id: String, offer: CallSessionDescription },
    Answer { call_id: String, answer: CallSessionDescription },
    Candidates { call_id: String, candidates: Vec<IceCandidate> },
    Hangup { call_id: String, reason: Option<String> },
}

impl CallSignal {
    pub fn call_id(&self) -> &str {
        match self {
            Self::Invite { call_id, .. }
            | Self::Answer { call_id, .. }
            | Self::Candidates { call_id, .. }
            | Self::Hangup { call_id, .. } => call_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.call_id().trim().is_empty() {
            return Err(Error::Protocol("call id must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientApiCoverageReport {
    pub endpoints: usize,
    pub covered_surfaces: BTreeSet<ClientApiSurface>,
    pub missing_surfaces: BTreeSet<ClientApiSurface>,
}

impl ClientApiCoverageReport {
    pub fn validate(&self) -> Result<()> {
        if self.missing_surfaces.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "client API missing surfaces: {:?}",
                self.missing_surfaces
            )))
        }
    }
}

pub fn client_api_coverage_report() -> ClientApiCoverageReport {
    let covered_surfaces =
        CLIENT_API_ENDPOINTS.iter().map(|endpoint| endpoint.surface).collect::<BTreeSet<_>>();
    let required = [
        ClientApiSurface::Account,
        ClientApiSurface::InteractiveAuth,
        ClientApiSurface::Device,
        ClientApiSurface::Profile,
        ClientApiSurface::Space,
        ClientApiSurface::Membership,
        ClientApiSurface::Messaging,
        ClientApiSurface::State,
        ClientApiSurface::Sync,
        ClientApiSurface::Search,
        ClientApiSurface::Directory,
        ClientApiSurface::Media,
        ClientApiSurface::Push,
        ClientApiSurface::Moderation,
        ClientApiSurface::Call,
        ClientApiSurface::Extensions,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let missing_surfaces = required.difference(&covered_surfaces).copied().collect();
    ClientApiCoverageReport {
        endpoints: CLIENT_API_ENDPOINTS.len(),
        covered_surfaces,
        missing_surfaces,
    }
}

pub mod protocol {
    pub use contrix_core::{
        DeviceMessagesReceiveResponse, DeviceMessagesSendRequest, DeviceMessagesSendResponse,
        KeysClaimRequest, KeysClaimResponse, KeysQueryRequest, KeysQueryResponse,
        KeysUploadRequest, KeysUploadResponse, ModerationReportRequest, ModerationReportResponse,
        SyncRequest, SyncResponse,
    };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyInviteRequest {
    pub invite_id: InviteId,
    pub medium: String,
    pub address: String,
    pub space_id: SpaceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineAnchor {
    pub event_id: EventId,
    pub order: Hlc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionDescriptor {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub stable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionDiscoveryResponse {
    pub protocol_version: String,
    pub extensions: Vec<ExtensionDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unstable_features: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn space() -> SpaceId {
        SpaceId::new("cx:space:01904100-0000-7000-8000-a035cff9ef92").unwrap()
    }

    #[test]
    fn endpoint_catalog_covers_required_client_api_surfaces() {
        let report = client_api_coverage_report();
        report.validate().unwrap();
        assert!(CLIENT_API_ENDPOINTS.iter().any(|endpoint| {
            endpoint.operation_id == "cx.auth.interactive.submit"
                && endpoint.surface == ClientApiSurface::InteractiveAuth
        }));
        assert!(CLIENT_API_ENDPOINTS.iter().any(|endpoint| {
            endpoint.operation_id == "cx.notifications.counts"
                && endpoint.surface == ClientApiSurface::Push
        }));
    }

    #[test]
    fn interactive_auth_selects_satisfied_flow() {
        let challenge = InteractiveAuthChallenge {
            session: "sess".to_owned(),
            flows: vec![InteractiveAuthFlow {
                flow_id: "password-passkey".to_owned(),
                stages: vec![
                    InteractiveAuthStage {
                        kind: InteractiveAuthStageKind::Password,
                        optional: false,
                    },
                    InteractiveAuthStage {
                        kind: InteractiveAuthStageKind::Passkey,
                        optional: false,
                    },
                ],
            }],
            completed: BTreeSet::from([
                InteractiveAuthStageKind::Password,
                InteractiveAuthStageKind::Passkey,
            ]),
            params: BTreeMap::new(),
        };
        assert_eq!(challenge.select_satisfied_flow().unwrap().flow_id, "password-passkey");
    }

    #[test]
    fn markdown_message_builds_rich_text_payload() {
        let request =
            SendMessageRequest::markdown(space(), "Hello @alice [docs](https://example.com)")
                .unwrap();
        let formatted = request.formatted.unwrap();
        assert!(formatted.sanitized_html.contains("<a href=\"https://example.com\">docs</a>"));
        assert_eq!(formatted.mentions[0].token, "alice");
    }

    #[test]
    fn sliding_sync_validates_window_and_subscriptions() {
        let request = SlidingSyncRequest {
            window_start: 0,
            window_end: 10,
            subscriptions: vec![SyncSubscription {
                space_id: space(),
                timeline_limit: 50,
                include_state: true,
            }],
        };
        request.validate().unwrap();

        let bad = SlidingSyncRequest { window_start: 10, window_end: 0, subscriptions: Vec::new() };
        assert!(matches!(bad.validate(), Err(Error::Protocol(_))));
    }

    #[test]
    fn media_and_moderation_contracts_validate_fail_closed() {
        let upload = MediaUploadRequest {
            filename: Some("a.txt".to_owned()),
            content_type: "text/plain".to_owned(),
            size: 12,
            sha256: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            encrypted: false,
        };
        upload.validate().unwrap();
        assert_eq!(MediaProgress { transferred: 6, total: 12 }.percent(), 50);

        let report = ReportRequest {
            category: AbuseCategory::Spam,
            event_id: None,
            user_id: Some(did("bad")),
            space_id: None,
            reason: "spam".to_owned(),
        };
        report.validate().unwrap();
    }

    #[test]
    fn push_and_notification_contracts_validate_fail_closed() {
        SetPusherRequest {
            pusher: Pusher {
                user_id: did("alice"),
                device_id: DeviceId::new("dev_phone").unwrap(),
                platform: contrix_api::push::PushPlatform::Fcm,
                push_gateway: "https://push.example".to_owned(),
                push_key: "token".to_owned(),
                app_id: Some("app".to_owned()),
                display_name: Some("phone".to_owned()),
            },
        }
        .validate()
        .unwrap();

        PushRuleUpdateRequest {
            rule_id: "mention".to_owned(),
            rule: PushRule {
                rule_id: "mention".to_owned(),
                enabled: true,
                event_kind: Some("cx.message.text".to_owned()),
                priority: PushPriority::High,
                redact_content: true,
            },
        }
        .validate()
        .unwrap();

        NotificationSettings {
            quiet_hours: Some(QuietHours {
                starts_at: "22:00".to_owned(),
                ends_at: "07:00".to_owned(),
                timezone: "Asia/Shanghai".to_owned(),
            }),
            ..NotificationSettings::default()
        }
        .validate()
        .unwrap();

        assert!(matches!(
            NotificationListRequest {
                since: None,
                limit: Some(0),
                only_highlight: false,
                spaces: Vec::new(),
            }
            .validate(),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn call_signal_requires_call_id() {
        let signal = CallSignal::Hangup { call_id: String::new(), reason: None };
        assert!(matches!(signal.validate(), Err(Error::Protocol(_))));
    }

    #[test]
    fn space_membership_state_and_search_contracts_validate() {
        SpaceCreateRequest {
            name: "Project".to_owned(),
            visibility: SpaceVisibility::Private,
            aliases: vec!["project".to_owned()],
            initial_state: BTreeMap::new(),
        }
        .validate()
        .unwrap();

        MembershipActionRequest {
            space_id: space(),
            action: MembershipAction::Invite,
            target_user: Some(did("bob")),
            reason: Some("join".to_owned()),
        }
        .validate()
        .unwrap();

        StateSetRequest {
            space_id: space(),
            subject: "topic".to_owned(),
            content: serde_json::json!({"topic": "work"}),
        }
        .validate()
        .unwrap();

        MessageSearchRequest { query: "hello".to_owned(), spaces: vec![space()], limit: Some(10) }
            .validate()
            .unwrap();

        PresenceSubscriptionRequest { users: vec![did("alice")] }.validate().unwrap();
    }
}
