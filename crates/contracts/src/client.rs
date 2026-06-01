//! Client-server protocol API contracts.
//!
//! Naming convention follows the OpenAPI shape of each operation:
//!
//! * `XxxParams`  — URL path parameters (`#[derive(ToParameters)]`).
//! * `XxxArgs`    — query-string parameters (`#[derive(ToParameters)]`).
//! * `XxxReqBody`  — request body payloads (`#[derive(ToSchema)]`).
//! * `XxxResBody`  — response body payloads (`#[derive(ToSchema)]`).
//!
//! The previous untyped `ClientApiEndpoint` catalogue (and the
//! `CLIENT_API_ENDPOINTS` constant) has been removed; the HTTP surface is
//! now described declaratively by salvo route handlers and the
//! `ToSchema` / `ToParameters` derives below.

use std::collections::{BTreeMap, BTreeSet};

use crate::push::{PushPriority, PushRule, PushRuleSet, Pusher};
use chrono::{DateTime, Utc};
use contrix_core::{
    BlobRef, DeviceId, Did, EncryptedPayload, Error, EventId, Hash, Hlc, InviteId, Result, SpaceId,
};
use contrix_crypto::MediaEncryptionInfo;
use contrix_html::RichTextDocument;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountRegisterReqBody {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_device_display_name: Option<String>,
}

impl AccountRegisterReqBody {
    pub fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            return Err(Error::Protocol("account username must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum LoginIdentifier {
    UserName(String),
    Did(Did),
    Email(String),
    Phone(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct LoginReqBody {
    pub identifier: LoginIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TokenRefreshReqBody {
    pub refresh_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct LogoutReqBody {
    pub device_id: DeviceId,
    #[serde(default)]
    pub all_devices: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionResBody {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct WhoamiResBody {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDataReqBody {
    pub data_type: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDataResBody {
    pub user_id: Did,
    pub data_type: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeactivateAccountReqBody {
    pub auth_session: String,
    #[serde(default)]
    pub erase: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InteractiveAuthStage {
    pub kind: InteractiveAuthStageKind,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InteractiveAuthChallengeResBody {
    pub session: String,
    pub flows: Vec<InteractiveAuthFlow>,
    pub completed: BTreeSet<InteractiveAuthStageKind>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, Value>,
}

impl InteractiveAuthChallengeResBody {
    pub fn select_satisfied_flow(&self) -> Option<&InteractiveAuthFlow> {
        self.flows.iter().find(|flow| flow.is_satisfied_by(&self.completed))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InteractiveAuthSubmitReqBody {
    pub session: String,
    pub stage: InteractiveAuthStageKind,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub credential: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InteractiveAuthError {
    pub session: String,
    pub stage: InteractiveAuthStageKind,
    pub retryable: bool,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceListResBody {
    pub devices: Vec<DeviceInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct UpdateDeviceParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct UpdateDeviceReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeleteDevicesReqBody {
    pub devices: Vec<DeviceId>,
    pub auth_session: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DehydratedDevice {
    pub device_id: DeviceId,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub device_data: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    Sas,
    Qr,
    DidProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PresenceState {
    Online,
    Unavailable,
    Offline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct ProfileParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub user_id: Did,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProfileResBody {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProfileUpdateReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PresenceSubscriptionReqBody {
    pub users: Vec<Did>,
}

impl PresenceSubscriptionReqBody {
    pub fn validate(&self) -> Result<()> {
        if self.users.is_empty() {
            Err(Error::Protocol("presence subscription must include users".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SpaceVisibility {
    Private,
    Knockable,
    Public,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceCreateReqBody {
    pub name: String,
    pub visibility: SpaceVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub initial_state: BTreeMap<String, Value>,
}

impl SpaceCreateReqBody {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::Protocol("space name must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceResBody {
    pub space_id: SpaceId,
    pub name: String,
    pub visibility: SpaceVisibility,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct SpacePreviewParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub space_id: SpaceId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpacePreviewResBody {
    pub space_id: SpaceId,
    pub name: String,
    pub visibility: SpaceVisibility,
    pub member_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct MembershipActionParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub space_id: SpaceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MembershipActionReqBody {
    pub action: MembershipAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MembershipActionReqBody {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MembershipActionResBody {
    pub event_id: EventId,
    pub membership: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SubmitEventReqBody {
    pub space_id: SpaceId,
    pub event_kind: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

impl SubmitEventReqBody {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventSubmitReceipt {
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EditMessageReqBody {
    pub target_event_id: EventId,
    pub body: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Option<serde_json::Value>)))]
    pub formatted: Option<RichTextDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RedactEventReqBody {
    pub target_event_id: EventId,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReactionReqBody {
    pub target_event_id: EventId,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThreadReplyReqBody {
    pub root_event_id: EventId,
    pub body: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Option<serde_json::Value>)))]
    pub formatted: Option<RichTextDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PollStartReqBody {
    pub question: String,
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closes_at: Option<DateTime<Utc>>,
}

impl PollStartReqBody {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReceiptReqBody {
    pub event_id: EventId,
    #[serde(default)]
    pub private: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReadMarkerReqBody {
    pub fully_read: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_receipt: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageSearchReqBody {
    pub query: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl MessageSearchReqBody {
    pub fn validate(&self) -> Result<()> {
        if self.query.trim().is_empty() {
            Err(Error::Protocol("message search query must not be empty".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageSearchHit {
    pub event_id: EventId,
    pub space_id: SpaceId,
    pub sender: Did,
    pub snippet: String,
    pub score: f32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageSearchResBody {
    pub hits: Vec<MessageSearchHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct EventContextParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct EventContextArgs {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub before_limit: u32,
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub after_limit: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventContextResBody {
    pub event_id: EventId,
    pub before: Vec<EventId>,
    pub after: Vec<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NearestTimestampReqBody {
    pub space_id: SpaceId,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchReqBody {
    pub query: String,
    pub visibility: Option<SpaceVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchResult {
    pub space_id: SpaceId,
    pub name: String,
    pub visibility: SpaceVisibility,
    pub member_count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchResBody {
    pub results: Vec<DirectorySearchResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct DirectoryAliasParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub alias: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryAliasResBody {
    pub alias: String,
    pub space_id: SpaceId,
    pub servers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TimelineGapRepairReqBody {
    pub space_id: SpaceId,
    pub from_event: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaUploadReqBody {
    pub filename: Option<String>,
    pub content_type: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub content_digest: Hash,
    #[serde(default)]
    pub encrypted: bool,
}

impl MediaUploadReqBody {
    pub fn validate(&self) -> Result<()> {
        if self.content_type.trim().is_empty() {
            return Err(Error::Protocol("media content type must not be empty".to_owned()));
        }
        if self.size_bytes == 0 {
            return Err(Error::Protocol("media upload size must be non-zero".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaUploadTicket {
    pub upload_id: String,
    pub upload_url: String,
    pub expires_at: DateTime<Utc>,
    pub chunk_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ResumableUploadPart {
    pub upload_id: String,
    pub offset: u64,
    pub length: u64,
    pub content_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct MediaDownloadParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub blob_ref: BlobRef,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct MediaDownloadArgs {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    #[serde(default)]
    pub authenticated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaDownloadResBody {
    pub blob_ref: BlobRef,
    pub content_type: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub content_digest: Hash,
    pub encrypted_content: Option<EncryptedPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct ThumbnailParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub blob_ref: BlobRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct ThumbnailArgs {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub width: u32,
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub height: u32,
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub method: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MediaScannerVerdict {
    Clean,
    Suspicious,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EncryptedMediaDescriptor {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub media: MediaEncryptionInfo,
    pub payload: EncryptedPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PusherListResBody {
    pub pushers: Vec<Pusher>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct SetPusherParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SetPusherReqBody {
    pub pusher: Pusher,
}

impl SetPusherReqBody {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct DeletePusherParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeletePusherReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRuleListResBody {
    pub rules: PushRuleSet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct PushRuleParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub rule_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRuleUpdateReqBody {
    pub rule: PushRule,
}

impl PushRuleUpdateReqBody {
    pub fn validate(&self, params: &PushRuleParams) -> Result<()> {
        if params.rule_id.trim().is_empty() {
            return Err(Error::Protocol("push rule id must not be empty".to_owned()));
        }
        if self.rule.rule_id != params.rule_id {
            return Err(Error::Protocol("push rule path id must match request rule id".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceNotificationSettings {
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub mention_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<PushPriority>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationCounts {
    pub notification_count: u64,
    pub highlight_count: u64,
    pub unread_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationCountsReqBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationCountsResBody {
    pub global: NotificationCounts,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<SpaceId, NotificationCounts>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationListReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default)]
    pub only_highlight: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<SpaceId>,
}

impl NotificationListReqBody {
    pub fn validate(&self) -> Result<()> {
        if self.limit == Some(0) {
            Err(Error::Protocol("notification list limit must be non-zero".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationListResBody {
    pub notifications: Vec<ClientNotification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MarkNotificationsReadReqBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_to_event_id: Option<EventId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReportReqBody {
    pub category: AbuseCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub reason: String,
}

impl ReportReqBody {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReportResBody {
    pub report_id: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallSessionDescription {
    pub sdp_type: String,
    pub sdp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct CallSignalParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub call_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CallSignalReqBody {
    Invite { call_id: String, offer: CallSessionDescription },
    Answer { call_id: String, answer: CallSessionDescription },
    Candidates { call_id: String, candidates: Vec<IceCandidate> },
    Hangup { call_id: String, reason: Option<String> },
}

impl CallSignalReqBody {
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

pub mod protocol {
    pub use contrix_core::{
        DeviceMessagesReceiveResBody, DeviceMessagesSendReqBody, DeviceMessagesSendResBody,
        KeysClaimReqBody, KeysClaimResBody, KeysQueryReqBody, KeysQueryResBody, KeysUploadReqBody,
        KeysUploadResBody, ModerationReportReqBody, ModerationReportResBody, SyncReqBody,
        SyncResBody,
    };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThirdPartyInviteReqBody {
    pub invite_id: InviteId,
    pub medium: String,
    pub address: String,
    pub space_id: SpaceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TimelineAnchor {
    pub event_id: EventId,
    pub order: Hlc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ExtensionDescriptor {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub stable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ExtensionDiscoveryResBody {
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
    fn interactive_auth_selects_satisfied_flow() {
        let challenge = InteractiveAuthChallengeResBody {
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
    fn media_and_moderation_contracts_validate_fail_closed() {
        let upload = MediaUploadReqBody {
            filename: Some("a.txt".to_owned()),
            content_type: "text/plain".to_owned(),
            size_bytes: 12,
            content_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            encrypted: false,
        };
        upload.validate().unwrap();
        assert_eq!(MediaProgress { transferred: 6, total: 12 }.percent(), 50);

        let report = ReportReqBody {
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
        SetPusherReqBody {
            pusher: Pusher {
                user_id: did("alice"),
                device_id: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap(),
                platform: crate::push::PushPlatform::Fcm,
                push_gateway: "https://push.example".to_owned(),
                push_key: "token".to_owned(),
                app_id: Some("app".to_owned()),
                display_name: Some("phone".to_owned()),
            },
        }
        .validate()
        .unwrap();

        let push_params = PushRuleParams { rule_id: "mention".to_owned() };
        PushRuleUpdateReqBody {
            rule: PushRule {
                rule_id: "mention".to_owned(),
                enabled: true,
                event_kind: Some("cx.message.create".to_owned()),
                priority: PushPriority::High,
                redact_content: true,
            },
        }
        .validate(&push_params)
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
            NotificationListReqBody {
                cursor: None,
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
        let signal = CallSignalReqBody::Hangup { call_id: String::new(), reason: None };
        assert!(matches!(signal.validate(), Err(Error::Protocol(_))));
    }

    #[test]
    fn space_membership_and_search_contracts_validate() {
        SpaceCreateReqBody {
            name: "Project".to_owned(),
            visibility: SpaceVisibility::Private,
            aliases: vec!["project".to_owned()],
            initial_state: BTreeMap::new(),
        }
        .validate()
        .unwrap();

        MembershipActionReqBody {
            action: MembershipAction::Invite,
            target_user: Some(did("bob")),
            reason: Some("join".to_owned()),
        }
        .validate()
        .unwrap();

        MessageSearchReqBody { query: "hello".to_owned(), spaces: vec![space()], limit: Some(10) }
            .validate()
            .unwrap();

        PresenceSubscriptionReqBody { users: vec![did("alice")] }.validate().unwrap();
    }
}
