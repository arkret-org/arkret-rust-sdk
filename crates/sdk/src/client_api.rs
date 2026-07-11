//! Client-server product API contracts.
//!
//! Owner: the Arkret client SDK. These product-local client API DTOs need
//! `arkret-crypto` / `arkret-html` types (encrypted media metadata, rich text)
//! so they live in the SDK rather than `arkret-core`. Canonical protocol
//! request/response bodies generated from `arkret-spec` stay in `arkret-core`.
//!
//! Naming convention follows the OpenAPI shape of each operation:
//!
//! * `XxxParams`  — URL path parameters (`#[derive(ToParameters)]`).
//! * `XxxArgs`    — query-string parameters (`#[derive(ToParameters)]`).
//! * `XxxRequestBody`  — request body payloads (`#[derive(ToSchema)]`).
//! * `XxxOutcome`  — response body payloads (`#[derive(ToSchema)]`).
//!
//! The previous untyped `ClientApiEndpoint` catalogue (and the
//! `CLIENT_API_ENDPOINTS` constant) has been removed; the HTTP surface is
//! now described declaratively by salvo route handlers and the
//! `ToSchema` / `ToParameters` derives below.

use std::collections::{BTreeMap, BTreeSet};

use arkret_core::push::{PushPriority, PushRule, PushRuleSet, Pusher};
use arkret_core::{
    BlobRef, DeviceId, Did, EncryptedPayload, Error, EventId, Hash, Hlc, InviteId,
    InviteSubjectProof, Notification, RealmId, Result, ThirdPartyInviteOobKind,
};
use arkret_crypto::MediaEncryptionInfo;
use arkret_html::RichTextDocument;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PasswordAccountRegisterRequestBody {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_device_display_name: Option<String>,
}

impl PasswordAccountRegisterRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            return Err(Error::Protocol(
                "account username must not be empty".to_owned(),
            ));
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
pub struct LoginRequestBody {
    pub identifier: LoginIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionCredentialRefreshRequestBody {
    pub renewal_credential: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct LogoutRequestBody {
    pub device_id: DeviceId,
    #[serde(default)]
    pub all_devices: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionOutcome {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub session_credential: String,
    pub renewal_credential: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct WhoamiOutcome {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDataRequestBody {
    pub data_type: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDataOutcome {
    pub user_id: Did,
    pub data_type: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeactivateAccountRequestBody {
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
pub struct InteractiveAuthStrand {
    pub strand_id: String,
    pub stages: Vec<InteractiveAuthStage>,
}

impl InteractiveAuthStrand {
    pub fn is_satisfied_by(&self, completed: &BTreeSet<InteractiveAuthStageKind>) -> bool {
        self.stages
            .iter()
            .filter(|stage| !stage.optional)
            .all(|stage| completed.contains(&stage.kind))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InteractiveAuthChallengeOutcome {
    pub session: String,
    pub strands: Vec<InteractiveAuthStrand>,
    pub completed: BTreeSet<InteractiveAuthStageKind>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, Value>,
}

impl InteractiveAuthChallengeOutcome {
    pub fn select_satisfied_strand(&self) -> Option<&InteractiveAuthStrand> {
        self.strands
            .iter()
            .find(|strand| strand.is_satisfied_by(&self.completed))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InteractiveAuthSubmitRequestBody {
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
pub struct DeviceListOutcome {
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
pub struct UpdateDeviceRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeleteDevicesRequestBody {
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
pub struct DeviceVerificationStrand {
    pub transaction_id: String,
    pub from_device: DeviceId,
    pub to_device: DeviceId,
    pub method: VerificationMethod,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Alias for the canonical closed presence wire set
/// (`discovery/profiles-presence.md` §3.2) — kept so existing
/// `PresenceState` call sites keep compiling while the single enum
/// lives in `arkret_core::sync`.
pub type PresenceState = crate::sync::PresenceStatus;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct ProfileParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub user_id: Did,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ProfileOutcome {
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
pub struct ProfileUpdateRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PresenceSubscriptionRequestBody {
    pub users: Vec<Did>,
}

impl PresenceSubscriptionRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.users.is_empty() {
            Err(Error::Protocol(
                "presence subscription must include users".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmVisibility {
    Private,
    Knockable,
    Public,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmCreateRequestBody {
    pub name: String,
    pub visibility: RealmVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub initial_state: BTreeMap<String, Value>,
}

impl RealmCreateRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::Protocol("realm name must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmOutcome {
    pub realm_id: RealmId,
    pub name: String,
    pub visibility: RealmVisibility,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToParameters))]
pub struct RealmPreviewParams {
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Path)))]
    pub realm_id: RealmId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmPreviewOutcome {
    pub realm_id: RealmId,
    pub name: String,
    pub visibility: RealmVisibility,
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
    pub realm_id: RealmId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MembershipActionRequestBody {
    pub action: MembershipAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MembershipActionRequestBody {
    pub fn validate(&self) -> Result<()> {
        if matches!(
            self.action,
            MembershipAction::Invite
                | MembershipAction::Kick
                | MembershipAction::Ban
                | MembershipAction::Unban
        ) && self.target_user.is_none()
        {
            return Err(Error::Protocol(
                "membership action requires target user".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MembershipActionOutcome {
    pub event_id: EventId,
    pub membership: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SubmitEventRequestBody {
    pub realm_id: RealmId,
    pub event_kind: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

impl SubmitEventRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.event_kind.trim().is_empty() {
            return Err(Error::Protocol("event kind must not be empty".to_owned()));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol(
                "event content must be a JSON object".to_owned(),
            ));
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
pub struct EditMessageRequestBody {
    pub target_event_id: EventId,
    pub body: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Option<serde_json::Value>)))]
    pub formatted: Option<RichTextDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RedactEventRequestBody {
    pub target_event_id: EventId,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReactionRequestBody {
    pub target_event_id: EventId,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThreadReplyRequestBody {
    pub root_event_id: EventId,
    pub body: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = Option<serde_json::Value>)))]
    pub formatted: Option<RichTextDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PollStartRequestBody {
    pub question: String,
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closes_at: Option<DateTime<Utc>>,
}

impl PollStartRequestBody {
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
pub struct ReceiptRequestBody {
    pub event_id: EventId,
    #[serde(default)]
    pub private: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReadMarkerRequestBody {
    pub fully_read: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_receipt: Option<EventId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageSearchRequestBody {
    pub query: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl MessageSearchRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.query.trim().is_empty() {
            Err(Error::Protocol(
                "message search query must not be empty".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageSearchHit {
    pub event_id: EventId,
    pub realm_id: RealmId,
    /// Sender identity. Bare `sender` is a hard-reject renamed wire field
    /// (`renames.json`): sender identity fields must carry the role + id
    /// suffix explicitly.
    pub sender_actor_id: Did,
    pub snippet: String,
    /// Relevance score in basis points (0–10000). Wire floats are
    /// forbidden in v1 (`encoding.md` §2 number profile: ratios MUST be
    /// integer + scale).
    pub score_basis_points: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MessageSearchOutcome {
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
pub struct EventContextOutcome {
    pub event_id: EventId,
    pub before: Vec<EventId>,
    pub after: Vec<EventId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NearestTimestampRequestBody {
    pub realm_id: RealmId,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchRequestBody {
    pub query: String,
    pub visibility: Option<RealmVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchResult {
    pub realm_id: RealmId,
    pub name: String,
    pub visibility: RealmVisibility,
    pub member_count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchOutcome {
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
pub struct DirectoryAliasOutcome {
    pub alias: String,
    pub realm_id: RealmId,
    pub servers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TimelineGapRepairRequestBody {
    pub realm_id: RealmId,
    pub from_event: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaUploadRequestBody {
    pub filename: Option<String>,
    pub content_type: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub content_digest: Hash,
    #[serde(default)]
    pub encrypted: bool,
}

impl MediaUploadRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.content_type.trim().is_empty() {
            return Err(Error::Protocol(
                "media content type must not be empty".to_owned(),
            ));
        }
        if self.size_bytes == 0 {
            return Err(Error::Protocol(
                "media upload size must be non-zero".to_owned(),
            ));
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
pub struct MediaDownloadOutcome {
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
pub struct PusherListOutcome {
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
pub struct SetPusherRequestBody {
    pub pusher: Pusher,
}

impl SetPusherRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.pusher.push_gateway.trim().is_empty() {
            return Err(Error::Protocol(
                "pusher gateway must not be empty".to_owned(),
            ));
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
pub struct DeletePusherRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRuleListOutcome {
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
pub struct PushRuleUpdateRequestBody {
    pub rule: PushRule,
}

impl PushRuleUpdateRequestBody {
    pub fn validate(&self, params: &PushRuleParams) -> Result<()> {
        if params.rule_id.trim().is_empty() {
            return Err(Error::Protocol("push rule id must not be empty".to_owned()));
        }
        if self.rule.rule_id != params.rule_id {
            return Err(Error::Protocol(
                "push rule path id must match request rule id".to_owned(),
            ));
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
pub struct RealmNotificationSettings {
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
    pub per_realm: BTreeMap<RealmId, RealmNotificationSettings>,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            muted: false,
            mention_only: false,
            default_priority: PushPriority::Normal,
            quiet_hours: None,
            per_realm: BTreeMap::new(),
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
pub struct NotificationCountsRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationCountsOutcome {
    pub global: NotificationCounts,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub realms: BTreeMap<RealmId, NotificationCounts>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationListRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default)]
    pub only_highlight: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
}

impl NotificationListRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.limit == Some(0) {
            Err(Error::Protocol(
                "notification list limit must be non-zero".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationListOutcome {
    /// Spec-shaped notification objects (`notification.schema.json`,
    /// mirrored by `arkret_core::Notification`). The former parallel
    /// `ClientNotification` shape (notification_id / sender / read /
    /// highlighted / content) drifted from the closed authoritative
    /// schema and has been removed.
    pub notifications: Vec<Notification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MarkNotificationsReadRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
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
pub struct ReportRequestBody {
    pub category: AbuseCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub reason: String,
}

impl ReportRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.event_id.is_none() && self.user_id.is_none() && self.realm_id.is_none() {
            return Err(Error::Protocol(
                "moderation report needs a target".to_owned(),
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(Error::Protocol(
                "moderation report reason must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ReportOutcome {
    pub report_id: String,
    pub accepted: bool,
}

/// SDP description type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SdpType {
    Offer,
    Answer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallSessionDescription {
    pub sdp_type: SdpType,
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
pub enum CallSignalRequestBody {
    Invite {
        call_id: String,
        offer: CallSessionDescription,
    },
    Answer {
        call_id: String,
        answer: CallSessionDescription,
    },
    Candidates {
        call_id: String,
        candidates: Vec<IceCandidate>,
    },
    Hangup {
        call_id: String,
        reason: Option<String>,
    },
}

impl CallSignalRequestBody {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteMedium {
    Email,
    Phone,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteRequestBody {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    pub medium: ThirdPartyInviteMedium,
    pub oob_code_kind: ThirdPartyInviteOobKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_entropy_bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_claims: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_rule_snapshot: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteTokenTransport {
    UrlFragment,
    OobCode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThirdPartyInviteTokenHandoff {
    pub transport: ThirdPartyInviteTokenTransport,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThirdPartyInviteIssueOutcome {
    pub invite_id: InviteId,
    pub realm_id: RealmId,
    pub state: String,
    pub event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub token_handoff: ThirdPartyInviteTokenHandoff,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyInviteClaimRequestBody {
    pub invite_token: String,
    pub claim_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<Did>,
    pub binding_proof: Value,
    pub subject_proof: InviteSubjectProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThirdPartyInviteClaimOutcome {
    pub invite_id: InviteId,
    pub realm_id: RealmId,
    pub state: String,
    pub invitee: Did,
    pub claim_event_id: EventId,
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
pub struct ExtensionDiscoveryOutcome {
    pub protocol_version: String,
    pub extensions: Vec<ExtensionDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unstable_features: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-a035cff9ef92").unwrap()
    }

    #[test]
    fn interactive_auth_selects_satisfied_strand() {
        let challenge = InteractiveAuthChallengeOutcome {
            session: "sess".to_owned(),
            strands: vec![InteractiveAuthStrand {
                strand_id: "password-passkey".to_owned(),
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
        assert_eq!(
            challenge.select_satisfied_strand().unwrap().strand_id,
            "password-passkey"
        );
    }

    #[test]
    fn media_and_moderation_contracts_validate_fail_closed() {
        let upload = MediaUploadRequestBody {
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
        assert_eq!(
            MediaProgress {
                transferred: 6,
                total: 12
            }
            .percent(),
            50
        );

        let report = ReportRequestBody {
            category: AbuseCategory::Spam,
            event_id: None,
            user_id: Some(did("bad")),
            realm_id: None,
            reason: "spam".to_owned(),
        };
        report.validate().unwrap();
    }

    #[test]
    fn push_and_notification_contracts_validate_fail_closed() {
        SetPusherRequestBody {
            pusher: Pusher {
                user_id: did("alice"),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
                platform: arkret_core::push::PushPlatform::Fcm,
                push_gateway: "https://push.example".to_owned(),
                push_key: "token".to_owned(),
                app_id: Some("app".to_owned()),
                display_name: Some("phone".to_owned()),
            },
        }
        .validate()
        .unwrap();

        let push_params = PushRuleParams {
            rule_id: "mention".to_owned(),
        };
        PushRuleUpdateRequestBody {
            rule: PushRule {
                rule_id: "mention".to_owned(),
                enabled: true,
                event_kind: Some("ak.message.create".to_owned()),
                priority: PushPriority::High,
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
            NotificationListRequestBody {
                cursor: None,
                limit: Some(0),
                only_highlight: false,
                realms: Vec::new(),
            }
            .validate(),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn call_signal_requires_call_id() {
        let signal = CallSignalRequestBody::Hangup {
            call_id: String::new(),
            reason: None,
        };
        assert!(matches!(signal.validate(), Err(Error::Protocol(_))));
    }

    #[test]
    fn space_membership_and_search_contracts_validate() {
        RealmCreateRequestBody {
            name: "Project".to_owned(),
            visibility: RealmVisibility::Private,
            aliases: vec!["project".to_owned()],
            initial_state: BTreeMap::new(),
        }
        .validate()
        .unwrap();

        MembershipActionRequestBody {
            action: MembershipAction::Invite,
            target_user: Some(did("bob")),
            reason: Some("join".to_owned()),
        }
        .validate()
        .unwrap();

        MessageSearchRequestBody {
            query: "hello".to_owned(),
            realms: vec![realm()],
            limit: Some(10),
        }
        .validate()
        .unwrap();

        PresenceSubscriptionRequestBody {
            users: vec![did("alice")],
        }
        .validate()
        .unwrap();
    }
}
