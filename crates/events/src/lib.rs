//! Contrix-native event taxonomy and typed content models.
//!
//! `contrix-core` owns the signed raw [`Event`] envelope. This crate owns the
//! reusable event-content vocabulary that client runtimes, appservices, bots,
//! UI projections and conformance tests can share without depending on the
//! umbrella SDK.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_core::{
    BlobRef, DeviceId, Did, EntityId, Error, Event, EventId, Hlc, PresenceStatus, Result, SpaceId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use contrix_core::Event as RawEvent;

pub const MESSAGE_TEXT: &str = "cx.message.text";
pub const MESSAGE_NOTICE: &str = "cx.message.notice";
pub const MESSAGE_EMOTE: &str = "cx.message.emote";
pub const MESSAGE_HTML: &str = "cx.message.html";
pub const MESSAGE_FILE: &str = "cx.message.file";
pub const MESSAGE_IMAGE: &str = "cx.message.image";
pub const MESSAGE_AUDIO: &str = "cx.message.audio";
pub const MESSAGE_VIDEO: &str = "cx.message.video";
pub const MESSAGE_VOICE: &str = "cx.message.voice";
pub const MESSAGE_DOCUMENT: &str = "cx.message.document";
pub const MESSAGE_LOCATION: &str = "cx.message.location";
pub const MESSAGE_STICKER: &str = "cx.message.sticker";
pub const MESSAGE_REACTION: &str = "cx.message.reaction";
pub const MESSAGE_POLL: &str = "cx.message.poll";
pub const MESSAGE_EDIT: &str = "cx.message.edit";
pub const MESSAGE_REDACTION: &str = "cx.message.redaction";

pub const STATE_MEMBERSHIP: &str = "cx.state.membership";
pub const STATE_PROFILE: &str = "cx.state.profile";
pub const STATE_POWER_LEVELS: &str = "cx.state.power_levels";
pub const STATE_POLICY: &str = "cx.state.policy";
pub const STATE_TAGS: &str = "cx.state.tags";
pub const STATE_PINNED_EVENTS: &str = "cx.state.pinned_events";
pub const STATE_TOPIC: &str = "cx.state.topic";
pub const STATE_NAME: &str = "cx.state.name";
pub const STATE_AVATAR: &str = "cx.state.avatar";
pub const STATE_NOTIFICATION_SETTINGS: &str = "cx.state.notification_settings";

pub const EPHEMERAL_TYPING: &str = "cx.ephemeral.typing";
pub const EPHEMERAL_RECEIPT: &str = "cx.ephemeral.receipt";
pub const EPHEMERAL_READ_MARKER: &str = "cx.ephemeral.read_marker";
pub const EPHEMERAL_PRESENCE: &str = "cx.ephemeral.presence";
pub const EPHEMERAL_TRANSIENT_DEVICE: &str = "cx.ephemeral.transient_device";

pub const ACCOUNT_DATA_DIRECT_SPACES: &str = "cx.account_data.direct_spaces";
pub const ACCOUNT_DATA_IGNORED_USERS: &str = "cx.account_data.ignored_users";
pub const ACCOUNT_DATA_RECENT_EMOJI: &str = "cx.account_data.recent_emoji";
pub const ACCOUNT_DATA_DRAFT: &str = "cx.account_data.draft";
pub const ACCOUNT_DATA_SPACE_SETTINGS: &str = "cx.account_data.space_settings";

pub const E2EE_ENCRYPTED: &str = "cx.e2ee.encrypted";
pub const E2EE_ROOM_KEY: &str = "cx.e2ee.room_key";
pub const E2EE_FORWARDED_ROOM_KEY: &str = "cx.e2ee.forwarded_room_key";
pub const E2EE_KEY_REQUEST: &str = "cx.e2ee.key_request";
pub const E2EE_SECRET_REQUEST: &str = "cx.e2ee.secret_request";
pub const E2EE_VERIFICATION: &str = "cx.e2ee.verification";

pub const CALL_INVITE: &str = "cx.call.invite";
pub const CALL_ANSWER: &str = "cx.call.answer";
pub const CALL_CANDIDATES: &str = "cx.call.candidates";
pub const CALL_HANGUP: &str = "cx.call.hangup";
pub const RTC_SESSION: &str = "cx.rtc.session";

pub const COLLAB_OPERATION_BATCH: &str = "cx.collab.operation_batch";
pub const COLLAB_DOCUMENT_PATCH: &str = "cx.collab.document_patch";
pub const COLLAB_CURSOR: &str = "cx.collab.cursor";
pub const COLLAB_SELECTION: &str = "cx.collab.selection";

/// Broad class for routing, indexing and UI projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    Message,
    State,
    Ephemeral,
    AccountData,
    E2ee,
    Call,
    Rtc,
    Collaboration,
    Custom(String),
}

/// Classify a protocol event kind without deserializing its content.
pub fn classify_event_kind(kind: &str) -> EventClass {
    match kind {
        MESSAGE_TEXT | MESSAGE_NOTICE | MESSAGE_EMOTE | MESSAGE_HTML | MESSAGE_FILE
        | MESSAGE_IMAGE | MESSAGE_AUDIO | MESSAGE_VIDEO | MESSAGE_VOICE | MESSAGE_DOCUMENT
        | MESSAGE_LOCATION | MESSAGE_STICKER | MESSAGE_REACTION | MESSAGE_POLL | MESSAGE_EDIT
        | MESSAGE_REDACTION => EventClass::Message,
        STATE_MEMBERSHIP
        | STATE_PROFILE
        | STATE_POWER_LEVELS
        | STATE_POLICY
        | STATE_TAGS
        | STATE_PINNED_EVENTS
        | STATE_TOPIC
        | STATE_NAME
        | STATE_AVATAR
        | STATE_NOTIFICATION_SETTINGS => EventClass::State,
        EPHEMERAL_TYPING
        | EPHEMERAL_RECEIPT
        | EPHEMERAL_READ_MARKER
        | EPHEMERAL_PRESENCE
        | EPHEMERAL_TRANSIENT_DEVICE => EventClass::Ephemeral,
        ACCOUNT_DATA_DIRECT_SPACES
        | ACCOUNT_DATA_IGNORED_USERS
        | ACCOUNT_DATA_RECENT_EMOJI
        | ACCOUNT_DATA_DRAFT
        | ACCOUNT_DATA_SPACE_SETTINGS => EventClass::AccountData,
        E2EE_ENCRYPTED
        | E2EE_ROOM_KEY
        | E2EE_FORWARDED_ROOM_KEY
        | E2EE_KEY_REQUEST
        | E2EE_SECRET_REQUEST
        | E2EE_VERIFICATION => EventClass::E2ee,
        CALL_INVITE | CALL_ANSWER | CALL_CANDIDATES | CALL_HANGUP => EventClass::Call,
        RTC_SESSION => EventClass::Rtc,
        COLLAB_OPERATION_BATCH | COLLAB_DOCUMENT_PATCH | COLLAB_CURSOR | COLLAB_SELECTION => {
            EventClass::Collaboration
        }
        _ => {
            if kind.starts_with("cx.message.") {
                EventClass::Message
            } else if kind.starts_with("cx.state.") {
                EventClass::State
            } else if kind.starts_with("cx.ephemeral.") {
                EventClass::Ephemeral
            } else if kind.starts_with("cx.account_data.") {
                EventClass::AccountData
            } else if kind.starts_with("cx.e2ee.") {
                EventClass::E2ee
            } else if kind.starts_with("cx.call.") {
                EventClass::Call
            } else if kind.starts_with("cx.rtc.") {
                EventClass::Rtc
            } else if kind.starts_with("cx.collab.") {
                EventClass::Collaboration
            } else {
                EventClass::Custom(kind.to_owned())
            }
        }
    }
}

/// A typed view of a raw event envelope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventContentEnvelope {
    pub event_id: EventId,
    pub kind: String,
    pub class: EventClass,
    pub space_id: SpaceId,
    pub actor_id: Did,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prev_refs: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_refs: Vec<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    pub content: AnyEventContent,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
}

impl EventContentEnvelope {
    pub fn from_event(event: &Event) -> Result<Self> {
        Ok(Self {
            event_id: event.event_id.clone(),
            kind: event.kind.clone(),
            class: classify_event_kind(&event.kind),
            space_id: event.space_id.clone(),
            actor_id: event.actor_id.clone(),
            created_at: event.created_at,
            hlc: event.hlc.clone(),
            prev_refs: event.prev_refs.clone(),
            auth_refs: event.auth_refs.clone(),
            redacts: event.redacts.clone(),
            content: parse_event_content(&event.kind, event.content.clone())?,
            unsigned: event.unsigned.clone(),
        })
    }
}

/// A typed event content value or a lossless custom/unknown value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "variant", rename_all = "snake_case")]
pub enum AnyEventContent {
    Known { content: KnownEventContent },
    Custom { content: CustomEventContent },
}

impl AnyEventContent {
    pub fn into_json(self) -> Result<Value> {
        match self {
            Self::Known { content } => serde_json::to_value(content).map_err(Into::into),
            Self::Custom { content } => Ok(content.raw),
        }
    }

    pub fn as_custom_raw(&self) -> Option<&Value> {
        match self {
            Self::Known { .. } => None,
            Self::Custom { content } => Some(&content.raw),
        }
    }
}

/// Strongly typed built-in event content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "content", rename_all = "snake_case")]
pub enum KnownEventContent {
    TextMessage(TextMessageContent),
    NoticeMessage(TextMessageContent),
    EmoteMessage(TextMessageContent),
    HtmlMessage(HtmlMessageContent),
    FileMessage(MediaContent),
    ImageMessage(MediaContent),
    AudioMessage(MediaContent),
    VideoMessage(MediaContent),
    VoiceMessage(MediaContent),
    DocumentMessage(MediaContent),
    LocationMessage(LocationContent),
    StickerMessage(StickerContent),
    Reaction(ReactionContent),
    Poll(PollContent),
    Edit(EditContent),
    Redaction(RedactionContent),
    Membership(MembershipContent),
    Profile(ProfileContent),
    PowerLevels(PowerLevelsContent),
    Policy(PolicyContent),
    Tags(TagsContent),
    PinnedEvents(PinnedEventsContent),
    Topic(TopicContent),
    Name(NameContent),
    Avatar(AvatarContent),
    NotificationSettings(NotificationSettingsContent),
    Typing(TypingContent),
    Receipt(ReceiptContent),
    ReadMarker(ReadMarkerContent),
    Presence(PresenceContent),
    TransientDevice(TransientDeviceContent),
    DirectSpaces(DirectSpacesContent),
    IgnoredUsers(IgnoredUsersContent),
    RecentEmoji(RecentEmojiContent),
    Draft(DraftContent),
    SpaceSettings(SpaceSettingsContent),
    Encrypted(EncryptedContent),
    RoomKey(RoomKeyContent),
    ForwardedRoomKey(ForwardedRoomKeyContent),
    KeyRequest(KeyRequestContent),
    SecretRequest(SecretRequestContent),
    Verification(VerificationContent),
    CallInvite(CallContent),
    CallAnswer(CallContent),
    CallCandidates(CallCandidatesContent),
    CallHangup(CallHangupContent),
    RtcSession(RtcSessionContent),
    OperationBatch(OperationBatchContent),
    DocumentPatch(DocumentPatchContent),
    Cursor(CursorContent),
    Selection(SelectionContent),
}

/// Lossless content for unknown or extension event kinds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomEventContent {
    pub kind: String,
    pub class: EventClass,
    pub raw: Value,
}

pub fn parse_event_content(kind: &str, content: Value) -> Result<AnyEventContent> {
    let known = match kind {
        MESSAGE_TEXT => KnownEventContent::TextMessage(parse(content)?),
        MESSAGE_NOTICE => KnownEventContent::NoticeMessage(parse(content)?),
        MESSAGE_EMOTE => KnownEventContent::EmoteMessage(parse(content)?),
        MESSAGE_HTML => KnownEventContent::HtmlMessage(parse(content)?),
        MESSAGE_FILE => KnownEventContent::FileMessage(parse(content)?),
        MESSAGE_IMAGE => KnownEventContent::ImageMessage(parse(content)?),
        MESSAGE_AUDIO => KnownEventContent::AudioMessage(parse(content)?),
        MESSAGE_VIDEO => KnownEventContent::VideoMessage(parse(content)?),
        MESSAGE_VOICE => KnownEventContent::VoiceMessage(parse(content)?),
        MESSAGE_DOCUMENT => KnownEventContent::DocumentMessage(parse(content)?),
        MESSAGE_LOCATION => KnownEventContent::LocationMessage(parse(content)?),
        MESSAGE_STICKER => KnownEventContent::StickerMessage(parse(content)?),
        MESSAGE_REACTION => KnownEventContent::Reaction(parse(content)?),
        MESSAGE_POLL => KnownEventContent::Poll(parse(content)?),
        MESSAGE_EDIT => KnownEventContent::Edit(parse(content)?),
        MESSAGE_REDACTION => KnownEventContent::Redaction(parse(content)?),
        STATE_MEMBERSHIP => KnownEventContent::Membership(parse(content)?),
        STATE_PROFILE => KnownEventContent::Profile(parse(content)?),
        STATE_POWER_LEVELS => KnownEventContent::PowerLevels(parse(content)?),
        STATE_POLICY => KnownEventContent::Policy(parse(content)?),
        STATE_TAGS => KnownEventContent::Tags(parse(content)?),
        STATE_PINNED_EVENTS => KnownEventContent::PinnedEvents(parse(content)?),
        STATE_TOPIC => KnownEventContent::Topic(parse(content)?),
        STATE_NAME => KnownEventContent::Name(parse(content)?),
        STATE_AVATAR => KnownEventContent::Avatar(parse(content)?),
        STATE_NOTIFICATION_SETTINGS => KnownEventContent::NotificationSettings(parse(content)?),
        EPHEMERAL_TYPING => KnownEventContent::Typing(parse(content)?),
        EPHEMERAL_RECEIPT => KnownEventContent::Receipt(parse(content)?),
        EPHEMERAL_READ_MARKER => KnownEventContent::ReadMarker(parse(content)?),
        EPHEMERAL_PRESENCE => KnownEventContent::Presence(parse(content)?),
        EPHEMERAL_TRANSIENT_DEVICE => KnownEventContent::TransientDevice(parse(content)?),
        ACCOUNT_DATA_DIRECT_SPACES => KnownEventContent::DirectSpaces(parse(content)?),
        ACCOUNT_DATA_IGNORED_USERS => KnownEventContent::IgnoredUsers(parse(content)?),
        ACCOUNT_DATA_RECENT_EMOJI => KnownEventContent::RecentEmoji(parse(content)?),
        ACCOUNT_DATA_DRAFT => KnownEventContent::Draft(parse(content)?),
        ACCOUNT_DATA_SPACE_SETTINGS => KnownEventContent::SpaceSettings(parse(content)?),
        E2EE_ENCRYPTED => KnownEventContent::Encrypted(parse(content)?),
        E2EE_ROOM_KEY => KnownEventContent::RoomKey(parse(content)?),
        E2EE_FORWARDED_ROOM_KEY => KnownEventContent::ForwardedRoomKey(parse(content)?),
        E2EE_KEY_REQUEST => KnownEventContent::KeyRequest(parse(content)?),
        E2EE_SECRET_REQUEST => KnownEventContent::SecretRequest(parse(content)?),
        E2EE_VERIFICATION => KnownEventContent::Verification(parse(content)?),
        CALL_INVITE => KnownEventContent::CallInvite(parse(content)?),
        CALL_ANSWER => KnownEventContent::CallAnswer(parse(content)?),
        CALL_CANDIDATES => KnownEventContent::CallCandidates(parse(content)?),
        CALL_HANGUP => KnownEventContent::CallHangup(parse(content)?),
        RTC_SESSION => KnownEventContent::RtcSession(parse(content)?),
        COLLAB_OPERATION_BATCH => KnownEventContent::OperationBatch(parse(content)?),
        COLLAB_DOCUMENT_PATCH => KnownEventContent::DocumentPatch(parse(content)?),
        COLLAB_CURSOR => KnownEventContent::Cursor(parse(content)?),
        COLLAB_SELECTION => KnownEventContent::Selection(parse(content)?),
        _ => {
            return Ok(AnyEventContent::Custom {
                content: CustomEventContent {
                    kind: kind.to_owned(),
                    class: classify_event_kind(kind),
                    raw: content,
                },
            });
        }
    };
    Ok(AnyEventContent::Known { content: known })
}

fn parse<T>(value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(Into::into)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextMessageContent {
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<FormattedBody>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<MentionRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relates_to: Option<RelationRef>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtmlMessageContent {
    pub body: String,
    pub html: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<MentionRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relates_to: Option<RelationRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormattedBody {
    pub format: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionRef {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationRef {
    pub kind: String,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MediaContent {
    pub body: String,
    pub blob: BlobRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimetype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub info: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relates_to: Option<RelationRef>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LocationContent {
    pub body: String,
    pub geo_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub info: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StickerContent {
    pub body: String,
    pub blob: BlobRef,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub info: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionContent {
    pub target_event_id: EventId,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollContent {
    pub question: String,
    pub answers: Vec<PollAnswer>,
    #[serde(default)]
    pub closed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollAnswer {
    pub id: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EditContent {
    pub target_event_id: EventId,
    pub replacement: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionContent {
    pub target_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Invite,
    Join,
    Knock,
    Leave,
    Ban,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipContent {
    pub user_id: Did,
    pub membership: MembershipState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProfileContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerLevelsContent {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub users: BTreeMap<Did, i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub events: BTreeMap<String, i64>,
    #[serde(default)]
    pub default_user_level: i64,
    #[serde(default)]
    pub default_event_level: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyContent {
    pub rule: String,
    pub effect: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagsContent {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, TagInfo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedEventsContent {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<EventId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicContent {
    pub topic: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameContent {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AvatarContent {
    pub avatar: BlobRef,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub info: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSettingsContent {
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub mention_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_rule_set: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypingContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub is_typing: bool,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVisibility {
    Public,
    Private,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptContent {
    pub user_id: Did,
    pub event_id: EventId,
    pub visibility: ReceiptVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkerContent {
    pub user_id: Did,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceContent {
    pub user_id: Did,
    pub status: PresenceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_msg: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransientDeviceContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub kind: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectSpacesContent {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces_by_user: BTreeMap<Did, Vec<SpaceId>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoredUsersContent {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<Did>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentEmojiContent {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emoji: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DraftContent {
    pub scope: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceSettingsContent {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedContent {
    pub algorithm: String,
    pub sender_key: String,
    pub ciphertext: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_keys: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomKeyContent {
    pub algorithm: String,
    pub room_id: SpaceId,
    pub session_id: String,
    pub session_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ForwardedRoomKeyContent {
    pub algorithm: String,
    pub room_id: SpaceId,
    pub session_id: String,
    pub session_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwarding_chain: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRequestAction {
    Request,
    Cancellation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyRequestContent {
    pub action: KeyRequestAction,
    pub request_id: String,
    pub requesting_device_id: DeviceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub body: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretRequestContent {
    pub action: KeyRequestAction,
    pub request_id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerificationContent {
    pub transaction_id: String,
    pub method: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallContent {
    pub call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallCandidatesContent {
    pub call_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallHangupContent {
    pub call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RtcSessionContent {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memberships: Vec<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationBatchContent {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DocumentPatchContent {
    pub entity_id: EntityId,
    pub patch_type: String,
    pub patch: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CursorContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<EntityId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub position: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelectionContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Value>,
}

pub fn event_content_json(content: KnownEventContent) -> Result<Value> {
    serde_json::to_value(content).map_err(Into::into)
}

pub fn require_known_content(content: AnyEventContent) -> Result<KnownEventContent> {
    match content {
        AnyEventContent::Known { content } => Ok(content),
        AnyEventContent::Custom { content } => Err(Error::Protocol(format!(
            "event kind '{}' does not have a built-in Contrix content model",
            content.kind
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn classifies_known_and_prefix_event_kinds() {
        assert_eq!(classify_event_kind(MESSAGE_TEXT), EventClass::Message);
        assert_eq!(classify_event_kind(STATE_MEMBERSHIP), EventClass::State);
        assert_eq!(classify_event_kind("cx.ephemeral.custom"), EventClass::Ephemeral);
        assert_eq!(
            classify_event_kind("vendor.example.widget"),
            EventClass::Custom("vendor.example.widget".to_owned())
        );
    }

    #[test]
    fn parses_known_text_content() {
        let content = parse_event_content(
            MESSAGE_TEXT,
            json!({
                "body": "hello",
                "mentions": [{ "target": "did:web:alice.example", "display_name": "Alice" }]
            }),
        )
        .unwrap();

        let known = require_known_content(content).unwrap();
        let KnownEventContent::TextMessage(message) = known else {
            panic!("expected text message");
        };
        assert_eq!(message.body, "hello");
        assert_eq!(message.mentions[0].target, "did:web:alice.example");
    }

    #[test]
    fn preserves_unknown_custom_content_losslessly() {
        let raw = json!({
            "opaque": true,
            "nested": { "answer": 42 },
            "list": [1, 2, 3]
        });
        let content = parse_event_content("vendor.example.custom", raw.clone()).unwrap();

        assert_eq!(content.as_custom_raw(), Some(&raw));
        assert_eq!(content.into_json().unwrap(), raw);
    }

    #[test]
    fn builds_typed_envelope_from_core_event() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let actor_id = Did::new("did:web:alice.example").unwrap();
        let hlc = Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap();
        let mut event = Event::new(
            MESSAGE_TEXT,
            space_id.clone(),
            actor_id.clone(),
            1,
            hlc.clone(),
            json!({ "body": "hello" }),
        )
        .unwrap();
        event.created_at = Utc.with_ymd_and_hms(2026, 4, 30, 0, 0, 0).unwrap();
        event.unsigned.insert("age".to_owned(), json!(12));

        let envelope = EventContentEnvelope::from_event(&event).unwrap();

        assert_eq!(envelope.kind, MESSAGE_TEXT);
        assert_eq!(envelope.class, EventClass::Message);
        assert_eq!(envelope.space_id, space_id);
        assert_eq!(envelope.actor_id, actor_id);
        assert_eq!(envelope.unsigned["age"], json!(12));
        assert!(matches!(
            envelope.content,
            AnyEventContent::Known { content: KnownEventContent::TextMessage(_) }
        ));
    }
}
