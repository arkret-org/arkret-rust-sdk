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
pub const MESSAGE_POLL_START: &str = "cx.message.poll.start";
pub const MESSAGE_POLL_RESPONSE: &str = "cx.message.poll.response";
pub const MESSAGE_POLL_END: &str = "cx.message.poll.end";
pub const MESSAGE_FORM_UPDATE: &str = "cx.message.form.update";
pub const MESSAGE_TASK_UPDATE: &str = "cx.message.task.update";
pub const MESSAGE_ACKNOWLEDGEMENT: &str = "cx.message.acknowledgement";
pub const MESSAGE_EPHEMERAL_INDICATOR: &str = "cx.message.ephemeral_indicator";
pub const MESSAGE_EDIT: &str = "cx.message.edit";
pub const MESSAGE_REDACTION: &str = "cx.message.redaction";

pub const STATE_MEMBERSHIP: &str = "cx.state.membership";
pub const STATE_PROFILE: &str = "cx.state.profile";
pub const STATE_POWER_LEVELS: &str = "cx.state.power_levels";
pub const STATE_POLICY: &str = "cx.state.policy";
pub const STATE_CAPABILITIES: &str = "cx.state.capabilities";
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
pub const E2EE_SECRET_SEND: &str = "cx.e2ee.secret_send";
pub const E2EE_VERIFICATION: &str = "cx.e2ee.verification";
pub const KEY_VERIFICATION_REQUEST: &str = "cx.key.verification.request";
pub const KEY_VERIFICATION_READY: &str = "cx.key.verification.ready";
pub const KEY_VERIFICATION_START: &str = "cx.key.verification.start";
pub const KEY_VERIFICATION_ACCEPT: &str = "cx.key.verification.accept";
pub const KEY_VERIFICATION_KEY: &str = "cx.key.verification.key";
pub const KEY_VERIFICATION_MAC: &str = "cx.key.verification.mac";
pub const KEY_VERIFICATION_DONE: &str = "cx.key.verification.done";
pub const KEY_VERIFICATION_CANCEL: &str = "cx.key.verification.cancel";

pub const CALL_INVITE: &str = "cx.call.invite";
pub const CALL_ANSWER: &str = "cx.call.answer";
pub const CALL_CANDIDATES: &str = "cx.call.candidates";
pub const CALL_HANGUP: &str = "cx.call.hangup";
pub const CALL_NEGOTIATION: &str = "cx.call.negotiation";
pub const CALL_MEMBERSHIP: &str = "cx.call.membership";
pub const CALL_DEVICE_MAPPING: &str = "cx.call.device_mapping";
pub const RTC_SESSION: &str = "cx.rtc.session";

pub const COLLAB_OPERATION_BATCH: &str = "cx.collab.operation_batch";
pub const COLLAB_DOCUMENT_PATCH: &str = "cx.collab.document_patch";
pub const COLLAB_CURSOR: &str = "cx.collab.cursor";
pub const COLLAB_SELECTION: &str = "cx.collab.selection";
pub const COLLAB_COMPOSING: &str = "cx.collab.composing";
pub const COLLAB_PRESENCE: &str = "cx.collab.presence";
pub const COLLAB_ACTIVITY_BEACON: &str = "cx.collab.activity_beacon";

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
        MESSAGE_TEXT
        | MESSAGE_NOTICE
        | MESSAGE_EMOTE
        | MESSAGE_HTML
        | MESSAGE_FILE
        | MESSAGE_IMAGE
        | MESSAGE_AUDIO
        | MESSAGE_VIDEO
        | MESSAGE_VOICE
        | MESSAGE_DOCUMENT
        | MESSAGE_LOCATION
        | MESSAGE_STICKER
        | MESSAGE_REACTION
        | MESSAGE_POLL
        | MESSAGE_POLL_START
        | MESSAGE_POLL_RESPONSE
        | MESSAGE_POLL_END
        | MESSAGE_FORM_UPDATE
        | MESSAGE_TASK_UPDATE
        | MESSAGE_ACKNOWLEDGEMENT
        | MESSAGE_EPHEMERAL_INDICATOR
        | MESSAGE_EDIT
        | MESSAGE_REDACTION => EventClass::Message,
        STATE_MEMBERSHIP
        | STATE_PROFILE
        | STATE_POWER_LEVELS
        | STATE_POLICY
        | STATE_CAPABILITIES
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
        | E2EE_SECRET_SEND
        | E2EE_VERIFICATION
        | KEY_VERIFICATION_REQUEST
        | KEY_VERIFICATION_READY
        | KEY_VERIFICATION_START
        | KEY_VERIFICATION_ACCEPT
        | KEY_VERIFICATION_KEY
        | KEY_VERIFICATION_MAC
        | KEY_VERIFICATION_DONE
        | KEY_VERIFICATION_CANCEL => EventClass::E2ee,
        CALL_INVITE | CALL_ANSWER | CALL_CANDIDATES | CALL_HANGUP | CALL_NEGOTIATION
        | CALL_MEMBERSHIP | CALL_DEVICE_MAPPING => EventClass::Call,
        RTC_SESSION => EventClass::Rtc,
        COLLAB_OPERATION_BATCH
        | COLLAB_DOCUMENT_PATCH
        | COLLAB_CURSOR
        | COLLAB_SELECTION
        | COLLAB_COMPOSING
        | COLLAB_PRESENCE
        | COLLAB_ACTIVITY_BEACON => EventClass::Collaboration,
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

    pub fn unsigned_metadata(&self) -> Result<UnsignedMetadata> {
        UnsignedMetadata::from_raw(self.unsigned.clone())
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
    PollStart(PollContent),
    PollResponse(PollResponseContent),
    PollEnd(PollEndContent),
    FormUpdate(FormUpdateContent),
    TaskUpdate(TaskUpdateContent),
    Acknowledgement(AcknowledgementContent),
    EphemeralIndicator(EphemeralIndicatorContent),
    Edit(EditContent),
    Redaction(RedactionContent),
    Membership(MembershipContent),
    Profile(ProfileContent),
    PowerLevels(PowerLevelsContent),
    Policy(PolicyContent),
    Capabilities(CapabilitiesContent),
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
    SecretSend(SecretSendContent),
    Verification(VerificationContent),
    CallInvite(CallContent),
    CallAnswer(CallContent),
    CallCandidates(CallCandidatesContent),
    CallHangup(CallHangupContent),
    CallNegotiation(CallNegotiationContent),
    CallMembership(CallMembershipContent),
    CallDeviceMapping(CallDeviceMappingContent),
    RtcSession(RtcSessionContent),
    OperationBatch(OperationBatchContent),
    DocumentPatch(DocumentPatchContent),
    Cursor(CursorContent),
    Selection(SelectionContent),
    Composing(ComposingContent),
    CollabPresence(PresenceContent),
    ActivityBeacon(ActivityBeaconContent),
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
        MESSAGE_POLL_START => KnownEventContent::PollStart(parse(content)?),
        MESSAGE_POLL_RESPONSE => KnownEventContent::PollResponse(parse(content)?),
        MESSAGE_POLL_END => KnownEventContent::PollEnd(parse(content)?),
        MESSAGE_FORM_UPDATE => KnownEventContent::FormUpdate(parse(content)?),
        MESSAGE_TASK_UPDATE => KnownEventContent::TaskUpdate(parse(content)?),
        MESSAGE_ACKNOWLEDGEMENT => KnownEventContent::Acknowledgement(parse(content)?),
        MESSAGE_EPHEMERAL_INDICATOR => KnownEventContent::EphemeralIndicator(parse(content)?),
        MESSAGE_EDIT => KnownEventContent::Edit(parse(content)?),
        MESSAGE_REDACTION => KnownEventContent::Redaction(parse(content)?),
        STATE_MEMBERSHIP => KnownEventContent::Membership(parse(content)?),
        STATE_PROFILE => KnownEventContent::Profile(parse(content)?),
        STATE_POWER_LEVELS => KnownEventContent::PowerLevels(parse(content)?),
        STATE_POLICY => KnownEventContent::Policy(parse(content)?),
        STATE_CAPABILITIES => KnownEventContent::Capabilities(parse(content)?),
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
        E2EE_SECRET_SEND => KnownEventContent::SecretSend(parse(content)?),
        E2EE_VERIFICATION
        | KEY_VERIFICATION_REQUEST
        | KEY_VERIFICATION_READY
        | KEY_VERIFICATION_START
        | KEY_VERIFICATION_ACCEPT
        | KEY_VERIFICATION_KEY
        | KEY_VERIFICATION_MAC
        | KEY_VERIFICATION_DONE
        | KEY_VERIFICATION_CANCEL => KnownEventContent::Verification(parse(content)?),
        CALL_INVITE => KnownEventContent::CallInvite(parse(content)?),
        CALL_ANSWER => KnownEventContent::CallAnswer(parse(content)?),
        CALL_CANDIDATES => KnownEventContent::CallCandidates(parse(content)?),
        CALL_HANGUP => KnownEventContent::CallHangup(parse(content)?),
        CALL_NEGOTIATION => KnownEventContent::CallNegotiation(parse(content)?),
        CALL_MEMBERSHIP => KnownEventContent::CallMembership(parse(content)?),
        CALL_DEVICE_MAPPING => KnownEventContent::CallDeviceMapping(parse(content)?),
        RTC_SESSION => KnownEventContent::RtcSession(parse(content)?),
        COLLAB_OPERATION_BATCH => KnownEventContent::OperationBatch(parse(content)?),
        COLLAB_DOCUMENT_PATCH => KnownEventContent::DocumentPatch(parse(content)?),
        COLLAB_CURSOR => KnownEventContent::Cursor(parse(content)?),
        COLLAB_SELECTION => KnownEventContent::Selection(parse(content)?),
        COLLAB_COMPOSING => KnownEventContent::Composing(parse(content)?),
        COLLAB_PRESENCE => KnownEventContent::CollabPresence(parse(content)?),
        COLLAB_ACTIVITY_BEACON => KnownEventContent::ActivityBeacon(parse(content)?),
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

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UnsignedMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_aggregations: Vec<RelationAggregation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub server_annotations: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, Value>,
}

impl UnsignedMetadata {
    pub fn from_raw(raw: BTreeMap<String, Value>) -> Result<Self> {
        let age_ms = raw.get("age_ms").or_else(|| raw.get("age")).and_then(Value::as_u64);
        let transaction_id = raw
            .get("transaction_id")
            .or_else(|| raw.get("txn_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let relation_aggregations = raw
            .get("relation_aggregations")
            .or_else(|| raw.get("relations"))
            .map(parse_relation_aggregations)
            .transpose()?
            .unwrap_or_default();
        let redaction = raw
            .get("redacted_because")
            .or_else(|| raw.get("redaction"))
            .map(RedactionMetadata::from_value)
            .transpose()?;
        let server_annotations = raw
            .iter()
            .filter(|(key, _)| key.starts_with("server.") || key.starts_with("annotation."))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        Ok(Self {
            age_ms,
            transaction_id,
            relation_aggregations,
            redaction,
            server_annotations,
            raw,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationAggregation {
    pub target_event_id: EventId,
    pub relation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_event_id: Option<EventId>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RedactionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, Value>,
}

impl RedactionMetadata {
    fn from_value(value: &Value) -> Result<Self> {
        let Some(object) = value.as_object() else {
            return Ok(Self {
                raw: BTreeMap::from([("value".to_owned(), value.clone())]),
                ..Self::default()
            });
        };
        let event_id =
            object.get("event_id").and_then(Value::as_str).map(EventId::new).transpose()?;
        let actor_id = object
            .get("actor_id")
            .or_else(|| object.get("sender"))
            .and_then(Value::as_str)
            .map(Did::new)
            .transpose()?;
        let reason = object.get("reason").and_then(Value::as_str).map(ToOwned::to_owned);
        Ok(Self {
            event_id,
            actor_id,
            reason,
            raw: object.iter().map(|(key, value)| (key.clone(), value.clone())).collect(),
        })
    }
}

fn parse_relation_aggregations(value: &Value) -> Result<Vec<RelationAggregation>> {
    match value {
        Value::Array(items) => items.iter().cloned().map(parse).collect(),
        Value::Object(_) => parse(value.clone()).map(|aggregation| vec![aggregation]),
        _ => Err(Error::Protocol(
            "unsigned relation aggregations must be an object or array".to_owned(),
        )),
    }
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollResponseContent {
    pub poll_event_id: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answer_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responded_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollEndContent {
    pub poll_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FormUpdateContent {
    pub form_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relates_to: Option<RelationRef>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskUpdateContent {
    pub task_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<Did>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relates_to: Option<RelationRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcknowledgementContent {
    pub target_event_id: EventId,
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EphemeralIndicatorContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub indicator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_event_id: Option<EventId>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
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

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CapabilitiesContent {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_power_levels: BTreeMap<String, i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub feature_flags: BTreeMap<String, bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, Value>,
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
pub struct SecretSendContent {
    pub request_id: String,
    pub name: String,
    pub encrypted_secret: EncryptedContent,
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
pub struct CallNegotiationContent {
    pub call_id: String,
    pub negotiation_id: String,
    pub phase: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallMembershipContent {
    pub call_id: String,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub membership: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CallDeviceMappingContent {
    pub call_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub devices_by_user: BTreeMap<Did, Vec<DeviceId>>,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComposingContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<EntityId>,
    pub is_composing: bool,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActivityBeaconContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub activity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
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
        assert_eq!(classify_event_kind(MESSAGE_POLL_RESPONSE), EventClass::Message);
        assert_eq!(classify_event_kind(STATE_MEMBERSHIP), EventClass::State);
        assert_eq!(classify_event_kind(CALL_DEVICE_MAPPING), EventClass::Call);
        assert_eq!(classify_event_kind(COLLAB_ACTIVITY_BEACON), EventClass::Collaboration);
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
    fn parses_poll_lifecycle_and_interactive_events() {
        let poll_response = require_known_content(
            parse_event_content(
                MESSAGE_POLL_RESPONSE,
                json!({
                    "poll_event_id": "cx:event:01904100-0000-7000-8000-fb8cfd35e274",
                    "answer_ids": ["a"],
                    "responded_at": "2026-05-01T00:00:00Z"
                }),
            )
            .unwrap(),
        )
        .unwrap();
        let KnownEventContent::PollResponse(response) = poll_response else {
            panic!("expected poll response");
        };
        assert_eq!(
            response.poll_event_id.as_str(),
            "cx:event:01904100-0000-7000-8000-fb8cfd35e274"
        );
        assert_eq!(response.answer_ids, vec!["a"]);

        let acknowledgement = require_known_content(
            parse_event_content(
                MESSAGE_ACKNOWLEDGEMENT,
                json!({
                    "target_event_id": "cx:event:01904100-0000-7000-8000-79a90338768b",
                    "key": "seen"
                }),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            acknowledgement,
            KnownEventContent::Acknowledgement(AcknowledgementContent { key, .. }) if key == "seen"
        ));
    }

    #[test]
    fn parses_collaboration_call_and_secret_events() {
        let beacon = require_known_content(
            parse_event_content(
                COLLAB_ACTIVITY_BEACON,
                json!({
                    "user_id": "did:web:alice.example",
                    "device_id": "dev_alice",
                    "activity": "viewing",
                    "observed_at": "2026-05-01T00:00:00Z"
                }),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            beacon,
            KnownEventContent::ActivityBeacon(ActivityBeaconContent { activity, .. }) if activity == "viewing"
        ));

        let mapping = require_known_content(
            parse_event_content(
                CALL_DEVICE_MAPPING,
                json!({
                    "call_id": "call-1",
                    "devices_by_user": {
                        "did:web:alice.example": ["dev_alice"]
                    }
                }),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            mapping,
            KnownEventContent::CallDeviceMapping(CallDeviceMappingContent { call_id, .. }) if call_id == "call-1"
        ));

        let secret = require_known_content(
            parse_event_content(
                E2EE_SECRET_SEND,
                json!({
                    "request_id": "req-1",
                    "name": "recovery",
                    "encrypted_secret": {
                        "algorithm": "cx.v1",
                        "sender_key": "ed25519:abc",
                        "ciphertext": { "body": "encrypted" }
                    }
                }),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            secret,
            KnownEventContent::SecretSend(SecretSendContent { name, .. }) if name == "recovery"
        ));
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
        let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let actor_id = Did::new("did:web:alice.example").unwrap();
        let hlc = Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap();
        let mut event = Event::new(
            MESSAGE_TEXT,
            space_id.clone(),
            actor_id.clone(),
            1,
            hlc,
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

    #[test]
    fn exposes_structured_unsigned_metadata() {
        let metadata = UnsignedMetadata::from_raw(BTreeMap::from([
            ("age".to_owned(), json!(42)),
            ("transaction_id".to_owned(), json!("txn-1")),
            (
                "relation_aggregations".to_owned(),
                json!([{
                    "target_event_id": "cx:event:01904100-0000-7000-8000-79a90338768b",
                    "relation_type": "reaction",
                    "key": "+1",
                    "count": 2,
                    "latest_event_id": "cx:event:01904100-0000-7000-8000-80da3b20e8ac"
                }]),
            ),
            (
                "redacted_because".to_owned(),
                json!({
                    "event_id": "cx:event:01904100-0000-7000-8000-743d43d94991",
                    "actor_id": "did:web:moderator.example",
                    "reason": "policy"
                }),
            ),
            ("server.received_at".to_owned(), json!("2026-05-01T00:00:00Z")),
        ]))
        .unwrap();

        assert_eq!(metadata.age_ms, Some(42));
        assert_eq!(metadata.transaction_id.as_deref(), Some("txn-1"));
        assert_eq!(metadata.relation_aggregations[0].count, 2);
        assert_eq!(
            metadata.redaction.as_ref().and_then(|redaction| redaction.reason.as_deref()),
            Some("policy")
        );
        assert!(metadata.server_annotations.contains_key("server.received_at"));
    }
}
