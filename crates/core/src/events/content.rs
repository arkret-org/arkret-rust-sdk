use std::collections::BTreeMap;

use crate::{
    AnchorId, BlobRef, DeviceId, Did, Effect, Error, Event, EventId, EventRef, Hlc, Precondition,
    PresenceStatus, Result, SpaceId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::kinds::*;

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
    pub refs: Vec<EventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Precondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<Effect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<AnchorId>,
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
            refs: event.refs.clone(),
            preconditions: event.preconditions.clone(),
            effects: event.effects.clone(),
            anchor_ref: event.anchor_ref.clone(),
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
    Standard(StandardEventContent),
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

/// Generic payload wrapper for active spec event kinds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StandardEventContent {
    pub kind: String,
    pub payload: Value,
}

/// Lossless content for unknown or extension event kinds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomEventContent {
    pub kind: String,
    pub class: EventClass,
    pub raw: Value,
}

pub fn parse_event_content(kind: &str, content: Value) -> Result<AnyEventContent> {
    if is_standard_event_kind(kind) {
        return Ok(AnyEventContent::Known {
            content: KnownEventContent::Standard(StandardEventContent {
                kind: kind.to_owned(),
                payload: content,
            }),
        });
    }
    Ok(AnyEventContent::Custom {
        content: CustomEventContent {
            kind: kind.to_owned(),
            class: classify_event_kind(kind),
            raw: content,
        },
    })
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

impl TextMessageContent {
    pub fn plain(body: impl Into<String>) -> Self {
        Self { body: body.into(), ..Self::default() }
    }

    pub fn html(body: impl Into<String>, html: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            formatted: Some(FormattedBody { format: "html".to_owned(), body: html.into() }),
            mentions: Vec::new(),
            relates_to: None,
        }
    }

    pub fn with_mentions(mut self, mentions: Vec<MentionRef>) -> Self {
        self.mentions = mentions;
        self
    }

    pub fn with_relation(mut self, relates_to: RelationRef) -> Self {
        self.relates_to = Some(relates_to);
        self
    }
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

impl HtmlMessageContent {
    pub fn new(body: impl Into<String>, html: impl Into<String>) -> Self {
        Self { body: body.into(), html: html.into(), ..Self::default() }
    }

    pub fn with_mentions(mut self, mentions: Vec<MentionRef>) -> Self {
        self.mentions = mentions;
        self
    }

    pub fn with_relation(mut self, relates_to: RelationRef) -> Self {
        self.relates_to = Some(relates_to);
        self
    }
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

impl MentionRef {
    pub fn new(target: impl Into<String>) -> Self {
        Self { target: target.into(), display_name: None }
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationRef {
    pub kind: String,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
}

impl RelationRef {
    pub fn new(kind: impl Into<String>, event_id: EventId) -> Self {
        Self { kind: kind.into(), event_id, thread_id: None }
    }

    pub fn with_thread(mut self, thread_id: impl Into<String>) -> Self {
        self.thread_id = Some(thread_id.into());
        self
    }
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

impl ReactionContent {
    pub fn new(target_event_id: EventId, key: impl Into<String>) -> Self {
        Self { target_event_id, key: key.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollContent {
    pub question: String,
    pub answers: Vec<PollAnswer>,
    #[serde(default)]
    pub closed: bool,
}

impl PollContent {
    pub fn new(question: impl Into<String>, answers: Vec<PollAnswer>) -> Self {
        Self { question: question.into(), answers, closed: false }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollAnswer {
    pub id: String,
    pub text: String,
}

impl PollAnswer {
    pub fn new(id: impl Into<String>, text: impl Into<String>) -> Self {
        Self { id: id.into(), text: text.into() }
    }
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

impl EditContent {
    pub fn new(target_event_id: EventId, replacement: Value) -> Self {
        Self { target_event_id, replacement }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionContent {
    pub target_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RedactionContent {
    pub fn new(target_event_id: EventId) -> Self {
        Self { target_event_id, reason: None }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
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

// ─── Matrix / MIMI interop key-share payloads ───────────────────────────
//
// `RoomKeyContent` / `ForwardedRoomKeyContent` model the Matrix-shaped
// `cx.keys.room_key` / `cx.keys.forwarded_room_key` device-message
// payloads. These exist purely as a compat surface for clients bridging
// to Matrix / MIMI E2EE sessions — the v1 native concept is the Space,
// not a Room. The `room_id` field name is retained verbatim because the
// wire schema is fixed by the interop binding; new code SHOULD use the
// Space-typed accessor via `RoomKeyContent::space_id`. See
// `contrix-spec/spec/v1/artifacts/registry/forbidden-model-terms.json`
// "Room" entry (interop allow-listed) and
// `crypto-media/device-lifecycle.md` for the device-message transport.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoomKeyContent {
    pub algorithm: String,
    /// Matrix/MIMI compat name. The v1 concept is the Space —
    /// see [`Self::space_id`].
    pub room_id: SpaceId,
    pub session_id: String,
    pub session_key: String,
}

impl RoomKeyContent {
    /// Native v1 accessor — the Space this key share applies to.
    pub fn space_id(&self) -> &SpaceId {
        &self.room_id
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ForwardedRoomKeyContent {
    pub algorithm: String,
    /// Matrix/MIMI compat name. The v1 concept is the Space —
    /// see [`Self::space_id`].
    pub room_id: SpaceId,
    pub session_id: String,
    pub session_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwarding_chain: Vec<String>,
}

impl ForwardedRoomKeyContent {
    /// Native v1 accessor — the Space this forwarded key share applies to.
    pub fn space_id(&self) -> &SpaceId {
        &self.room_id
    }
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
    pub object_ref: String,
    pub patch_type: String,
    pub patch: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CursorContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub position: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelectionContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComposingContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    pub is_composing: bool,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActivityBeaconContent {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub activity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
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
    fn text_content_builders_preserve_mentions_and_relations() {
        let target = EventId::new("cx:event:01904100-0000-7000-8000-79a90338768b").unwrap();
        let content = TextMessageContent::html("hello", "<strong>hello</strong>")
            .with_mentions(vec![
                MentionRef::new("did:web:alice.example").with_display_name("Alice"),
            ])
            .with_relation(RelationRef::new("reply", target.clone()).with_thread("thread-1"));

        assert_eq!(content.body, "hello");
        assert_eq!(content.formatted.as_ref().map(|body| body.format.as_str()), Some("html"));
        assert_eq!(content.mentions[0].target, "did:web:alice.example");
        assert_eq!(
            content.relates_to.as_ref().map(|relation| relation.event_id.clone()),
            Some(target)
        );
    }

    #[test]
    fn parses_standard_spec_content() {
        let payload = json!({
            "flow_id": "cx:flow:01904100-0000-7000-8000-fb8cfd35e274",
            "track": "main",
            "content": { "body": "hello" }
        });
        let content = parse_event_content(MESSAGE_CREATE, payload.clone()).unwrap();

        let known = require_known_content(content).unwrap();
        let KnownEventContent::Standard(message) = known else {
            panic!("expected standard event payload");
        };
        assert_eq!(message.kind, MESSAGE_CREATE);
        assert_eq!(message.payload, payload);
    }

    #[test]
    fn classifies_multiple_active_spec_categories() {
        for (kind, class) in [
            (REACTION_ADD, EventClass::Message),
            (CALL_SIGNAL, EventClass::Call),
            (AGENT_PROTOCOL_SESSION_STATUS, EventClass::Agent),
            (MLS_WELCOME, EventClass::E2ee),
        ] {
            let content =
                require_known_content(parse_event_content(kind, json!({})).unwrap()).unwrap();
            assert!(matches!(content, KnownEventContent::Standard(_)));
            assert_eq!(classify_event_kind(kind), class);
        }
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
            MESSAGE_CREATE,
            space_id.clone(),
            actor_id.clone(),
            1,
            hlc,
            json!({
                "flow_id": "cx:flow:01904100-0000-7000-8000-fb8cfd35e274",
                "track": "main",
                "content": { "body": "hello" }
            }),
        )
        .unwrap();
        event.created_at = Utc.with_ymd_and_hms(2026, 4, 30, 0, 0, 0).unwrap();
        event.unsigned.insert("age".to_owned(), json!(12));

        let envelope = EventContentEnvelope::from_event(&event).unwrap();

        assert_eq!(envelope.kind, MESSAGE_CREATE);
        assert_eq!(envelope.class, EventClass::Message);
        assert_eq!(envelope.space_id, space_id);
        assert_eq!(envelope.actor_id, actor_id);
        assert_eq!(envelope.unsigned["age"], json!(12));
        assert!(matches!(
            envelope.content,
            AnyEventContent::Known { content: KnownEventContent::Standard(_) }
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
