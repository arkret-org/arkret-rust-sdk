use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::canonical::now_utc_seconds;
use crate::*;

/// Current wire object carried by `ck.morph.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MorphCreateObject {
    pub id: MorphId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    pub schema_refs: Vec<String>,
    pub morph_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facets: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MorphMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    pub stage: ObjectStage,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl MorphCreateObject {
    pub fn new(
        id: MorphId,
        realm_id: RealmId,
        morph_type: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: MORPH_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            schema_refs: vec![MORPH_SCHEMA.to_owned()],
            morph_type: morph_type.into(),
            facets: BTreeMap::new(),
            metadata: None,
            encrypted_metadata: None,
            content: None,
            encrypted_content: None,
            fields: BTreeMap::new(),
            state: None,
            stage: ObjectStage::Draft,
            created_by,
            created_at: now_utc_seconds(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(MorphMetadata::default)
            .title = Some(title.into());
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(MorphMetadata::default)
            .summary = Some(summary.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata
            .get_or_insert_with(MorphMetadata::default)
            .extra
            .insert(key.into(), value);
        self
    }

    pub fn with_content(mut self, content: Value) -> Self {
        self.content = Some(content);
        self.encrypted_content = None;
        self
    }

    pub fn with_encrypted_content(mut self, encrypted_content: Value) -> Self {
        self.encrypted_content = Some(encrypted_content);
        self.content = None;
        self
    }

    pub fn with_facet(mut self, name: impl Into<String>, value: Value) -> Self {
        self.facets.insert(name.into(), value);
        self
    }

    pub fn with_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn validate_content_carrier(&self) -> Result<()> {
        if self.content.is_some() && self.encrypted_content.is_some() {
            return Err(Error::Protocol(
                "morph create object must not carry both content and encrypted_content".to_owned(),
            ));
        }
        if self.metadata.is_some() && self.encrypted_metadata.is_some() {
            return Err(Error::Protocol(
                "morph create object must not carry both metadata and encrypted_metadata"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_create_payload_value(&self) -> Result<Value> {
        self.validate_content_carrier()?;
        ObjectCreatePayload::new(self).to_value()
    }
}

/// Payload for `ck.morph.update`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphUpdatePayload {
    pub target_ref: MorphId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl MorphUpdatePayload {
    pub fn for_morph(morph_id: MorphId, patch: Patch) -> Result<Self> {
        validate_morph_update_patch(&patch)?;
        Ok(Self {
            target_ref: morph_id,
            patch,
            expected_state_digest: None,
        })
    }

    pub fn with_expected_state_digest(mut self, expected_state_digest: Hash) -> Self {
        self.expected_state_digest = Some(expected_state_digest);
        self
    }

    pub fn validate(&self) -> Result<()> {
        validate_morph_update_patch(&self.patch)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("morph update payload serialize: {err}")))
    }
}

fn validate_morph_update_patch(patch: &Patch) -> Result<()> {
    patch.validate()?;
    for (path, _) in patch.iter() {
        if matches!(path.as_str(), "morph_type" | "stage" | "stage_changed_at") {
            return Err(Error::Protocol(
                "morph update patch targets create-locked or single-sourced field".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Extensible ContentBlock used by message, Strand, and Morph content fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContentBlock {
    pub kind: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<ContentBlock>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ContentBlock {
    pub fn new(kind: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            body: body.into(),
            parts: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    pub fn text(body: impl Into<String>) -> Self {
        Self::new("ck.content.text", body)
    }

    pub fn with_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn with_mentions(mut self, mentions: Vec<Mention>) -> Result<Self> {
        let value = serde_json::to_value(mentions)
            .map_err(|err| Error::Protocol(format!("content mentions serialize: {err}")))?;
        self.extra.insert("mentions".to_owned(), value);
        Ok(self)
    }

    pub fn with_audience_mentions(
        mut self,
        audience_mentions: Vec<AudienceMention>,
    ) -> Result<Self> {
        let value = serde_json::to_value(audience_mentions).map_err(|err| {
            Error::Protocol(format!("content audience_mentions serialize: {err}"))
        })?;
        self.extra.insert("audience_mentions".to_owned(), value);
        Ok(self)
    }

    pub fn with_part(mut self, part: ContentBlock) -> Self {
        self.parts.push(part);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("content block serialize: {err}")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentBlockKind {
    Composite,
    Text,
    FormattedText,
    Code,
    Image,
    Video,
    Audio,
    File,
    Location,
    Poll,
    PollResponse,
    PollClose,
    AudienceMention,
}

impl ContentBlockKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ck.content.composite" => Some(Self::Composite),
            "ck.content.text" => Some(Self::Text),
            "ck.content.formatted_text" => Some(Self::FormattedText),
            "ck.content.code" => Some(Self::Code),
            "ck.content.image" => Some(Self::Image),
            "ck.content.video" => Some(Self::Video),
            "ck.content.audio" => Some(Self::Audio),
            "ck.content.file" => Some(Self::File),
            "ck.content.location" => Some(Self::Location),
            "ck.content.poll" => Some(Self::Poll),
            "ck.content.poll.response" => Some(Self::PollResponse),
            "ck.content.poll.close" => Some(Self::PollClose),
            "audience_mention" | "ck.content.audience_mention" => Some(Self::AudienceMention),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Composite => "ck.content.composite",
            Self::Text => "ck.content.text",
            Self::FormattedText => "ck.content.formatted_text",
            Self::Code => "ck.content.code",
            Self::Image => "ck.content.image",
            Self::Video => "ck.content.video",
            Self::Audio => "ck.content.audio",
            Self::File => "ck.content.file",
            Self::Location => "ck.content.location",
            Self::Poll => "ck.content.poll",
            Self::PollResponse => "ck.content.poll.response",
            Self::PollClose => "ck.content.poll.close",
            Self::AudienceMention => "audience_mention",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentBlockValidationError {
    message: &'static str,
}

impl ContentBlockValidationError {
    pub fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ContentBlockValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for ContentBlockValidationError {}

pub type ContentBlockValidationResult<T> = std::result::Result<T, ContentBlockValidationError>;

pub fn validate_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    let Some(object) = block.as_object() else {
        return Err(ContentBlockValidationError::new(
            "content block must be a JSON object",
        ));
    };
    let Some(block_kind) = object.get("kind").and_then(Value::as_str) else {
        return Err(ContentBlockValidationError::new(
            "content block requires kind",
        ));
    };
    if object.contains_key("blocks") {
        return Err(ContentBlockValidationError::new(
            "content.blocks is not permitted; use content.parts",
        ));
    }
    let Some(block_kind) = ContentBlockKind::parse(block_kind) else {
        return Err(ContentBlockValidationError::new(
            "unsupported content block type",
        ));
    };
    match block_kind {
        ContentBlockKind::Composite => validate_composite_content_block(block),
        ContentBlockKind::Text | ContentBlockKind::FormattedText => {
            if !content_block_has_text(block) {
                return Err(ContentBlockValidationError::new(
                    "text content block requires text",
                ));
            }
            Ok(())
        }
        ContentBlockKind::Code => {
            if block
                .get("text")
                .or_else(|| block.get("body"))
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(ContentBlockValidationError::new(
                    "code content block requires text",
                ));
            }
            Ok(())
        }
        ContentBlockKind::Image
        | ContentBlockKind::Video
        | ContentBlockKind::Audio
        | ContentBlockKind::File => validate_media_content_block(block),
        ContentBlockKind::Location => validate_location_content_block(block),
        ContentBlockKind::Poll => validate_poll_content_block(block),
        ContentBlockKind::PollResponse => validate_poll_response_content_block(block),
        ContentBlockKind::PollClose => {
            if block
                .get("poll_id")
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(ContentBlockValidationError::new(
                    "poll close content block requires poll_id",
                ));
            }
            Ok(())
        }
        ContentBlockKind::AudienceMention => {
            serde_json::from_value::<AudienceMention>(block.clone())
                .map(|_| ())
                .map_err(|_| ContentBlockValidationError::new("audience mention is invalid"))
        }
    }
}

fn validate_composite_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    let Some(parts) = block.get("parts").and_then(Value::as_array) else {
        return Err(ContentBlockValidationError::new(
            "composite content block requires parts",
        ));
    };
    if parts.is_empty() {
        return Err(ContentBlockValidationError::new(
            "content.parts must not be empty",
        ));
    }
    for part in parts {
        validate_content_block(part)?;
    }
    Ok(())
}

fn validate_media_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    let has_blob_ref = block
        .get("blob_ref")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("ck:blob:sha256:"));
    let has_url = block
        .get("url")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    if !has_blob_ref && !has_url {
        return Err(ContentBlockValidationError::new(
            "media content block requires blob_ref or url",
        ));
    }
    Ok(())
}

fn validate_location_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    if !block.get("latitude").is_some_and(json_integer)
        || !block.get("longitude").is_some_and(json_integer)
    {
        return Err(ContentBlockValidationError::new(
            "location content block requires latitude and longitude",
        ));
    }
    Ok(())
}

fn validate_poll_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    let poll = serde_json::from_value::<PollBlock>(block.clone()).map_err(|_| {
        ContentBlockValidationError::new(
            "poll content block requires question and at least two options",
        )
    })?;
    let has_question = !poll.body.trim().is_empty()
        || poll
            .poll
            .question
            .as_ref()
            .is_some_and(|question| content_block_has_text_value(question));
    if !has_question || poll.poll.answers.len() < 2 {
        return Err(ContentBlockValidationError::new(
            "poll content block requires question and at least two options",
        ));
    }
    for answer in &poll.poll.answers {
        validate_content_block(&answer.text.to_value().map_err(|_| {
            ContentBlockValidationError::new("poll content block answer requires text")
        })?)?;
    }
    Ok(())
}

fn validate_poll_response_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    let response = serde_json::from_value::<PollResponseBlock>(block.clone()).map_err(|_| {
        ContentBlockValidationError::new(
            "poll response content block requires poll_ref and at least one selection",
        )
    })?;
    if response
        .poll_response
        .selections
        .iter()
        .all(|selection| selection.trim().is_empty())
    {
        return Err(ContentBlockValidationError::new(
            "poll response content block requires poll_ref and at least one selection",
        ));
    }
    Ok(())
}

fn content_block_has_text(block: &Value) -> bool {
    block.as_str().is_some_and(|value| !value.trim().is_empty())
        || block
            .get("body")
            .or_else(|| block.get("text"))
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
}

fn content_block_has_text_value(block: &ContentBlock) -> bool {
    !block.body.trim().is_empty()
        || block
            .extra
            .get("text")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
}

fn json_integer(value: &Value) -> bool {
    value.is_i64() || value.is_u64()
}

/// Expiry anchor trigger for `ck.profile.disappearing.v1` messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisappearingMessageExpiryTrigger {
    OnSend,
    OnFirstRead,
    OnLastRead,
}

impl DisappearingMessageExpiryTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnSend => "on_send",
            Self::OnFirstRead => "on_first_read",
            Self::OnLastRead => "on_last_read",
        }
    }
}

/// Disappearing-message expiry contract for `ck.message.create.payload.expiry`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisappearingMessageExpiry {
    pub ttl_ms: u64,
    pub trigger: DisappearingMessageExpiryTrigger,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_ms: Option<u64>,
}

impl DisappearingMessageExpiry {
    pub fn new(ttl_ms: u64, trigger: DisappearingMessageExpiryTrigger) -> Result<Self> {
        let expiry = Self {
            ttl_ms,
            trigger,
            grace_ms: None,
        };
        expiry.validate()?;
        Ok(expiry)
    }

    pub fn with_grace_ms(mut self, grace_ms: u64) -> Self {
        self.grace_ms = Some(grace_ms);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.ttl_ms == 0 {
            return Err(Error::Protocol(
                "message expiry ttl_ms must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Payload for `ck.message.create`.
///
/// Producers must choose exactly one of `content` or `encrypted_content`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCreatePayload {
    pub strand_id: StrandId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    pub track_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mention_sidecar_hash: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DisappearingMessageExpiry>,
}

impl MessageCreatePayload {
    pub fn with_content(
        strand_id: StrandId,
        track_name: impl Into<String>,
        content: Value,
    ) -> Self {
        Self {
            strand_id,
            message_id: None,
            track_name: track_name.into(),
            content: Some(content),
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            blob_refs: Vec::new(),
            mention_sidecar_hash: Vec::new(),
            reply_to: None,
            expiry: None,
        }
    }

    pub fn with_encrypted_content(
        strand_id: StrandId,
        track_name: impl Into<String>,
        encrypted_content: Value,
    ) -> Self {
        Self {
            strand_id,
            message_id: None,
            track_name: track_name.into(),
            content: None,
            encrypted_content: Some(encrypted_content),
            metadata: None,
            encrypted_metadata: None,
            blob_refs: Vec::new(),
            mention_sidecar_hash: Vec::new(),
            reply_to: None,
            expiry: None,
        }
    }

    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }

    pub fn with_expiry(mut self, expiry: DisappearingMessageExpiry) -> Self {
        self.expiry = Some(expiry);
        self
    }

    pub fn content_mut(&mut self) -> Option<&mut Value> {
        self.content.as_mut()
    }

    pub fn to_value(&self) -> Result<Value> {
        if self.metadata.is_some() && self.encrypted_metadata.is_some() {
            return Err(Error::Protocol(
                "message create payload must not carry both metadata and encrypted_metadata"
                    .to_owned(),
            ));
        }
        if let Some(expiry) = self.expiry.as_ref() {
            expiry.validate()?;
        }
        match (self.content.is_some(), self.encrypted_content.is_some()) {
            (true, false) | (false, true) => serde_json::to_value(self)
                .map_err(|err| Error::Protocol(format!("message create payload serialize: {err}"))),
            (false, false) => Err(Error::Protocol(
                "message create payload requires content or encrypted_content".to_owned(),
            )),
            (true, true) => Err(Error::Protocol(
                "message create payload must not carry both content and encrypted_content"
                    .to_owned(),
            )),
        }
    }
}
