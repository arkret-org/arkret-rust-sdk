use std::collections::BTreeMap;

use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::{Error, Hash, MorphId, Patch, Result, StrandId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::mention::{AudienceMention, Mention};
use crate::objects::strand::MessageMetadata;

/// Payload for `ak.morph.update`.
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

pub const CONTENT_KIND_COMPOSITE: &str = "ak.content.composite";
pub const CONTENT_KIND_TEXT: &str = "ak.content.text";
pub const CONTENT_KIND_FORMATTED_TEXT: &str = "ak.content.formatted_text";
pub const CONTENT_KIND_CODE: &str = "ak.content.code";
pub const CONTENT_KIND_IMAGE: &str = "ak.content.image";
pub const CONTENT_KIND_VIDEO: &str = "ak.content.video";
pub const CONTENT_KIND_AUDIO: &str = "ak.content.audio";
pub const CONTENT_KIND_FILE: &str = "ak.content.file";
pub const CONTENT_KIND_LOCATION: &str = "ak.content.location";
pub const CONTENT_KIND_POLL: &str = "ak.content.poll";
pub const CONTENT_KIND_POLL_RESPONSE: &str = "ak.content.poll.response";
pub const CONTENT_KIND_POLL_CLOSE: &str = "ak.content.poll.close";
pub const CONTENT_KIND_AUDIENCE_MENTION: &str = "ak.content.audience_mention";

pub const MEDIA_CONTENT_KINDS: [&str; 4] = [
    CONTENT_KIND_IMAGE,
    CONTENT_KIND_VIDEO,
    CONTENT_KIND_AUDIO,
    CONTENT_KIND_FILE,
];

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
        Self::new(CONTENT_KIND_TEXT, body)
    }

    pub fn from_value(value: Value) -> Result<Self> {
        serde_json::from_value(value)
            .map_err(|err| Error::Protocol(format!("content block decode: {err}")))
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

    pub fn parsed_kind(&self) -> Option<ContentBlockKind> {
        ContentBlockKind::parse(&self.kind)
    }

    pub fn is_media(&self) -> bool {
        self.parsed_kind().is_some_and(|kind| kind.is_media())
    }

    pub fn first_media_block(&self) -> Option<&ContentBlock> {
        if self.is_media() {
            return Some(self);
        }
        if self.kind != CONTENT_KIND_COMPOSITE {
            return None;
        }
        self.parts.iter().find(|part| part.is_media())
    }

    pub fn extra_str(&self, key: &str) -> Option<&str> {
        self.extra.get(key).and_then(Value::as_str)
    }

    pub fn extra_u64(&self, key: &str) -> Option<u64> {
        self.extra.get(key).and_then(Value::as_u64)
    }

    pub fn blob_ref(&self) -> Option<&str> {
        self.extra_str("blob_ref")
    }

    pub fn mime_type(&self) -> Option<&str> {
        self.extra_str("mime_type")
    }

    pub fn filename(&self) -> Option<&str> {
        self.extra_str("filename")
    }

    pub fn size_bytes(&self) -> Option<u64> {
        self.extra_u64("size_bytes")
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
            CONTENT_KIND_COMPOSITE => Some(Self::Composite),
            CONTENT_KIND_TEXT => Some(Self::Text),
            CONTENT_KIND_FORMATTED_TEXT => Some(Self::FormattedText),
            CONTENT_KIND_CODE => Some(Self::Code),
            CONTENT_KIND_IMAGE => Some(Self::Image),
            CONTENT_KIND_VIDEO => Some(Self::Video),
            CONTENT_KIND_AUDIO => Some(Self::Audio),
            CONTENT_KIND_FILE => Some(Self::File),
            CONTENT_KIND_LOCATION => Some(Self::Location),
            CONTENT_KIND_POLL => Some(Self::Poll),
            CONTENT_KIND_POLL_RESPONSE => Some(Self::PollResponse),
            CONTENT_KIND_POLL_CLOSE => Some(Self::PollClose),
            "audience_mention" | CONTENT_KIND_AUDIENCE_MENTION => Some(Self::AudienceMention),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Composite => CONTENT_KIND_COMPOSITE,
            Self::Text => CONTENT_KIND_TEXT,
            Self::FormattedText => CONTENT_KIND_FORMATTED_TEXT,
            Self::Code => CONTENT_KIND_CODE,
            Self::Image => CONTENT_KIND_IMAGE,
            Self::Video => CONTENT_KIND_VIDEO,
            Self::Audio => CONTENT_KIND_AUDIO,
            Self::File => CONTENT_KIND_FILE,
            Self::Location => CONTENT_KIND_LOCATION,
            Self::Poll => CONTENT_KIND_POLL,
            Self::PollResponse => CONTENT_KIND_POLL_RESPONSE,
            Self::PollClose => CONTENT_KIND_POLL_CLOSE,
            Self::AudienceMention => "audience_mention",
        }
    }

    pub fn is_media(&self) -> bool {
        matches!(self, Self::Image | Self::Video | Self::Audio | Self::File)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentBlockMediaAttachment {
    pub blob_ref: String,
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub size_bytes: Option<u64>,
    pub caption: String,
}

/// Expiry anchor trigger for `ak.profile.disappearing.v1` messages.
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

/// Disappearing-message expiry contract for `ak.message.create.payload.expiry`.
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

/// Payload for `ak.message.create`.
///
/// Producers must choose exactly one of `content` or `encrypted_content`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCreatePayload {
    pub strand_id: StrandId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    pub track_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
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
        content: ContentBlock,
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
        encrypted_content: EncryptedEnvelope,
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

    pub fn content_mut(&mut self) -> Option<&mut ContentBlock> {
        self.content.as_mut()
    }

    pub fn content_block(&self) -> Result<Option<ContentBlock>> {
        Ok(self.content.clone())
    }

    pub fn plain_body(&self) -> Result<String> {
        Ok(self
            .content_block()?
            .map(|content| content.body)
            .unwrap_or_default())
    }

    pub fn first_media_content_block(&self) -> Result<Option<ContentBlock>> {
        let Some(content) = self.content_block()? else {
            return Ok(None);
        };
        Ok(content.first_media_block().cloned())
    }

    pub fn first_media_attachment(&self) -> Result<Option<ContentBlockMediaAttachment>> {
        let Some(content) = self.content_block()? else {
            return Ok(None);
        };
        let Some(block) = content.first_media_block() else {
            return Ok(None);
        };
        let Some(blob_ref) = block
            .blob_ref()
            .map(str::to_owned)
            .or_else(|| self.blob_refs.first().cloned())
        else {
            return Ok(None);
        };
        let mime_type = block.mime_type().map(str::to_owned);
        let filename = block.filename().map(str::to_owned);
        let size_bytes = block.size_bytes();
        let caption = content.body;
        Ok(Some(ContentBlockMediaAttachment {
            blob_ref,
            mime_type,
            filename,
            size_bytes,
            caption,
        }))
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
