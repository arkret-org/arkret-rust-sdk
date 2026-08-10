//! Message and content-block event payloads.

use std::collections::BTreeMap;

use arkret_models_crypto::{
    EncryptedEnvelope, MlsEncryptedPayload, MlsPayloadType, PlainPayload, ProtectedPayload,
};
use arkret_wire::{DidCoreId, Error, Result, StrandId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::mention::{AudienceMention, Mention};
use crate::events_payloads::poll::{PollBlock, PollResponseBlock};
use crate::internal_prelude::*;
use crate::objects::strand::MessageMetadata;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/content_kind`.
pub type ContentKind = String;

/// Canonical decrypted media type for an MLS-protected message ContentBlock.
pub const MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE: &str = "application/vnd.arkret.message+json";

/// Canonical decrypted media type for MLS-protected Message metadata.
pub const MESSAGE_METADATA_MLS_CONTENT_TYPE: &str = "application/vnd.arkret.message-metadata+json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageTrackName {
    Discussion,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_metadata_fields`.
pub type MessageMetadataFields = BTreeMap<String, Value>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_redact_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRedactPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<MessageTrackName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserve: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageRedactPayloadWire {
    #[serde(default)]
    message_id: Option<MessageId>,
    #[serde(default)]
    target_ref: Option<ObjectRef>,
    #[serde(default)]
    event_id: Option<EventId>,
    #[serde(default)]
    target_event_id: Option<EventId>,
    #[serde(default)]
    track_name: Option<MessageTrackName>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    preserve: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for MessageRedactPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MessageRedactPayloadWire::deserialize(deserializer)?;
        if wire.message_id.is_none()
            && wire.target_ref.is_none()
            && wire.event_id.is_none()
            && wire.target_event_id.is_none()
        {
            return Err(serde::de::Error::custom(
                "message_redact_payload requires a target identifier",
            ));
        }
        Ok(Self {
            message_id: wire.message_id,
            target_ref: wire.target_ref,
            event_id: wire.event_id,
            target_event_id: wire.target_event_id,
            track_name: wire.track_name,
            reason: wire.reason,
            preserve: wire.preserve,
        })
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_revise_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRevisePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_of: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<MessageTrackName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageRevisePayloadWire {
    #[serde(default)]
    message_id: Option<MessageId>,
    #[serde(default)]
    target_ref: Option<ObjectRef>,
    #[serde(default)]
    revision_of: Option<MessageId>,
    #[serde(default)]
    track_name: Option<MessageTrackName>,
    #[serde(default)]
    content: Option<ContentBlock>,
    #[serde(default)]
    encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default)]
    metadata: Option<MessageMetadata>,
    #[serde(default)]
    encrypted_metadata: Option<EncryptedEnvelope>,
    #[serde(default)]
    reason: Option<String>,
}

impl<'de> Deserialize<'de> for MessageRevisePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MessageRevisePayloadWire::deserialize(deserializer)?;
        if wire.message_id.is_none() && wire.target_ref.is_none() && wire.revision_of.is_none() {
            return Err(serde::de::Error::custom(
                "message_revise_payload requires a target identifier",
            ));
        }
        if wire.content.is_some() == wire.encrypted_content.is_some() {
            return Err(serde::de::Error::custom(
                "message_revise_payload requires exactly one content carrier",
            ));
        }
        if wire.metadata.is_some() && wire.encrypted_metadata.is_some() {
            return Err(serde::de::Error::custom(
                "message_revise_payload cannot contain both metadata forms",
            ));
        }
        Ok(Self {
            message_id: wire.message_id,
            target_ref: wire.target_ref,
            revision_of: wire.revision_of,
            track_name: wire.track_name,
            content: wire.content,
            encrypted_content: wire.encrypted_content,
            metadata: wire.metadata,
            encrypted_metadata: wire.encrypted_metadata,
            reason: wire.reason,
        })
    }
}

pub const CONTENT_KIND_COMPOSITE: &str = "ak.content.composite";
pub const CONTENT_KIND_TEXT: &str = "ak.content.text";
pub const CONTENT_KIND_LONG_TEXT: &str = "ak.content.long_text";
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
const LEGACY_CONTENT_KIND_AUDIENCE_MENTION: &str = "audience_mention";

pub const MEDIA_CONTENT_KINDS: [&str; 4] = [
    CONTENT_KIND_IMAGE,
    CONTENT_KIND_VIDEO,
    CONTENT_KIND_AUDIO,
    CONTENT_KIND_FILE,
];

/// Extensible ContentBlock used by message, Strand, and Morph content fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContentBlock {
    pub kind: ContentBlockKind,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<ContentBlock>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl MlsPayloadType for ContentBlock {
    const MLS_CONTENT_TYPE: &'static str = MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE;
}

impl MlsPayloadType for MessageMetadata {
    const MLS_CONTENT_TYPE: &'static str = MESSAGE_METADATA_MLS_CONTENT_TYPE;
}

impl ContentBlock {
    pub fn new(kind: ContentBlockKind, body: impl Into<String>) -> Self {
        Self {
            kind,
            body: body.into(),
            parts: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    pub fn text(body: impl Into<String>) -> Self {
        Self::new(ContentBlockKind::Text, body)
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

    pub fn parsed_kind(&self) -> ContentBlockKind {
        self.kind
    }

    pub fn is_media(&self) -> bool {
        self.kind.is_media()
    }

    pub fn first_media_block(&self) -> Option<&ContentBlock> {
        if self.is_media() {
            return Some(self);
        }
        if self.kind != ContentBlockKind::Composite {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentBlockKind {
    Composite,
    Text,
    LongText,
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

impl std::fmt::Display for ContentBlockKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl ContentBlockKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            CONTENT_KIND_COMPOSITE => Some(Self::Composite),
            CONTENT_KIND_TEXT => Some(Self::Text),
            CONTENT_KIND_LONG_TEXT => Some(Self::LongText),
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
            LEGACY_CONTENT_KIND_AUDIENCE_MENTION | CONTENT_KIND_AUDIENCE_MENTION => {
                Some(Self::AudienceMention)
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Composite => CONTENT_KIND_COMPOSITE,
            Self::Text => CONTENT_KIND_TEXT,
            Self::LongText => CONTENT_KIND_LONG_TEXT,
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
            Self::AudienceMention => CONTENT_KIND_AUDIENCE_MENTION,
        }
    }

    pub fn is_media(&self) -> bool {
        matches!(self, Self::Image | Self::Video | Self::Audio | Self::File)
    }
}

impl Serialize for ContentBlockKind {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ContentBlockKind {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value)
            .ok_or_else(|| serde::de::Error::custom("unsupported content block kind"))
    }
}

/// Inline / long-text boundary for `ak.content.text.body`, measured in normalized UTF-8 bytes.
///
/// See `zh/models/content-types.md` section 4.1.4 and
/// `zh/conformance/scalability-constraints.md` section 5.
pub const CONTENT_TEXT_INLINE_MAX_BYTES: usize = 262_144;

/// Fallback `body` bound for `ak.content.long_text`, measured in normalized UTF-8 bytes.
pub const LONG_TEXT_FALLBACK_MAX_BYTES: usize = 4_096;

/// Closed `body_kind` set for `ak.content.long_text`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LongTextBodyKind {
    Prefix,
    Summary,
}

impl LongTextBodyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Summary => "summary",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "prefix" => Some(Self::Prefix),
            "summary" => Some(Self::Summary),
            _ => None,
        }
    }
}

/// Closed `format` set for `ak.content.long_text`, paired with its media type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LongTextFormat {
    Plain,
    Markdown,
}

impl LongTextFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Markdown => "markdown",
        }
    }

    /// Media type bound to this format. No parameters: charset is fixed to UTF-8 by the kind.
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Plain => "text/plain",
            Self::Markdown => "text/markdown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Self::Plain),
            "markdown" => Some(Self::Markdown),
            _ => None,
        }
    }
}

/// Normalize a long-text body per `zh/models/content-types.md` section 4.1.2.
///
/// Rejects a BOM and every C0 control character other than LF and TAB, and rewrites CRLF / CR to
/// LF. The result is what `size_bytes` (plaintext form) or `attachment.size_bytes` (E2EE form),
/// the Blob digest and `line_count` are computed over; producers MUST normalize before deriving a
/// prefix or a summary.
pub fn normalize_long_text(input: &str) -> Result<String> {
    if input.starts_with('\u{feff}') {
        return Err(Error::Protocol(
            "long_text body must not start with a BOM".to_owned(),
        ));
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(ch),
            '\u{0}'..='\u{1f}' | '\u{7f}' => {
                return Err(Error::Protocol(format!(
                    "long_text body must not contain control character U+{:04X}",
                    ch as u32
                )));
            }
            _ => out.push(ch),
        }
    }
    Ok(out)
}

/// `line_count` for an already normalized long-text body.
pub fn long_text_line_count(normalized: &str) -> u64 {
    if normalized.is_empty() {
        return 0;
    }
    let newlines = normalized.matches('\n').count() as u64;
    if normalized.ends_with('\n') {
        newlines
    } else {
        newlines + 1
    }
}

/// Return the longest UTF-8 scalar-safe prefix within the normative fallback bound.
pub fn long_text_prefix(normalized: &str) -> &str {
    if normalized.len() <= LONG_TEXT_FALLBACK_MAX_BYTES {
        return normalized;
    }
    let mut end = LONG_TEXT_FALLBACK_MAX_BYTES;
    while !normalized.is_char_boundary(end) {
        end -= 1;
    }
    &normalized[..end]
}

fn hash_blob_ref_suite_and_hex(blob_ref: &str) -> Option<(&str, &str)> {
    let rest = blob_ref.strip_prefix("ak:blob:")?;
    let (suite, hex) = rest.split_once(':')?;
    if !matches!(suite, "sha256" | "blake3") {
        return None;
    }
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    Some((suite, hex))
}

impl ContentBlock {
    /// Build the plaintext branch of `ak.content.long_text` from the complete
    /// source body and the hash-addressed Blob ref returned by its upload.
    ///
    /// The body is normalized before all derived fields are computed. Prefix
    /// mode derives the longest scalar-safe 4 KiB prefix; summary mode requires
    /// an explicit summary and normalizes it independently.
    pub fn plaintext_long_text(
        full_body: &str,
        format: LongTextFormat,
        blob_ref: impl Into<String>,
        body_kind: LongTextBodyKind,
        summary: Option<&str>,
    ) -> Result<Self> {
        let normalized = normalize_long_text(full_body)?;
        let fallback = match body_kind {
            LongTextBodyKind::Prefix => long_text_prefix(&normalized).to_owned(),
            LongTextBodyKind::Summary => {
                let summary = summary.ok_or_else(|| {
                    Error::Protocol(
                        "long_text body_kind=summary requires an explicit summary".to_owned(),
                    )
                })?;
                let summary = normalize_long_text(summary)?;
                if summary.len() > LONG_TEXT_FALLBACK_MAX_BYTES {
                    return Err(Error::Protocol(format!(
                        "long_text summary is {} UTF-8 bytes, limit is \
                         {LONG_TEXT_FALLBACK_MAX_BYTES}",
                        summary.len()
                    )));
                }
                summary
            }
        };
        let block = Self::new(ContentBlockKind::LongText, fallback)
            .with_field("format", Value::String(format.as_str().to_owned()))
            .with_field("body_kind", Value::String(body_kind.as_str().to_owned()))
            .with_field("blob_ref", Value::String(blob_ref.into()))
            .with_field("size_bytes", Value::from(normalized.len() as u64))
            .with_field("line_count", Value::from(long_text_line_count(&normalized)))
            .with_field("media_type", Value::String(format.media_type().to_owned()));
        block.validate_long_text()?;
        Ok(block)
    }

    /// Validate an `ak.content.long_text` block against the normative rules that JSON Schema
    /// cannot express: UTF-8 byte bounds, normalization, format / media-type binding,
    /// hash-only Blob refs, the plaintext `size_bytes` / `segment_count` relation and the
    /// mandatory streaming AEAD scheme for the E2EE branch.
    ///
    /// The `>256 KiB` rule itself is not enforced here: section 4.1.4 allows a shorter body when
    /// the full Event would otherwise exceed the 1 MiB envelope limit, and only a full-Event size
    /// validator can prove that exception.
    pub fn validate_long_text(&self) -> Result<()> {
        if self.kind != ContentBlockKind::LongText {
            return Err(Error::Protocol(format!(
                "expected {CONTENT_KIND_LONG_TEXT}, got {}",
                self.kind.as_str()
            )));
        }
        if !self.parts.is_empty() {
            return Err(Error::Protocol(
                "long_text must not carry composite parts".to_owned(),
            ));
        }

        let format = self
            .extra_str("format")
            .and_then(LongTextFormat::parse)
            .ok_or_else(|| {
                Error::Protocol("long_text requires format = plain | markdown".to_owned())
            })?;
        self.extra_str("body_kind")
            .and_then(LongTextBodyKind::parse)
            .ok_or_else(|| {
                Error::Protocol("long_text requires body_kind = prefix | summary".to_owned())
            })?;

        if normalize_long_text(&self.body)? != self.body {
            return Err(Error::Protocol(
                "long_text fallback body is not normalized (BOM, CR or forbidden control character)"
                    .to_owned(),
            ));
        }
        if self.body.len() > LONG_TEXT_FALLBACK_MAX_BYTES {
            return Err(Error::Protocol(format!(
                "long_text fallback body is {} UTF-8 bytes, limit is {LONG_TEXT_FALLBACK_MAX_BYTES}",
                self.body.len()
            )));
        }

        let plaintext_branch = self.extra.contains_key("blob_ref");
        let e2ee_branch = self.extra.contains_key("attachment");
        if plaintext_branch == e2ee_branch {
            return Err(Error::Protocol(
                "long_text requires exactly one of blob_ref (plaintext) and attachment (E2EE)"
                    .to_owned(),
            ));
        }

        // The wire shape is additionalProperties=false, so the branch's field set is closed.
        let allowed: &[&str] = if plaintext_branch {
            &[
                "format",
                "body_kind",
                "blob_ref",
                "size_bytes",
                "line_count",
                "media_type",
            ]
        } else {
            &["format", "body_kind", "line_count", "attachment"]
        };
        if let Some(unknown) = self
            .extra
            .keys()
            .find(|key| !allowed.contains(&key.as_str()))
        {
            return Err(Error::Protocol(format!(
                "long_text does not allow field {unknown:?}"
            )));
        }

        if plaintext_branch {
            let blob_ref = self.extra_str("blob_ref").unwrap_or_default();
            if hash_blob_ref_suite_and_hex(blob_ref).is_none() {
                return Err(Error::Protocol(
                    "long_text blob_ref must be hash-addressed ak:blob:(sha256|blake3):<64 hex>"
                        .to_owned(),
                ));
            }
            if self.extra_u64("size_bytes").is_none() {
                return Err(Error::Protocol(
                    "plaintext long_text requires size_bytes".to_owned(),
                ));
            }
            let media_type = self.extra_str("media_type").unwrap_or_default();
            if media_type != format.media_type() {
                return Err(Error::Protocol(format!(
                    "long_text media_type {media_type:?} does not match format {}",
                    format.as_str()
                )));
            }
        } else {
            let attachment = self
                .extra
                .get("attachment")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    Error::Protocol("E2EE long_text attachment must be an object".to_owned())
                })?;
            let field = |key: &str| {
                attachment
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            };
            if field("scheme") != "ak.blob.stream_aead.v1" {
                return Err(Error::Protocol(
                    "E2EE long_text attachment must use ak.blob.stream_aead.v1".to_owned(),
                ));
            }
            if !field("encryption_algorithm").ends_with("_stream") {
                return Err(Error::Protocol(
                    "E2EE long_text attachment must use the matching _stream AEAD algorithm"
                        .to_owned(),
                ));
            }
            if field("media_type") != format.media_type() {
                return Err(Error::Protocol(format!(
                    "E2EE long_text attachment media_type does not match format {}",
                    format.as_str()
                )));
            }
            let blob_ref = field("blob_ref");
            let Some((suite, hex)) = hash_blob_ref_suite_and_hex(blob_ref) else {
                return Err(Error::Protocol(
                    "E2EE long_text attachment blob_ref must be hash-addressed".to_owned(),
                ));
            };
            if field("ciphertext_digest") != format!("{suite}:{hex}") {
                return Err(Error::Protocol(
                    "E2EE long_text attachment ciphertext_digest must equal the blob_ref digest"
                        .to_owned(),
                ));
            }
            for key in [
                "nonce_prefix",
                "segment_bytes",
                "segment_count",
                "size_bytes",
            ] {
                if !attachment.contains_key(key) {
                    return Err(Error::Protocol(format!(
                        "E2EE long_text attachment requires {key}"
                    )));
                }
            }
            let plaintext_size = attachment.get("size_bytes").and_then(Value::as_u64);
            let segment_bytes = attachment.get("segment_bytes").and_then(Value::as_u64);
            let segment_count = attachment.get("segment_count").and_then(Value::as_u64);
            if let (Some(size), Some(seg), Some(count)) =
                (plaintext_size, segment_bytes, segment_count)
            {
                if seg == 0 {
                    return Err(Error::Protocol(
                        "E2EE long_text attachment segment_bytes must be positive".to_owned(),
                    ));
                }
                let expected = if size == 0 { 1 } else { size.div_ceil(seg) };
                if expected != count {
                    return Err(Error::Protocol(format!(
                        "E2EE long_text attachment segment_count {count} does not equal                          ceil(size_bytes / segment_bytes) = {expected}"
                    )));
                }
            }
        }

        if let Some(declared) = self.extra_u64("line_count")
            && declared == 0
            && !self.body.is_empty()
        {
            return Err(Error::Protocol(
                "long_text line_count of 0 requires an empty body".to_owned(),
            ));
        }

        Ok(())
    }

    /// Validate that an `ak.content.text` block stays inside the inline boundary.
    pub fn validate_inline_text(&self) -> Result<()> {
        if self.kind != ContentBlockKind::Text {
            return Err(Error::Protocol(format!(
                "expected {CONTENT_KIND_TEXT}, got {}",
                self.kind.as_str()
            )));
        }
        if self.body.len() > CONTENT_TEXT_INLINE_MAX_BYTES {
            return Err(Error::Protocol(format!(
                "ak.content.text body is {} UTF-8 bytes, limit is {CONTENT_TEXT_INLINE_MAX_BYTES}; \
                 use {CONTENT_KIND_LONG_TEXT}",
                self.body.len()
            )));
        }
        Ok(())
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
#[serde(deny_unknown_fields)]
pub struct MessageAgentContext {
    pub agent_id: DidCoreId,
    pub operator_or_controller: String,
    pub execution_purpose: String,
    pub authorization_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageCreatePayload {
    pub strand_id: StrandId,
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
    pub mention_sidecar_digest: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_context: Option<MessageAgentContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DisappearingMessageExpiry>,
}

impl MessageCreatePayload {
    pub fn with_protected_content(
        strand_id: StrandId,
        track_name: impl Into<String>,
        protected_content: ProtectedPayload<ContentBlock>,
    ) -> Self {
        match protected_content {
            ProtectedPayload::Plain(content) => {
                Self::with_content(strand_id, track_name, content.into_value())
            }
            ProtectedPayload::Mls(content) => Self::with_encrypted_content_envelope(
                strand_id,
                track_name,
                content.into_envelope(),
            ),
        }
    }

    pub fn with_content(
        strand_id: StrandId,
        track_name: impl Into<String>,
        content: ContentBlock,
    ) -> Self {
        Self {
            strand_id,
            track_name: track_name.into(),
            content: Some(content),
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            blob_refs: Vec::new(),
            mention_sidecar_digest: Vec::new(),
            reply_to: None,
            agent_context: None,
            expiry: None,
        }
    }

    pub fn with_encrypted_content(
        strand_id: StrandId,
        track_name: impl Into<String>,
        encrypted_content: MlsEncryptedPayload<ContentBlock>,
    ) -> Self {
        Self::with_encrypted_content_envelope(
            strand_id,
            track_name,
            encrypted_content.into_envelope(),
        )
    }

    fn with_encrypted_content_envelope(
        strand_id: StrandId,
        track_name: impl Into<String>,
        encrypted_content: EncryptedEnvelope,
    ) -> Self {
        Self {
            strand_id,
            track_name: track_name.into(),
            content: None,
            encrypted_content: Some(encrypted_content),
            metadata: None,
            encrypted_metadata: None,
            blob_refs: Vec::new(),
            mention_sidecar_digest: Vec::new(),
            reply_to: None,
            agent_context: None,
            expiry: None,
        }
    }

    pub fn with_mls_encrypted_content(
        strand_id: StrandId,
        track_name: impl Into<String>,
        encrypted_content: MlsEncryptedPayload<ContentBlock>,
    ) -> Self {
        Self::with_encrypted_content(strand_id, track_name, encrypted_content)
    }

    pub fn protected_content(&self) -> Result<ProtectedPayload<ContentBlock>> {
        match (&self.content, &self.encrypted_content) {
            (Some(content), None) => Ok(PlainPayload::new(content.clone()).into()),
            (None, Some(content)) => Ok(MlsEncryptedPayload::new(content.clone())?.into()),
            (None, None) => Err(Error::Protocol(
                "message create payload requires content or encrypted_content".to_owned(),
            )),
            (Some(_), Some(_)) => Err(Error::Protocol(
                "message create payload must not carry both content and encrypted_content"
                    .to_owned(),
            )),
        }
    }

    pub fn with_protected_metadata(
        mut self,
        protected_metadata: ProtectedPayload<MessageMetadata>,
    ) -> Self {
        match protected_metadata {
            ProtectedPayload::Plain(metadata) => {
                self.metadata = Some(metadata.into_value());
                self.encrypted_metadata = None;
            }
            ProtectedPayload::Mls(metadata) => {
                self.metadata = None;
                self.encrypted_metadata = Some(metadata.into_envelope());
            }
        }
        self
    }

    pub fn with_mls_encrypted_metadata(
        self,
        encrypted_metadata: MlsEncryptedPayload<MessageMetadata>,
    ) -> Self {
        self.with_protected_metadata(encrypted_metadata.into())
    }

    pub fn protected_metadata(&self) -> Result<Option<ProtectedPayload<MessageMetadata>>> {
        match (&self.metadata, &self.encrypted_metadata) {
            (Some(metadata), None) => Ok(Some(PlainPayload::new(metadata.clone()).into())),
            (None, Some(metadata)) => Ok(Some(MlsEncryptedPayload::new(metadata.clone())?.into())),
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Err(Error::Protocol(
                "message create payload must not carry both metadata and encrypted_metadata"
                    .to_owned(),
            )),
        }
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

/// Structural error surfaced by the content-block validators.
///
/// A distinct, allocation-free error type so the validators do not couple to
/// the crate-wide [`Error`]; callers that need to bridge into a facade map it
/// explicitly.
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

impl std::fmt::Display for ContentBlockValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    if object.contains_key("blocks") {
        return Err(ContentBlockValidationError::new(
            "content.blocks is not permitted; use content.parts",
        ));
    }
    let parsed = ContentBlock::from_value(block.clone())
        .map_err(|_| ContentBlockValidationError::new("content block is invalid"))?;
    match parsed.kind {
        ContentBlockKind::Composite => validate_composite_content_block(block),
        ContentBlockKind::Text | ContentBlockKind::FormattedText => {
            validate_text_content_block(block)
        }
        ContentBlockKind::LongText => ContentBlock::from_value(block.clone())
            .and_then(|parsed| parsed.validate_long_text())
            .map_err(|_| ContentBlockValidationError::new("long text content block is invalid")),
        ContentBlockKind::Code => validate_code_content_block(block),
        ContentBlockKind::Image
        | ContentBlockKind::Video
        | ContentBlockKind::Audio
        | ContentBlockKind::File => validate_media_content_block(block),
        ContentBlockKind::Location => validate_location_content_block(block),
        ContentBlockKind::Poll => validate_poll_content_block(block),
        ContentBlockKind::PollResponse => validate_poll_response_content_block(block),
        ContentBlockKind::PollClose => validate_poll_close_content_block(block),
        ContentBlockKind::AudienceMention => {
            serde_json::from_value::<AudienceMention>(block.clone())
                .map(|_| ())
                .map_err(|_| ContentBlockValidationError::new("audience mention is invalid"))
        }
    }
}

fn validate_text_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    if !content_block_has_text(block) {
        return Err(ContentBlockValidationError::new(
            "text content block requires text",
        ));
    }
    Ok(())
}

fn validate_code_content_block(block: &Value) -> ContentBlockValidationResult<()> {
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

fn validate_poll_close_content_block(block: &Value) -> ContentBlockValidationResult<()> {
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
        .is_some_and(|value| value.starts_with("ak:blob:sha256:"));
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
            .is_some_and(content_block_has_text_value);
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
