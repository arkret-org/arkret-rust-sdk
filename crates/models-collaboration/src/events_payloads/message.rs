//! Message and content-block event payloads.

use std::collections::BTreeMap;

use arkret_models_crypto::{
    EncryptedEnvelope, MlsEncryptedPayload, MlsPayloadType, PlainPayload, ProtectedPayload,
};
use arkret_wire::{DidCoreId, EventId, Result, StrandId, WireError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::mention::{AudienceMention, Mention};
use crate::events_payloads::poll::{PollBlock, PollResponseBlock};
use crate::internal_prelude::*;
use crate::objects::strand::MessageMetadata;

/// Canonical decrypted media type for an MLS-protected message ContentBlock.
pub const MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE: &str = "application/vnd.arkret.message+json";

/// Canonical decrypted media type for MLS-protected Message metadata.
pub const MESSAGE_METADATA_MLS_CONTENT_TYPE: &str = "application/vnd.arkret.message-metadata+json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageTrackName {
    Discussion,
}

/// Auditable attribution for a message authored by a MIMI facade service.
///
/// The Event actor remains the facade service DID. These fields attribute the
/// external sender without granting that sender's authority to the facade.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiMessageProvenance {
    pub provenance: MimiMessageProvenanceKind,
    pub source_provider_id: DidCoreId,
    pub attributed_sender_actor_id: ActorId,
    pub attributed_sender_device_id: DeviceId,
    pub source_envelope_digest: Hash,
    pub room_binding_ref: EventId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MimiMessageProvenanceKind {
    #[serde(rename = "mimi_facade")]
    MimiFacade,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_redact_payload`.
///
/// `message_id` is the single target carrier: the registered
/// `ak.component.object.redaction.v1` cell subject is that typed Message ID, so
/// the same Message cannot be addressed two ways.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRedactPayload {
    pub message_id: MessageId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<MessageTrackName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preserve: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_provenance: Option<MimiMessageProvenance>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_revise_payload`.
///
/// `message_id` is the single target carrier: the registered
/// `ak.component.message.revision.v1` cell subject is that typed Message ID.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRevisePayload {
    pub message_id: MessageId,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_provenance: Option<MimiMessageProvenance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageRevisePayloadWire {
    message_id: MessageId,
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
    #[serde(default)]
    mimi_provenance: Option<MimiMessageProvenance>,
}

impl<'de> Deserialize<'de> for MessageRevisePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MessageRevisePayloadWire::deserialize(deserializer)?;
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
            track_name: wire.track_name,
            content: wire.content,
            encrypted_content: wire.encrypted_content,
            metadata: wire.metadata,
            encrypted_metadata: wire.encrypted_metadata,
            reason: wire.reason,
            mimi_provenance: wire.mimi_provenance,
        })
    }
}

pub const CONTENT_KIND_COMPOSITE: &str = "ak.content.composite";
pub const CONTENT_KIND_TEXT: &str = "ak.content.text";
pub const CONTENT_KIND_LONG_TEXT: &str = "ak.content.long_text";
pub const CONTENT_KIND_CODE: &str = "ak.content.code";
pub const CONTENT_KIND_IMAGE: &str = "ak.content.image";
pub const CONTENT_KIND_VIDEO: &str = "ak.content.video";
pub const CONTENT_KIND_AUDIO: &str = "ak.content.audio";
pub const CONTENT_KIND_FILE: &str = "ak.content.file";
pub const CONTENT_KIND_LOCATION: &str = "ak.content.location";
pub const CONTENT_KIND_POLL: &str = "ak.content.poll";
pub const CONTENT_KIND_POLL_RESPONSE: &str = "ak.content.poll.response";

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
        Self::text_with_format(body, TextFormat::Plain)
    }

    /// Build an `ak.content.text` block with an explicit, closed-set format.
    pub fn text_with_format(body: impl Into<String>, format: TextFormat) -> Self {
        Self::new(ContentBlockKind::Text, body)
            .with_field("format", Value::String(format.as_str().to_owned()))
    }

    /// Build an `ak.content.text` block whose body is Markdown source.
    pub fn markdown_text(body: impl Into<String>) -> Self {
        Self::text_with_format(body, TextFormat::Markdown)
    }

    /// Read the declared format of an `ak.content.text` block.
    ///
    /// `None` covers both non-text blocks and valid remote text blocks that
    /// omit the protocol's SHOULD-level discriminator.
    pub fn text_format(&self) -> Option<TextFormat> {
        (self.kind == ContentBlockKind::Text)
            .then(|| self.extra_str("format").and_then(TextFormat::parse))
            .flatten()
    }

    pub fn formatted_body(&self) -> Option<&Value> {
        self.extra.get("formatted_body")
    }

    pub fn from_value(value: Value) -> Result<Self> {
        serde_json::from_value(value)
            .map_err(|err| WireError::Protocol(format!("content block decode: {err}")))
    }

    pub fn with_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn with_mentions(mut self, mentions: Vec<Mention>) -> Result<Self> {
        let value = serde_json::to_value(mentions)
            .map_err(|err| WireError::Protocol(format!("content mentions serialize: {err}")))?;
        self.extra.insert("mentions".to_owned(), value);
        Ok(self)
    }

    pub fn with_audience_mentions(
        mut self,
        audience_mentions: Vec<AudienceMention>,
    ) -> Result<Self> {
        let value = serde_json::to_value(audience_mentions).map_err(|err| {
            WireError::Protocol(format!("content audience_mentions serialize: {err}"))
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
            .map_err(|err| WireError::Protocol(format!("content block serialize: {err}")))
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
    Code,
    Image,
    Video,
    Audio,
    File,
    Location,
    Poll,
    PollResponse,
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
            CONTENT_KIND_CODE => Some(Self::Code),
            CONTENT_KIND_IMAGE => Some(Self::Image),
            CONTENT_KIND_VIDEO => Some(Self::Video),
            CONTENT_KIND_AUDIO => Some(Self::Audio),
            CONTENT_KIND_FILE => Some(Self::File),
            CONTENT_KIND_LOCATION => Some(Self::Location),
            CONTENT_KIND_POLL => Some(Self::Poll),
            CONTENT_KIND_POLL_RESPONSE => Some(Self::PollResponse),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Composite => CONTENT_KIND_COMPOSITE,
            Self::Text => CONTENT_KIND_TEXT,
            Self::LongText => CONTENT_KIND_LONG_TEXT,
            Self::Code => CONTENT_KIND_CODE,
            Self::Image => CONTENT_KIND_IMAGE,
            Self::Video => CONTENT_KIND_VIDEO,
            Self::Audio => CONTENT_KIND_AUDIO,
            Self::File => CONTENT_KIND_FILE,
            Self::Location => CONTENT_KIND_LOCATION,
            Self::Poll => CONTENT_KIND_POLL,
            Self::PollResponse => CONTENT_KIND_POLL_RESPONSE,
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

/// Closed `format` set for `ak.content.text`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextFormat {
    Plain,
    Markdown,
    ProsemirrorJson,
}

impl TextFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Markdown => "markdown",
            Self::ProsemirrorJson => "prosemirror_json",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Self::Plain),
            "markdown" => Some(Self::Markdown),
            "prosemirror_json" => Some(Self::ProsemirrorJson),
            _ => None,
        }
    }
}

/// Closed full-body media types for `ak.content.long_text`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LongTextMediaType {
    #[serde(rename = "text/plain")]
    Plain,
    #[serde(rename = "text/markdown")]
    Markdown,
}

impl LongTextMediaType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "text/plain",
            Self::Markdown => "text/markdown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text/plain" => Some(Self::Plain),
            "text/markdown" => Some(Self::Markdown),
            _ => None,
        }
    }

    /// Local rendering choice; never serialized as a long-text `format` field.
    pub fn text_format(self) -> TextFormat {
        match self {
            Self::Plain => TextFormat::Plain,
            Self::Markdown => TextFormat::Markdown,
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
        return Err(WireError::Protocol(
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
                return Err(WireError::Protocol(format!(
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
    /// Read the full-body media type from the sole carrier for the selected branch.
    pub fn long_text_media_type(&self) -> Option<LongTextMediaType> {
        if self.kind != ContentBlockKind::LongText {
            return None;
        }
        match (
            self.extra.contains_key("blob_ref"),
            self.extra.get("attachment"),
        ) {
            (true, None) => self
                .extra_str("media_type")
                .and_then(LongTextMediaType::parse),
            (false, Some(attachment)) => attachment
                .get("media_type")
                .and_then(Value::as_str)
                .and_then(LongTextMediaType::parse),
            _ => None,
        }
    }

    /// Build the plaintext branch of `ak.content.long_text` from the complete
    /// source body and the hash-addressed Blob ref returned by its upload.
    ///
    /// The body is normalized before all derived fields are computed. Prefix
    /// mode derives the longest scalar-safe 4 KiB prefix; summary mode requires
    /// an explicit summary and normalizes it independently.
    pub fn plaintext_long_text(
        full_body: &str,
        media_type: LongTextMediaType,
        blob_ref: impl Into<String>,
        body_kind: LongTextBodyKind,
        summary: Option<&str>,
    ) -> Result<Self> {
        let normalized = normalize_long_text(full_body)?;
        let fallback = match body_kind {
            LongTextBodyKind::Prefix => long_text_prefix(&normalized).to_owned(),
            LongTextBodyKind::Summary => {
                let summary = summary.ok_or_else(|| {
                    WireError::Protocol(
                        "long_text body_kind=summary requires an explicit summary".to_owned(),
                    )
                })?;
                let summary = normalize_long_text(summary)?;
                if summary.len() > LONG_TEXT_FALLBACK_MAX_BYTES {
                    return Err(WireError::Protocol(format!(
                        "long_text summary is {} UTF-8 bytes, limit is \
                         {LONG_TEXT_FALLBACK_MAX_BYTES}",
                        summary.len()
                    )));
                }
                summary
            }
        };
        let block = Self::new(ContentBlockKind::LongText, fallback)
            .with_field("body_kind", Value::String(body_kind.as_str().to_owned()))
            .with_field("blob_ref", Value::String(blob_ref.into()))
            .with_field("size_bytes", Value::from(normalized.len() as u64))
            .with_field("line_count", Value::from(long_text_line_count(&normalized)))
            .with_field("media_type", Value::String(media_type.as_str().to_owned()));
        block.validate_long_text()?;
        Ok(block)
    }

    /// Validate an `ak.content.long_text` block against the normative rules that JSON Schema
    /// cannot express: UTF-8 byte bounds, normalization,
    /// hash-only Blob refs, the streaming descriptor shape and the
    /// mandatory streaming AEAD scheme for the E2EE branch.
    ///
    /// The `>256 KiB` rule itself is not enforced here: section 4.1.4 allows a shorter body when
    /// the full Event would otherwise exceed the 1 MiB envelope limit, and only a full-Event size
    /// validator can prove that exception.
    pub fn validate_long_text(&self) -> Result<()> {
        if self.kind != ContentBlockKind::LongText {
            return Err(WireError::Protocol(format!(
                "expected {CONTENT_KIND_LONG_TEXT}, got {}",
                self.kind.as_str()
            )));
        }
        if !self.parts.is_empty() {
            return Err(WireError::Protocol(
                "long_text must not carry composite parts".to_owned(),
            ));
        }

        self.extra_str("body_kind")
            .and_then(LongTextBodyKind::parse)
            .ok_or_else(|| {
                WireError::Protocol("long_text requires body_kind = prefix | summary".to_owned())
            })?;

        if normalize_long_text(&self.body)? != self.body {
            return Err(WireError::Protocol(
                "long_text fallback body is not normalized (BOM, CR or forbidden control character)"
                    .to_owned(),
            ));
        }
        if self.body.len() > LONG_TEXT_FALLBACK_MAX_BYTES {
            return Err(WireError::Protocol(format!(
                "long_text fallback body is {} UTF-8 bytes, limit is {LONG_TEXT_FALLBACK_MAX_BYTES}",
                self.body.len()
            )));
        }

        let plaintext_branch = self.extra.contains_key("blob_ref");
        let e2ee_branch = self.extra.contains_key("attachment");
        if plaintext_branch == e2ee_branch {
            return Err(WireError::Protocol(
                "long_text requires exactly one of blob_ref (plaintext) and attachment (E2EE)"
                    .to_owned(),
            ));
        }

        // The wire shape is additionalProperties=false, so the branch's field set is closed.
        let allowed: &[&str] = if plaintext_branch {
            &[
                "body_kind",
                "blob_ref",
                "size_bytes",
                "line_count",
                "media_type",
            ]
        } else {
            &["body_kind", "line_count", "attachment"]
        };
        if let Some(unknown) = self
            .extra
            .keys()
            .find(|key| !allowed.contains(&key.as_str()))
        {
            return Err(WireError::Protocol(format!(
                "long_text does not allow field {unknown:?}"
            )));
        }

        self.long_text_media_type().ok_or_else(|| {
            WireError::Protocol(
                "long_text requires media_type = text/plain | text/markdown in its body descriptor"
                    .to_owned(),
            )
        })?;

        if plaintext_branch {
            let blob_ref = self.extra_str("blob_ref").unwrap_or_default();
            if hash_blob_ref_suite_and_hex(blob_ref).is_none() {
                return Err(WireError::Protocol(
                    "long_text blob_ref must be hash-addressed ak:blob:(sha256|blake3):<64 hex>"
                        .to_owned(),
                ));
            }
            if self.extra_u64("size_bytes").is_none() {
                return Err(WireError::Protocol(
                    "plaintext long_text requires size_bytes".to_owned(),
                ));
            }
        } else {
            let attachment = self
                .extra
                .get("attachment")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    WireError::Protocol("E2EE long_text attachment must be an object".to_owned())
                })?;
            let field = |key: &str| {
                attachment
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            };
            if field("scheme") != "ak.blob.stream_aead.v1" {
                return Err(WireError::Protocol(
                    "E2EE long_text attachment must use ak.blob.stream_aead.v1".to_owned(),
                ));
            }
            if !field("encryption_algorithm").ends_with("_stream") {
                return Err(WireError::Protocol(
                    "E2EE long_text attachment must use the matching _stream AEAD algorithm"
                        .to_owned(),
                ));
            }
            let blob_ref = field("blob_ref");
            if hash_blob_ref_suite_and_hex(blob_ref).is_none() {
                return Err(WireError::Protocol(
                    "E2EE long_text attachment blob_ref must be hash-addressed".to_owned(),
                ));
            }
            const STREAM_ATTACHMENT_FIELDS: &[&str] = &[
                "blob_ref",
                "encrypted",
                "scheme",
                "encryption_algorithm",
                "key_ref",
                "size_bytes",
                "media_type",
                "nonce_prefix",
                "segment_bytes",
            ];
            if let Some(unknown) = attachment
                .keys()
                .find(|key| !STREAM_ATTACHMENT_FIELDS.contains(&key.as_str()))
            {
                return Err(WireError::Protocol(format!(
                    "E2EE long_text attachment does not allow field {unknown:?}"
                )));
            }
            for key in ["nonce_prefix", "segment_bytes", "size_bytes"] {
                if !attachment.contains_key(key) {
                    return Err(WireError::Protocol(format!(
                        "E2EE long_text attachment requires {key}"
                    )));
                }
            }
            let segment_bytes = attachment.get("segment_bytes").and_then(Value::as_u64);
            if segment_bytes == Some(0) {
                return Err(WireError::Protocol(
                    "E2EE long_text attachment segment_bytes must be positive".to_owned(),
                ));
            }
        }

        if let Some(declared) = self.extra_u64("line_count")
            && declared == 0
            && !self.body.is_empty()
        {
            return Err(WireError::Protocol(
                "long_text line_count of 0 requires an empty body".to_owned(),
            ));
        }

        Ok(())
    }

    /// Validate that an `ak.content.text` block stays inside the inline boundary.
    pub fn validate_inline_text(&self) -> Result<()> {
        if self.kind != ContentBlockKind::Text {
            return Err(WireError::Protocol(format!(
                "expected {CONTENT_KIND_TEXT}, got {}",
                self.kind.as_str()
            )));
        }
        if self.body.len() > CONTENT_TEXT_INLINE_MAX_BYTES {
            return Err(WireError::Protocol(format!(
                "ak.content.text body is {} UTF-8 bytes, limit is {CONTENT_TEXT_INLINE_MAX_BYTES}; \
                 use {CONTENT_KIND_LONG_TEXT}",
                self.body.len()
            )));
        }
        if let Some(raw_format) = self.extra_str("format")
            && TextFormat::parse(raw_format).is_none()
        {
            return Err(WireError::Protocol(
                "ak.content.text format must be plain | markdown | prosemirror_json".to_owned(),
            ));
        }
        if self.text_format() == Some(TextFormat::Plain) && self.formatted_body().is_some() {
            return Err(WireError::Protocol(
                "ak.content.text format=plain must not carry formatted_body".to_owned(),
            ));
        }
        if self
            .formatted_body()
            .is_some_and(|value| !value.is_string() && !value.is_object())
        {
            return Err(WireError::Protocol(
                "ak.content.text formatted_body must be a string or object".to_owned(),
            ));
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

/// A producer-visible replacement declaration for one accepted poll response.
/// The governance Station verifies both Event refs against the same poll,
/// actor and effective scope; this pair is not a vote-winner selector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResponseHead {
    pub poll_event_ref: EventId,
    pub response_event_ref: EventId,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_context: Option<MessageAgentContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimi_provenance: Option<MimiMessageProvenance>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_poll_response_heads"
    )]
    pub poll_response_heads: Vec<PollResponseHead>,
}

fn poll_response_heads_valid(heads: &[PollResponseHead]) -> bool {
    !heads.is_empty()
        && heads.len() <= 64
        && !heads
            .iter()
            .enumerate()
            .any(|(index, head)| heads[..index].contains(head))
}

fn deserialize_poll_response_heads<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<PollResponseHead>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let heads = Vec::<PollResponseHead>::deserialize(deserializer)?;
    if !poll_response_heads_valid(&heads) {
        return Err(serde::de::Error::custom(
            "poll_response_heads must contain 1..64 unique entries when present",
        ));
    }
    Ok(heads)
}

impl MessageCreatePayload {
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
            reply_to_id: None,
            agent_context: None,
            mimi_provenance: None,
            poll_response_heads: Vec::new(),
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
            reply_to_id: None,
            agent_context: None,
            mimi_provenance: None,
            poll_response_heads: Vec::new(),
        }
    }

    /// Bind the exact accepted response Events this message supersedes.
    /// An empty declaration is represented by omission on the wire.
    pub fn with_poll_response_heads(mut self, heads: Vec<PollResponseHead>) -> Result<Self> {
        if self.encrypted_content.is_some() && !heads.is_empty() {
            return Err(WireError::Protocol(
                "encrypted messages cannot carry poll_response_heads in v1".to_owned(),
            ));
        }
        if !heads.is_empty() && !poll_response_heads_valid(&heads) {
            return Err(WireError::Protocol(
                "poll_response_heads must be unique and contain at most 64 entries".to_owned(),
            ));
        }
        self.poll_response_heads = heads;
        Ok(self)
    }

    pub fn validate_poll_response_heads(&self) -> Result<()> {
        if self.encrypted_content.is_some() && !self.poll_response_heads.is_empty() {
            return Err(WireError::Protocol(
                "encrypted messages cannot carry poll_response_heads in v1".to_owned(),
            ));
        }
        if self.poll_response_heads.is_empty()
            || poll_response_heads_valid(&self.poll_response_heads)
        {
            Ok(())
        } else {
            Err(WireError::Protocol(
                "poll_response_heads must be unique and contain at most 64 entries".to_owned(),
            ))
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
            (None, None) => Err(WireError::Protocol(
                "message create payload requires content or encrypted_content".to_owned(),
            )),
            (Some(_), Some(_)) => Err(WireError::Protocol(
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
            (Some(_), Some(_)) => Err(WireError::Protocol(
                "message create payload must not carry both metadata and encrypted_metadata"
                    .to_owned(),
            )),
        }
    }

    pub fn with_reply_to_id(mut self, reply_to_id: impl Into<String>) -> Self {
        self.reply_to_id = Some(reply_to_id.into());
        self
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
        self.validate_poll_response_heads()?;
        if self.metadata.is_some() && self.encrypted_metadata.is_some() {
            return Err(WireError::Protocol(
                "message create payload must not carry both metadata and encrypted_metadata"
                    .to_owned(),
            ));
        }
        match (self.content.is_some(), self.encrypted_content.is_some()) {
            (true, false) | (false, true) => serde_json::to_value(self).map_err(|err| {
                WireError::Protocol(format!("message create payload serialize: {err}"))
            }),
            (false, false) => Err(WireError::Protocol(
                "message create payload requires content or encrypted_content".to_owned(),
            )),
            (true, true) => Err(WireError::Protocol(
                "message create payload must not carry both content and encrypted_content"
                    .to_owned(),
            )),
        }
    }
}

/// Structural error surfaced by the content-block validators.
///
/// A distinct, allocation-free error type so the validators do not couple to
/// the shared [`arkret_wire::WireError`]; callers that need to bridge into a facade map it
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
    crate::events_payloads::mention::validate_mention_carriers(object)?;
    match parsed.kind {
        ContentBlockKind::Composite => validate_composite_content_block(block),
        ContentBlockKind::Text => validate_text_content_block(block),
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
    }
}

fn validate_text_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    if !content_block_has_text(block) {
        return Err(ContentBlockValidationError::new(
            "text content block requires text",
        ));
    }
    ContentBlock::from_value(block.clone())
        .and_then(|parsed| parsed.validate_inline_text())
        .map_err(|_| ContentBlockValidationError::new("text content block is invalid"))
}

fn validate_code_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    if block
        .get("body")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(ContentBlockValidationError::new(
            "code content block requires text",
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
    let poll = serde_json::from_value::<PollBlock>(block.clone())
        .map_err(|_| ContentBlockValidationError::new("invalid Poll content block"))?;
    poll.validate()
}

fn validate_poll_response_content_block(block: &Value) -> ContentBlockValidationResult<()> {
    let response = serde_json::from_value::<PollResponseBlock>(block.clone())
        .map_err(|_| ContentBlockValidationError::new("invalid Poll response block"))?;
    response.validate()
}

fn content_block_has_text(block: &Value) -> bool {
    block.as_str().is_some_and(|value| !value.trim().is_empty())
        || block
            .get("body")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
}

fn json_integer(value: &Value) -> bool {
    value.is_i64() || value.is_u64()
}
