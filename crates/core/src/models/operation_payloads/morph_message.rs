//! Message-create payload and content-block validation retained by
//! `arkret-core`.
//!
//! The `ContentBlock` wire family, morph-update payload, and
//! disappearing-message expiry types migrated to
//! `arkret-models-collaboration` (re-exported below).
//! [`MessageCreatePayload`] stays because it embeds the (not yet
//! migrated) `MessageMetadata` strand projection; the content-block
//! validators stay because they consume the `PollBlock` /
//! `PollResponseBlock` artifacts types.

use std::fmt;

pub use arkret_models_collaboration::events_payloads::morph_message::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

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
