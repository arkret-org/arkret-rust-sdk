//! Message-create payload and content-block validation retained by
//! `arkret-core`.
//!
//! The `ContentBlock` wire family, `MessageCreatePayload`, morph-update
//! payload, and disappearing-message expiry types migrated to
//! `arkret-models-collaboration` (re-exported below). The content-block
//! validators stay because they consume the `PollBlock` /
//! `PollResponseBlock` artifacts types.

use std::fmt;

pub use arkret_models_collaboration::events_payloads::morph_message::*;
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
