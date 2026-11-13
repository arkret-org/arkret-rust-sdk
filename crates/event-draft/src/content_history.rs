//! Registered historical key slots, rooted at the immutable original Event.

use arkret_models_collaboration::events_payloads::ContentBlock;
use arkret_models_crypto::{EncryptedAttachment, HistoryKeySelector};
use arkret_wire::{Event, Result, WireError};

use crate::{EventContentEnvelope, EventContentEnvelopesExt, content_block_plaintext};

fn attachment_suffix(remaining: &[String]) -> Result<()> {
    match remaining {
        [field, position, rest @ ..] if field == "parts" => {
            index(position)?;
            attachment_suffix(rest)
        }
        [field] if field == "attachment" => Ok(()),
        [field, position] if field == "attachments" => {
            index(position)?;
            Ok(())
        }
        _ => Err(invalid(
            "history pointer does not select a registered complete attachment",
        )),
    }
}

/// Public structural admission only. Descendants of ciphertext still require
/// independent parent authentication and exact descriptor validation at both
/// key-producing and receiving endpoints.
pub fn history_content_key_width(original: &Event, content_path: &str) -> Result<usize> {
    HistoryKeySelector::ContentKey {
        source_event_ref: original.event_id.clone(),
        content_path: content_path.into(),
    }
    .validate()?;
    let target = tokens(content_path)?;
    for slot in original.event_content_envelopes()? {
        if slot.content_path == content_path {
            return Ok(16);
        }
        if content_path.starts_with(&(slot.content_path.clone() + "/")) {
            if slot.envelope.content_type
                != <ContentBlock as arkret_models_crypto::MlsPayloadType>::MLS_CONTENT_TYPE
            {
                return Err(invalid(
                    "history parent content type is not registered ContentBlock",
                ));
            }
            attachment_suffix(&target[tokens(&slot.content_path)?.len()..])?;
            return Ok(32);
        }
    }
    match select_history_content(original, content_path, |_| {
        Err(invalid("history parent key is absent"))
    })? {
        HistoryContentSelection::Envelope(_) => Ok(16),
        HistoryContentSelection::Attachment { .. } => Ok(32),
    }
}

/// A local selection, not a replacement for the original or its authority.
#[derive(Clone, Debug, PartialEq)]
pub enum HistoryContentSelection {
    Envelope(EventContentEnvelope),
    Attachment {
        content_path: String,
        descriptor: EncryptedAttachment,
        parent: Option<EventContentEnvelope>,
    },
}

fn invalid(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

fn tokens(path: &str) -> Result<Vec<String>> {
    let raw = path
        .strip_prefix('/')
        .ok_or_else(|| invalid("history selection requires a JSON pointer"))?;
    raw.split('/')
        .map(|segment| {
            let mut output = String::new();
            let mut chars = segment.chars();
            while let Some(value) = chars.next() {
                output.push(match value {
                    '~' => match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err(invalid("history pointer escape is invalid")),
                    },
                    other => other,
                });
            }
            Ok(output)
        })
        .collect()
}

fn index(value: &str) -> Result<usize> {
    let index: usize = value
        .parse()
        .map_err(|_| invalid("history array index is invalid"))?;
    if value != index.to_string() {
        return Err(invalid("history array index is not canonical"));
    }
    Ok(index)
}

fn attachment_in_block(block: &ContentBlock, remaining: &[String]) -> Result<EncryptedAttachment> {
    // Validate the registered descriptor collection and conflicting resources
    // before selecting one exact original array position.
    block.encrypted_attachments()?;
    match remaining {
        [field, position, rest @ ..] if field == "parts" => {
            let part = block
                .parts
                .get(index(position)?)
                .ok_or_else(|| invalid("history ContentBlock part is absent"))?;
            attachment_in_block(part, rest)
        }
        [field] if field == "attachment" => block
            .extra
            .get("attachment")
            .cloned()
            .ok_or_else(|| invalid("history attachment is absent"))
            .and_then(|value| serde_json::from_value(value).map_err(Into::into)),
        [field, position] if field == "attachments" => {
            let values = block
                .extra
                .get("attachments")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| invalid("history attachment array is absent"))?;
            let value = values
                .get(index(position)?)
                .ok_or_else(|| invalid("history attachment position is absent"))?;
            Ok(serde_json::from_value(value.clone())?)
        }
        _ => Err(invalid(
            "history pointer does not select a registered complete key slot",
        )),
    }
}

fn original_plain_block(
    original: &Event,
    path: &str,
    value: &serde_json::Value,
) -> Result<Option<ContentBlock>> {
    let segments = tokens(path)?;
    if let [payload, patch, field] = segments.as_slice()
        && payload == "payload"
        && patch == "patch"
        && let Some(raw) = original.payload.get("patch")
    {
        let operations: arkret_wire::patch::Patch = serde_json::from_value(raw.clone())?;
        if operations.iter().any(|(name, operation)| {
            name == field && matches!(operation, arkret_wire::patch::PatchOp::Explicit { .. })
        }) {
            return Ok(None);
        }
    }
    content_block_plaintext(
        &original.kind,
        path,
        &arkret_canonical::canonical_json_bytes(value)?,
    )
}

/// Resolve a selector against an already authenticated immutable original.
/// `open_parent` must independently authenticate Context, commitment and AEAD
/// with a separately authorized parent key. A child selector grants no parent.
pub fn select_history_content(
    original: &Event,
    content_path: &str,
    mut open_parent: impl FnMut(&EventContentEnvelope) -> Result<Vec<u8>>,
) -> Result<HistoryContentSelection> {
    HistoryKeySelector::ContentKey {
        source_event_ref: original.event_id.clone(),
        content_path: content_path.to_owned(),
    }
    .validate()?;
    let target = tokens(content_path)?;
    for slot in original.event_content_envelopes()? {
        if content_path == slot.content_path {
            return Ok(HistoryContentSelection::Envelope(slot));
        }
        if content_path.starts_with(&(slot.content_path.clone() + "/")) {
            if slot.envelope.content_type
                != <ContentBlock as arkret_models_crypto::MlsPayloadType>::MLS_CONTENT_TYPE
            {
                return Err(invalid(
                    "history parent content type is not registered ContentBlock",
                ));
            }
            attachment_suffix(&target[tokens(&slot.content_path)?.len()..])?;
            let plaintext = open_parent(&slot)?;
            let value =
                arkret_canonical::canonical::parse_json_rejecting_duplicate_keys(&plaintext)?;
            let canonical = arkret_canonical::canonical_json_bytes(&value)?;
            let block = content_block_plaintext(&original.kind, &slot.content_path, &canonical)?
                .ok_or_else(|| invalid("history parent is not a registered ContentBlock"))?;
            let parent_tokens = tokens(&slot.content_path)?;
            let descriptor = attachment_in_block(&block, &target[parent_tokens.len()..])?;
            return Ok(HistoryContentSelection::Attachment {
                content_path: content_path.to_owned(),
                descriptor,
                parent: Some(slot),
            });
        }
    }
    // A plaintext ContentBlock is authenticated by the original Event itself.
    // Only registered carrier paths are considered, never extension-shaped JSON.
    let raw = serde_json::to_value(original)?;
    let mut prefix = String::new();
    for (offset, token) in target.iter().enumerate() {
        prefix.push('/');
        prefix.push_str(&token.replace('~', "~0").replace('/', "~1"));
        let Some(value) = raw.pointer(&prefix) else {
            break;
        };
        if let Some(block) = original_plain_block(original, &prefix, value)? {
            let descriptor = attachment_in_block(&block, &target[offset + 1..])?;
            return Ok(HistoryContentSelection::Attachment {
                content_path: content_path.to_owned(),
                descriptor,
                parent: None,
            });
        }
    }
    Err(invalid("history source has no registered selected content"))
}

/// Enumerate descriptor positions without changing the authenticated view.
pub fn history_attachment_slots(
    block: &ContentBlock,
    content_path: &str,
) -> Result<Vec<(String, EncryptedAttachment)>> {
    fn collect(
        block: &ContentBlock,
        path: &str,
        output: &mut Vec<(String, EncryptedAttachment)>,
    ) -> Result<()> {
        if let Some(value) = block.extra.get("attachment") {
            output.push((
                format!("{path}/attachment"),
                serde_json::from_value(value.clone())?,
            ));
        }
        if let Some(values) = block.extra.get("attachments") {
            let values = values
                .as_array()
                .ok_or_else(|| invalid("history attachments are not an array"))?;
            for (index, value) in values.iter().enumerate() {
                output.push((
                    format!("{path}/attachments/{index}"),
                    serde_json::from_value(value.clone())?,
                ));
            }
        }
        for (index, part) in block.parts.iter().enumerate() {
            collect(part, &format!("{path}/parts/{index}"), output)?;
        }
        Ok(())
    }
    block.encrypted_attachments()?;
    let mut output = Vec::new();
    collect(block, content_path, &mut output)?;
    Ok(output)
}

/// Original plaintext ContentBlocks at registered Event carrier paths only.
pub fn event_plain_content_blocks(original: &Event) -> Result<Vec<(String, ContentBlock)>> {
    let encrypted = original.event_content_envelopes()?;
    let raw = serde_json::to_value(original)?;
    let mut pending = vec![(String::new(), &raw)];
    let mut output = Vec::new();
    while let Some((path, value)) = pending.pop() {
        if encrypted.iter().any(|slot| slot.content_path == path) {
            continue;
        }
        if path.starts_with("/payload") {
            if let Some(block) = original_plain_block(original, &path, value)? {
                output.push((path, block));
                continue;
            }
        }
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    pending.push((
                        format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                        value,
                    ));
                }
            }
            serde_json::Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    pending.push((format!("{path}/{index}"), value));
                }
            }
            _ => {}
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
