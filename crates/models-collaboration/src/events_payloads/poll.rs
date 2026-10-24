//! Content-block poll wire shapes.
//!
//! Counterparts for `spec/v1/artifacts/schemas/content-block-poll.schema.json`.
//! Migrated from the `arkret` umbrella (`models::artifacts::self_ops`); the poll and
//! poll-response content blocks embed the collaboration-owned
//! [`ContentBlock`] and are consumed by the message content-block
//! validators in [`crate::events_payloads::message`].

use std::collections::BTreeMap;

use arkret_wire::{ActorId, EventId, MessageId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::message::{
    ContentBlock, ContentBlockValidationError, ContentBlockValidationResult, TextFormat,
    validate_content_block,
};
use crate::serde_absence::deserialize_non_null_optional;

/// The closed union in content-block-poll.schema.json. Deserialize once at the
/// heterogeneous Content Block boundary, then retain the selected typed branch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PollContentBlock {
    Definition(PollBlock),
    Response(PollResponseBlock),
}

impl PollContentBlock {
    pub fn validate(&self) -> ContentBlockValidationResult<()> {
        match self {
            Self::Definition(block) => block.validate(),
            Self::Response(block) => block.validate(),
        }
    }
}

/// Discriminator for `content-block-poll.schema.json#/$defs/poll_body.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollDisclosureKind {
    #[serde(rename = "disclosed")]
    Disclosed,
}

/// Discriminator for `content-block-poll.schema.json#/$defs/poll_block.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollBlockKind {
    #[serde(rename = "ak.content.poll")]
    Poll,
}

/// Discriminator for
/// `content-block-poll.schema.json#/$defs/poll_response_block.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollResponseBlockKind {
    #[serde(rename = "ak.content.poll.response")]
    PollResponse,
}

/// Closed identity alternatives permitted by the Poll reply-context schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PollReplyMessageRef {
    Message(MessageId),
    Event(EventId),
}

/// Known reply-context fields remain typed; the schema permits extension fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PollReplyContext {
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub message_ref: Option<PollReplyMessageRef>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub sender_actor_id: Option<ActorId>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub excerpt: Option<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl PollReplyContext {
    fn validate(&self) -> ContentBlockValidationResult<()> {
        if self.extensions.keys().any(|key| {
            matches!(
                key.as_str(),
                "type" | "message_ref" | "sender_actor_id" | "excerpt"
            )
        }) {
            return Err(ContentBlockValidationError::new(
                "invalid Poll reply-context extension",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FormattedBody {
    Text(String),
    Structured(BTreeMap<String, Value>),
}

fn valid_answer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
}

impl PollBlock {
    pub fn question_text(&self) -> &str {
        self.poll
            .question
            .as_ref()
            .map_or(&self.body, |question| &question.body)
    }

    pub fn validate(&self) -> ContentBlockValidationResult<()> {
        if let Some(context) = &self.reply_context {
            context.validate()?;
        }
        if self.poll.max_selection_count == 0
            || self.poll.answers.is_empty()
            || self.poll.answers.len() > 1000
        {
            return Err(ContentBlockValidationError::new(
                "invalid Poll definition bounds",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for answer in &self.poll.answers {
            if !valid_answer_id(&answer.id) || !ids.insert(&answer.id) {
                return Err(ContentBlockValidationError::new(
                    "invalid or duplicate Poll answer id",
                ));
            }
            validate_content_block(
                &answer
                    .text
                    .to_value()
                    .map_err(|_| ContentBlockValidationError::new("invalid Poll answer content"))?,
            )?;
        }
        if let Some(question) = &self.poll.question {
            validate_content_block(
                &question.to_value().map_err(|_| {
                    ContentBlockValidationError::new("invalid Poll question content")
                })?,
            )?;
        }
        Ok(())
    }
}

impl PollResponseBlock {
    pub fn validate(&self) -> ContentBlockValidationResult<()> {
        if let Some(context) = &self.reply_context {
            context.validate()?;
        }
        let selections = &self.poll_response.selections;
        let unique: std::collections::BTreeSet<_> = selections.iter().collect();
        if selections.is_empty()
            || selections.len() > 1000
            || unique.len() != selections.len()
            || selections.iter().any(|id| !valid_answer_id(id))
        {
            return Err(ContentBlockValidationError::new(
                "invalid Poll response selections",
            ));
        }
        Ok(())
    }
}

include!("generated/poll_contracts.rs");
