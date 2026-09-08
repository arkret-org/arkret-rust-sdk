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

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_answer`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollAnswer {
    pub id: String,
    pub text: ContentBlock,
}

/// Discriminator for `content-block-poll.schema.json#/$defs/poll_body.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollDisclosureKind {
    #[serde(rename = "disclosed")]
    Disclosed,
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollBody {
    pub kind: PollDisclosureKind,
    pub max_selections: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub question: Option<ContentBlock>,
    pub answers: Vec<PollAnswer>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_response_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResponseBody {
    pub poll_ref: MessageId,
    pub selections: Vec<String>,
}

/// Discriminator for `content-block-poll.schema.json#/$defs/poll_block.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollBlockKind {
    #[serde(rename = "ak.content.poll")]
    Poll,
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_block`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollBlock {
    pub kind: PollBlockKind,
    pub body: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub format: Option<TextFormat>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub formatted_body: Option<FormattedBody>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub reply_context: Option<PollReplyContext>,
    pub poll: PollBody,
}

/// Discriminator for
/// `content-block-poll.schema.json#/$defs/poll_response_block.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollResponseBlockKind {
    #[serde(rename = "ak.content.poll.response")]
    PollResponse,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_response_block`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResponseBlock {
    pub kind: PollResponseBlockKind,
    pub body: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub format: Option<TextFormat>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub formatted_body: Option<FormattedBody>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub reply_context: Option<PollReplyContext>,
    pub poll_response: PollResponseBody,
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
        if self.poll.max_selections == 0
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn definition() -> Value {
        json!({"kind":"ak.content.poll", "body":"fallback", "poll":{
            "kind":"disclosed", "max_selections":1,
            "answers":[{"id":"yes", "text":{"kind":"ak.content.text","body":"Yes"}}]
        }})
    }

    fn valid(value: Value) -> bool {
        serde_json::from_value::<PollContentBlock>(value)
            .is_ok_and(|block| block.validate().is_ok())
    }

    #[test]
    fn poll_content_rejects_legacy_and_malformed_fields_without_partial_acceptance() {
        assert!(valid(definition()));
        for (pointer, invalid) in [
            ("/poll/answers", json!(["Yes"])),
            (
                "/poll/answers",
                json!([{"text":{"kind":"ak.content.text","body":"Yes"}}]),
            ),
            ("/poll/answers", json!([])),
            ("/poll/answers/0/id", json!("invalid id")),
            ("/poll/max_selections", json!(0)),
            ("/poll/kind", json!("hidden")),
        ] {
            let mut value = definition();
            *value.pointer_mut(pointer).unwrap() = invalid;
            assert!(!valid(value), "accepted invalid {pointer}");
        }
        let mut duplicate = definition();
        let answer = duplicate["poll"]["answers"][0].clone();
        duplicate["poll"]["answers"]
            .as_array_mut()
            .unwrap()
            .push(answer);
        assert!(!valid(duplicate));
        for (field, invalid) in [
            ("format", json!("html")),
            ("format", Value::Null),
            ("reply_context", json!({"type":"legacy"})),
            ("reply_context", json!({"sender_actor_id":"alice"})),
            ("options", json!(["Yes"])),
        ] {
            let mut value = definition();
            value[field] = invalid;
            assert!(!valid(value), "accepted invalid {field}");
        }
    }

    #[test]
    fn poll_content_preserves_rich_question_and_large_selection_limit() {
        let mut value = definition();
        value["poll"]["max_selections"] = json!(u64::from(u32::MAX) + 1);
        value["poll"]["question"] = json!({"kind":"ak.content.text","body":"Question"});
        let block: PollBlock = serde_json::from_value(value).unwrap();
        block.validate().unwrap();
        assert_eq!(block.question_text(), "Question");
        assert_eq!(block.poll.max_selections, u64::from(u32::MAX) + 1);
    }

    #[test]
    fn poll_response_rejects_empty_duplicate_and_noncanonical_selections() {
        for selections in [json!([]), json!(["yes", "yes"]), json!(["invalid id"])] {
            assert!(!valid(
                json!({"kind":"ak.content.poll.response", "body":"response",
                "poll_response":{"poll_ref":"ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu", "selections":selections}})
            ));
        }
        assert!(valid(
            json!({"kind":"ak.content.poll.response", "body":"response",
            "poll_response":{"poll_ref":"ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu", "selections":["yes"]}})
        ));
    }
}
