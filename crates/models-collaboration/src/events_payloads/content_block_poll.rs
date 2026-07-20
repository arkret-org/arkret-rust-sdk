//! Content-block poll wire shapes.
//!
//! Counterparts for `spec/v1/artifacts/schemas/content-block-poll.schema.json`.
//! Migrated from `arkret-core` (`models::artifacts::self_ops`); the poll and
//! poll-response content blocks embed the collaboration-owned
//! [`ContentBlock`] and are consumed by the message content-block
//! validators in [`crate::events_payloads::morph_message`].

use std::collections::BTreeMap;

use arkret_wire::MessageId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::morph_message::ContentBlock;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/reply_context`.
pub type PollReplyContext = BTreeMap<String, Value>;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted_body: Option<FormattedBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted_body: Option<FormattedBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_context: Option<PollReplyContext>,
    pub poll_response: PollResponseBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FormattedBody {
    Text(String),
    Structured(BTreeMap<String, Value>),
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ContentBlockPoll {
    PollBlock(PollBlock),
    PollResponseBlock(PollResponseBlock),
}
