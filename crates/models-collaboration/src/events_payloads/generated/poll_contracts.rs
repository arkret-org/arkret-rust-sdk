// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-block-poll.schema.json
// sha256=4b5d4e97c751e4aff7f8ada839580db5e16cfbb27ca8a8ba6d60d9e235c0d9fb
//
// Input: schemas/message.schema.json
// sha256=279cc187893bea352ae89e4718237a618b5b1852d5778b54a29b94a1769c3fbd
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c8b4ad76a778828f23891614ed9c259161da8c53eb669c8825b9bb8a5da8ff2

/// Counterpart: `content-block-poll.schema.json#/$defs/poll_answer`.
/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_answer`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollAnswer {
    pub id: String,
    pub text: ContentBlock,
}

/// Counterpart: `content-block-poll.schema.json#/$defs/poll_body`.
/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollBody {
    pub kind: PollDisclosureKind,
    pub max_selection_count: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub question: Option<ContentBlock>,
    pub answers: Vec<PollAnswer>,
}

/// Counterpart: `content-block-poll.schema.json#/$defs/poll_vote`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_vote`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollVote {
    pub poll_ref: MessageId,
    pub selections: Vec<String>,
}

/// Counterpart: `content-block-poll.schema.json#/$defs/poll_block`.
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

/// Counterpart: `content-block-poll.schema.json#/$defs/poll_response_block`.
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
    pub poll_response: PollVote,
}
