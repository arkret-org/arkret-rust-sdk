// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-block-poll.schema.json
// sha256=4b5d4e97c751e4aff7f8ada839580db5e16cfbb27ca8a8ba6d60d9e235c0d9fb
//
// Input: schemas/message.schema.json
// sha256=395b49fc93d22a55cb40aba0d7e17aae146d9dac513c72c690b0a67663a545e7
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

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
