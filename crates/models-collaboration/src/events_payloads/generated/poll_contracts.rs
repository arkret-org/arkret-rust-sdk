// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-block-poll.schema.json
// sha256=34986ba616ed4fe53e5c5d7e1b35e9c6ff206ca703d3d1babe0dcd01121b6e2c
//
// Input: schemas/message.schema.json
// sha256=5cc5ebff41195a4312de792c0dc60887b4cd4b024e931ca4418aacea64e21707
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c0dd616b73cb58355247f04ec903123c52cd61b038fe2b7df35029d0b6802c1

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
    pub max_selections: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub question: Option<ContentBlock>,
    pub answers: Vec<PollAnswer>,
}

/// Counterpart: `content-block-poll.schema.json#/$defs/poll_response_body`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_response_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResponseBody {
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
    pub poll_response: PollResponseBody,
}
