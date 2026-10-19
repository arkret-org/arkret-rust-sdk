// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=575ea203cf43456045514ea1085603136877fe9313302291f7d573a1eb7055cc
//
// Input: schemas/event-payload.schema.json
// sha256=cc3c0dfe191c29585876c1d6438a28787cf75076690f0ef1d7a999c470499b9a
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=5f2752ea44fd1fbc9de2b85e1d89524b11ee593a43ddc700d52484230e874397
//
// Bindings: tools/closed-model-bindings.json
// sha256=42637b7091c5d9a931ae042b62a3b4b684763d010e044485fc40891314c2f844

/// Counterpart: `typed-current-result.schema.json#/$defs/reaction_assertion_entry`.
/// One asserted element of the `message_reactions` keyed set
/// (`typed-current-result.schema.json#/$defs/reaction_assertion_entry`): the
/// accepting Event's canonical dot and that Event's complete reaction payload.
///
/// The asserting actor and the polarity (add or remove) are deliberately not
/// element fields: `models/strand-and-message.md` section 9.8.3 reads both from
/// the signed envelope of the Event the dot names.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionAssertionEntry {
    pub tag_id: CanonicalEventDot,
    pub value: ReactionPayload,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/message_reactions_value`.
/// Closed value of the `message_reactions` typed current result
/// (`typed-current-result.schema.json#/$defs/message_reactions_value`): the
/// canonically sorted dot set of reaction assertions on one target.
///
/// `ak.reaction.add` and `ak.reaction.remove` each project exactly one
/// `keyed_set_add`, so every element's dot names write index 0 of its Event,
/// and a remove is itself an element. The join is the keyed-set union of
/// `models/common-fields.md` section 2; membership, deduplication and counts
/// are read-side folds and never part of this value. Decoding enforces the
/// set invariants, so a held value is always a valid set of one target.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageReactionsCurrentValue {
    assertions: Vec<ReactionAssertionEntry>,
}

/// Counterpart: `event-payload.schema.json#/$defs/reaction_payload`.
/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/reaction_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionPayload {
    pub target_ref: ObjectRef,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub encrypted_payload: Option<EncryptedEnvelope>,
}
