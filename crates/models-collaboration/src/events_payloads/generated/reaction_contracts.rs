// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=bfee8c04c7b3d9e76727652feaa2e49488bb443f0bb99670a13dd07f2be02fe3
//
// Input: schemas/event-payload.schema.json
// sha256=db43f4934d4601ea90be4c1dd25628271e264c7fd7058283c6b765e30217463c
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=5f2752ea44fd1fbc9de2b85e1d89524b11ee593a43ddc700d52484230e874397
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

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
