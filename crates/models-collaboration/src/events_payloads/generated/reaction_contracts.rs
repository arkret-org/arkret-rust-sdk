// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=12c6338f4680c74863df4fb44a782ce08bf15a489ee12c019864141f0f6962f2
//
// Input: schemas/event-payload.schema.json
// sha256=c1b7f6c9f9f4ceb88c4b7c2924da91d09b11c7dd9ef63fe1e1097a133c1d6fe0
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=79f44b93062a197a5ed0854fa6ae7b113f028dd8e38369f40276457d00d93e0b
//
// Bindings: tools/closed-model-bindings.json
// sha256=973940c1b2f35b239f2e75b4f8e41fe33a818d78b1b608381b2b70df42e49f18

/// Counterpart: `current-state.schema.json#/$defs/reaction_assertion_entry`.
/// One asserted element of the `message_reactions` keyed set
/// (`current-state.schema.json#/$defs/reaction_assertion_entry`): the
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

/// Counterpart: `current-state.schema.json#/$defs/message_reactions_value`.
/// Closed value of the `message_reactions` current state
/// (`current-state.schema.json#/$defs/message_reactions_value`): the
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
