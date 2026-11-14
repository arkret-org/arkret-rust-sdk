// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=7df2b471b4cf8fdd16049ce20e07129c8669d5de08f2bd80e1ecd0d142162973
//
// Input: schemas/event-payload.schema.json
// sha256=110f3442df382c602cece0f2f5e0b4f2af3a0374f493911960b3cf6216f99a95
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=79f44b93062a197a5ed0854fa6ae7b113f028dd8e38369f40276457d00d93e0b
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc73c01cf2bfb7cc6d4969c8f2f7faa6e44275c4a585ad81f3c94ac408daab8c

/// Counterpart: `current-state.schema.json#/$defs/reaction_current_entry`.
/// One active full-Actor/key membership and its original accepted add source.
/// The reference grants no historical Event/key access or AEAD verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionCurrentEntry {
    pub actor_id: ActorId,
    pub key: String,
    pub source: CommittedEventRef,
}

/// Counterpart: `current-state.schema.json#/$defs/message_reactions_value`.
/// Complete active metadata for one outer target/scope selector.
/// Empty entries retain the outer row's real revision. This is not a
/// historical assertion union or a client-side Event reducer.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageReactionsCurrentValue {
    entries: Vec<ReactionCurrentEntry>,
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
