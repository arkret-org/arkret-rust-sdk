// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=303069f3b12147816e080f5948d4877f5444a1ff82f532785c8244cc0a173e34
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=79f44b93062a197a5ed0854fa6ae7b113f028dd8e38369f40276457d00d93e0b
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

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
