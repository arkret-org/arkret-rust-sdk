// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=64318ce99e830ea80a893a806c5f9437c11b0153401bcf8172df22a7c2baf737
//
// Input: schemas/current-state.schema.json
// sha256=72b3aa5374e048b1fd8bf165fcb91f6bc06d12d8d6542d44d2845089bd3a5e7c
//
// Bindings: tools/closed-model-bindings.json
// sha256=5c71516a86f6e77bf88bd907edc9f7002dddfcc4a5457d0ba636150543e5b28e

/// Counterpart: `event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
/// `event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationBoundPayload {
    pub pair_key: Hash,
    pub unordered_participant_ids: Vec<ActorId>,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
    pub authorization_basis: DirectConversationAuthorizationBasis,
    pub initial_exact_pair_group_state_ref: EventId,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

/// Counterpart: `current-state.schema.json#/$defs/direct_conversation_binding_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationBindingCurrentValue {
    pub binding_event_ref: EventId,
    pub binding: DirectConversationBoundPayload,
}
