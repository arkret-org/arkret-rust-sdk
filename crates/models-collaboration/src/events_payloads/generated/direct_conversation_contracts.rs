// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=5d51dfc7bb9e654a8c467a057b1df9d91741203447e09c3aff43e05fb8e76a4f
//
// Input: schemas/current-state.schema.json
// sha256=b3cb719af901c84d50427c0d94de8900dfb1572ee60d81cd331187225388756d
//
// Bindings: tools/closed-model-bindings.json
// sha256=dd0891cd81e0fc2caaf499fd178468a13da86ea101d8780b59ca3e5c661eeecd

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
