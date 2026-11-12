// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e57f2773764165f5a2e6047ae5491cdf152476deb73c83b2f6c14fff58925305
//
// Input: schemas/current-state.schema.json
// sha256=b9b2fcecf87470a1def1e55bf536bdb637b04f0e6f42083d5ed9962a80b14c61
//
// Bindings: tools/closed-model-bindings.json
// sha256=e1457ee62d38c96bf19ebec5a494f5b8b0ff175b3fda2ac3be4ca317967625e0

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
