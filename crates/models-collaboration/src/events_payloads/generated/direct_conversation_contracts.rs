// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=ad0a6afcb615a15924cab022e1c499da750e70b2f9c1bcc0cc6b25a3de3e450e
//
// Input: schemas/current-state.schema.json
// sha256=12c6338f4680c74863df4fb44a782ce08bf15a489ee12c019864141f0f6962f2
//
// Bindings: tools/closed-model-bindings.json
// sha256=c118dc80d3979cf43e74a8ebd793a80ebb67f13c08db276c8d2c87279bae1b20

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
