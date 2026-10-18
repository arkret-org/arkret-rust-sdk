// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=b42ab7eb500df851ff7e7c4ad9383751d8e8dd62ccae338246d81a59bf646259
//
// Input: schemas/typed-current-result.schema.json
// sha256=fe2f5aa29f51e9d6243e74433c0ee027e4d15f04b8e01c3354a423f069b285a5
//
// Bindings: tools/closed-model-bindings.json
// sha256=4262c38f5c99fc4a61ddb6e91e7b7f08062a8a80502ab2cc5dca79d57658ca4b

/// Counterpart: `event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
/// `event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
/// `binding_digest` is receiver-derived and deliberately absent from the wire.
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

/// Counterpart:
/// `typed-current-result.schema.json#/$defs/direct_conversation_binding_endorsement_entry`.
/// One endorsement of the settled binding
/// (`typed-current-result.schema.json#/$defs/direct_conversation_binding_endorsement_entry`):
/// the canonical dot of the accepted `ak.direct_conversation.bound` write and
/// that Event's complete payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationBindingEndorsementEntry {
    pub tag_id: crate::exact_current_results::CanonicalEventDot,
    pub value: DirectConversationBoundPayload,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/direct_conversation_binding_value`.
/// Closed value of the `direct_conversation_binding` typed current result
/// (`typed-current-result.schema.json#/$defs/direct_conversation_binding_value`):
/// the add-only, canonically sorted dot set of accepted endorsements
/// (`contact-and-direct-conversation.md` section 8.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationBindingCurrentValue {
    pub endorsements: Vec<DirectConversationBindingEndorsementEntry>,
}
