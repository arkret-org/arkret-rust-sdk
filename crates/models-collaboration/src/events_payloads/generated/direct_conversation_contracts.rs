// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=deec42771ac61327cec2794982e07dbd345c0dc58de617248bcfc6331ba020ee
//
// Input: schemas/typed-current-result.schema.json
// sha256=ad33beeae92adb2bdf6ce5528d33435ba67cc5608647a5e0d5e8728902c543a7
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c0dd616b73cb58355247f04ec903123c52cd61b038fe2b7df35029d0b6802c1

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
