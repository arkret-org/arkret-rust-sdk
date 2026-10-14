// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/typed-current-result.schema.json
// sha256=fec530d3711c83b9a3bf0c4bc9bb5bee2c350c552440b12a98c5e723f7740529
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

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
