// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=cc3c0dfe191c29585876c1d6438a28787cf75076690f0ef1d7a999c470499b9a
//
// Input: schemas/typed-current-result.schema.json
// sha256=575ea203cf43456045514ea1085603136877fe9313302291f7d573a1eb7055cc
//
// Bindings: tools/closed-model-bindings.json
// sha256=42637b7091c5d9a931ae042b62a3b4b684763d010e044485fc40891314c2f844

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
