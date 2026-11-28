// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/keys-operations.schema.json
// sha256=e54664c4e941abe6616c509aaefaae265d78e1f65044b6e3ed722d4804102d49
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `event-payload.schema.json#/$defs/realm_owner_transfer_payload/properties/patch`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOwnerTransferPatch {
    pub controller_actor_id: ActorId,
}

/// Counterpart:
/// `event-payload.schema.json#/$defs/realm_owner_transfer_acceptance_transcript/properties/
/// payload_without_successor_acceptance`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOwnerTransferUnsignedPayload {
    pub realm_id: RealmId,
    pub expected_state_digest: Hash,
    pub patch: RealmOwnerTransferPatch,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_owner_transfer_acceptance_transcript`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOwnerTransferAcceptanceIntent {
    pub scope_ref: ScopeRef,
    pub actor_id: ActorId,
    pub payload_without_successor_acceptance: RealmOwnerTransferUnsignedPayload,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/peer_keys_query_request_body/properties/
/// owner_transfer_acceptance`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOwnerTransferAcceptance {
    pub intent: RealmOwnerTransferAcceptanceIntent,
    pub acceptance: DetachedObjectSignature,
}
