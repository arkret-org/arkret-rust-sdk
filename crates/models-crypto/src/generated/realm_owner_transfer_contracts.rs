// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=64318ce99e830ea80a893a806c5f9437c11b0153401bcf8172df22a7c2baf737
//
// Input: schemas/keys-operations.schema.json
// sha256=6ae4e3efa09f689cad8f3cf498111d3e9bee6e48017194dfac443320d01b37b7
//
// Bindings: tools/closed-model-bindings.json
// sha256=5c71516a86f6e77bf88bd907edc9f7002dddfcc4a5457d0ba636150543e5b28e

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
