// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e82aa2728d1f60c88a7493e0ec3093f76e625428156e83978a5e8e4b14614034
//
// Input: schemas/keys-operations.schema.json
// sha256=8cafab3f5d4a61e2d9900c88eabf3d707a081f3411ccf0d16a4eb4f081682733
//
// Bindings: tools/closed-model-bindings.json
// sha256=6f2298d507cfeaf587b0a77d565af971535b7d029bf667f2e4b743448bcc016f

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
