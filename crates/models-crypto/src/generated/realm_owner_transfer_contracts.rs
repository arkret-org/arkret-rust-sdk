// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=25014dfa0753800eba6d70e87ef3c5464d3ff2b22969282911e7f73672f68947
//
// Input: schemas/keys-operations.schema.json
// sha256=a3fe4bf71b7e94747a347d41967cff92cf1864653114d6ba5437824ae74de67a
//
// Bindings: tools/closed-model-bindings.json
// sha256=f8598148149e81024ca07d8b02d6f7c48f1dc0672c100b2e8e4103790a652e46

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
