// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=30f8a7bac2a387091f550a02d6f44c69afc5fde62df0cd0be521f28a963726c0
//
// Input: schemas/keys-operations.schema.json
// sha256=8cafab3f5d4a61e2d9900c88eabf3d707a081f3411ccf0d16a4eb4f081682733
//
// Bindings: tools/closed-model-bindings.json
// sha256=7d1fdb47ec4baf0bbf7ecbf1969f8fff785140d5d15b0d6fadc690db7bbd4a62

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
