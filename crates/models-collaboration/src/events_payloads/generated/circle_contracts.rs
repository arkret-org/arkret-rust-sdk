// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=74e26ef25ba5846ba74149c301a7ff5c7f1afc507f2cfd207cfe0edc060507bf
//
// Input: schemas/account-operations.schema.json
// sha256=78c6503698cd43571f2b25543013f9036927ef9bfd005e71377ad3006f4a64d4
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

/// Counterpart: `event-payload.schema.json#/$defs/circle_create_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleCreatePayload {
    pub object: Circle,
}

/// Counterpart: `event-payload.schema.json#/$defs/circle_patch_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CirclePatchPayload {
    pub circle_id: CircleId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_state_digest: Option<Hash>,
}
