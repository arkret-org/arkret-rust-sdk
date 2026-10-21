// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=a4c646467cc0e400d6cb24a119fe6791612dcf3a3a8d77fd355f9429600679bc
//
// Input: schemas/account-operations.schema.json
// sha256=b4be514e16b4a5154a4cb3bd56cf062f9ffb2cfc29ef25a26777a29f1e3d7644
//
// Bindings: tools/closed-model-bindings.json
// sha256=d27aff562a6c1628ec46d4e850170d384869963a898494b561139f314ad91286

/// Counterpart: `event-payload.schema.json#/$defs/view_create_payload`.
/// `event-payload.schema.json#/$defs/view_create_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewCreatePayload {
    pub object: ViewDefinition,
}

/// Counterpart: `event-payload.schema.json#/$defs/view_update_payload`.
/// `event-payload.schema.json#/$defs/view_update_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewUpdatePayload {
    pub view_id: ViewId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart: `event-payload.schema.json#/$defs/view_reconcile_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_reconcile_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewReconcilePayload {
    pub view_id: ViewId,
    pub definition: ViewDefinition,
}
