// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

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
