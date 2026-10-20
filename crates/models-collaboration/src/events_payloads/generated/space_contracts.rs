// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=140d80954da7fc35c298320ecd75b1ee6c9fc268ffbbfccbab10a19f879f3468
//
// Bindings: tools/closed-model-bindings.json
// sha256=af95236e8ff82e50c34d7765747d25e44d52146a0301a74856e3530bb2a4bf50

/// Counterpart: `event-payload.schema.json#/$defs/space_create_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceCreatePayload {
    pub object: Space,
}

/// Counterpart: `event-payload.schema.json#/$defs/space_parent_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_parent_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceParentPayload {
    pub space_id: SpaceId,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub parent_space_id: Option<SpaceId>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub expected_parent_space_id: Option<SpaceId>,
}
