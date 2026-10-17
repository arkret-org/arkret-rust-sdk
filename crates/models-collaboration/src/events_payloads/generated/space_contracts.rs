// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=b42ab7eb500df851ff7e7c4ad9383751d8e8dd62ccae338246d81a59bf646259
//
// Bindings: tools/closed-model-bindings.json
// sha256=14ce06e703487b8afdca6c0a5335ef346a965acc5f9443d89af8470d63109b0f

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
