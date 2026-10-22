// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=5210d9cda5e05851274d77802d4d609d186411af48ceda43c94fcabf571291f1
//
// Bindings: tools/closed-model-bindings.json
// sha256=c47c2cf65d6369093f5d7c6c29aaabfd64872c6277db759f4cd74b82db0a8236

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
