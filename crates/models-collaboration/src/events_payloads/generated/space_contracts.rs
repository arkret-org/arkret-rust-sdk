// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=30f8a7bac2a387091f550a02d6f44c69afc5fde62df0cd0be521f28a963726c0
//
// Bindings: tools/closed-model-bindings.json
// sha256=378099dfc0552c94d918067d3fefafa8cc572fc164f01f1a4d741a161c5c7c1a

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
