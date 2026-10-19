// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=cc3c0dfe191c29585876c1d6438a28787cf75076690f0ef1d7a999c470499b9a
//
// Bindings: tools/closed-model-bindings.json
// sha256=42637b7091c5d9a931ae042b62a3b4b684763d010e044485fc40891314c2f844

/// Counterpart: `event-payload.schema.json#/$defs/morph_create_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphCreatePayload {
    pub object: Morph,
}

/// Counterpart: `event-payload.schema.json#/$defs/morph_stage_set_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphStageSetPayload {
    pub morph_id: MorphId,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_stage: Option<String>,
}
