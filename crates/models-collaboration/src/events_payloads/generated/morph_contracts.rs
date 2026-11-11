// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=acfbdce31eae2f3c3f4ca550f3506c9ecd500e4de81b3517fe8167903934c7c4
//
// Bindings: tools/closed-model-bindings.json
// sha256=8754dda4399255a8d93502ff99e0f2e245ea00988a5263e7f64cf21d1eada652

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
