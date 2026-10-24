// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/strand.schema.json
// sha256=6df510ee9e4a7c34c16c911cbd038b5c6f075e682853835bdb524b0f282b1c6a
//
// Input: schemas/morph.schema.json
// sha256=b3cac6f2589c477119aadd54227858dbe16aa35dae1b4fd1047ce6afd0aec24f
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=a0f5bb09fcb5ae9612cd3a27c533f4bf7dfa29f0b19aa178443af54fa4817c10
//
// Input: schemas/circle.schema.json
// sha256=6100d0f9ad68406bc14b96bd5a24ac8976468c6b5f0c4cd2d3e8802be64caa6c
//
// Bindings: tools/closed-model-bindings.json
// sha256=449548ffe916fc20fdfa401c27c8bb4c71e9b2b7d85b5d4534c920be64e8ac22

/// Counterpart: `strand.schema.json#/$defs/strand_track`.
/// Counterpart for `spec/v1/artifacts/schemas/strand.schema.json#/$defs/strand_track`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandTrack {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub is_primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub encrypted_content: Option<EncryptedEnvelope>,
}

/// Counterpart: `circle.schema.json#/$defs/display/properties/symbol`.
/// Counterpart for `spec/v1/artifacts/schemas/circle.schema.json#/$defs/display`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplaySymbol {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub emoji: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub glyph: Option<String>,
}
