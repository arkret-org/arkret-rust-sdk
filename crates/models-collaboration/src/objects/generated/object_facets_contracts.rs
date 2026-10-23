// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/strand.schema.json
// sha256=857a35af89123d63b0b4248701c9aafe70948538b05b93ba32f41e8c636ae894
//
// Input: schemas/morph.schema.json
// sha256=56302af44cf962e007b3255541fc755179ed6bb82b93ee3beb36d3ab551e94cb
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=5f2752ea44fd1fbc9de2b85e1d89524b11ee593a43ddc700d52484230e874397
//
// Input: schemas/circle.schema.json
// sha256=25bff113919d1ad9f0598ef42a06d6f190fd184d9110513ef58d6885d15cdf78
//
// Bindings: tools/closed-model-bindings.json
// sha256=d200bd3e6d76abd1b6154781fb5e54f11fbbc834638cdc29554f83590127fdfa

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
