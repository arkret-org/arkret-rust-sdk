// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/view.schema.json
// sha256=993f340506135586b4041795369e2de7423215ae005f0401013f21e523f944a7
//
// Bindings: tools/closed-model-bindings.json
// sha256=8f43ab7f7fe4be59fd38447b7690378c53af63212ce0eb1df8f8d25fa2a14315

/// Counterpart: `view.schema.json#/$defs/sort_spec`.
/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/sort_spec`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SortSpec {
    pub field: String,
    pub direction: SortDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub nulls: Option<NullsOrder>,
}
