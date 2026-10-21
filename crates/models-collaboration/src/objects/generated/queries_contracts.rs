// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/view.schema.json
// sha256=993f340506135586b4041795369e2de7423215ae005f0401013f21e523f944a7
//
// Bindings: tools/closed-model-bindings.json
// sha256=493cae310937341f71c829355ac772a12a878b5f7c2e20a5e915ba45fda6c2aa

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
