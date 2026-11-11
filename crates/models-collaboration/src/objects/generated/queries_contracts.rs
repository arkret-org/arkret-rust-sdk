// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/view.schema.json
// sha256=51e8a31f953b8264d697a0d93cadeaece23bb59ff1ae3b0bc01471351d168d33
//
// Bindings: tools/closed-model-bindings.json
// sha256=8754dda4399255a8d93502ff99e0f2e245ea00988a5263e7f64cf21d1eada652

/// Counterpart: `view.schema.json#/$defs/sort_specification`.
/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/sort_specification`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SortSpecification {
    pub field: String,
    pub direction: SortDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub nulls: Option<NullsOrder>,
}
