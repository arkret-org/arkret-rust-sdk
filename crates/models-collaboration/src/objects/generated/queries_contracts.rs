// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/view.schema.json
// sha256=f12bcf942493ff8c43f45bfdc5a3140d62ff1de8a3ae827cb72d696eaa7e5d3a
//
// Bindings: tools/closed-model-bindings.json
// sha256=378099dfc0552c94d918067d3fefafa8cc572fc164f01f1a4d741a161c5c7c1a

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
