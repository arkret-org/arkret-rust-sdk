// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/view.schema.json
// sha256=8464fde342bae3720ecb809b096cd37a330811f0d07f26234a4f01d9eb4f6320
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

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
