// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=36cd224e905e42c33740bf6c3c3d893497e38b5305cadc8d0fb51c1cfdba9c0d
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

/// Counterpart: `event-payload.schema.json#/$defs/read_receipt_policy_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/read_receipt_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptPolicyPayload {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub disclosure: Option<ReadReceiptDisclosure>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub visibility: Option<ReadReceiptVisibility>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub scope_overrides_allowed: Option<bool>,
}
