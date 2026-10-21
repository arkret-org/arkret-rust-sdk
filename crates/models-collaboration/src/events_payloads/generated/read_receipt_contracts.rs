// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=51122d20a1426cc7e23a5e93ea307be964a90e3eaa9e5980d051ae67c2634887
//
// Input: schemas/typed-current-result.schema.json
// sha256=224f4055e7e30ab5a95a401acc78ea65e9fac2e347ea0fcd0931860a3c6feec1
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

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
}

/// Counterpart: `typed-current-result.schema.json#/$defs/scope_read_receipt_policy_result`.
/// Verified current value of exactly one Realm/Circle scope. Call validate before consumption.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeReadReceiptPolicyCurrent {
    pub selector: CurrentSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: ReadReceiptPolicyPayload,
}
