// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=deec42771ac61327cec2794982e07dbd345c0dc58de617248bcfc6331ba020ee
//
// Input: schemas/typed-current-result.schema.json
// sha256=ad33beeae92adb2bdf6ce5528d33435ba67cc5608647a5e0d5e8728902c543a7
//
// Bindings: tools/closed-model-bindings.json
// sha256=732705747345d917d3513f52645f7b15c40fea3cf0dcd0eba2a9055e6ae96ae7

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
