// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=64318ce99e830ea80a893a806c5f9437c11b0153401bcf8172df22a7c2baf737
//
// Input: schemas/current-state.schema.json
// sha256=72b3aa5374e048b1fd8bf165fcb91f6bc06d12d8d6542d44d2845089bd3a5e7c
//
// Bindings: tools/closed-model-bindings.json
// sha256=5c71516a86f6e77bf88bd907edc9f7002dddfcc4a5457d0ba636150543e5b28e

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

/// Counterpart: `current-state.schema.json#/$defs/current_scope_read_receipt_policy`.
/// Verified current value of exactly one Realm/Circle scope. Call validate before consumption.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentScopeReadReceiptPolicy {
    pub selector: CurrentSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: ReadReceiptPolicyPayload,
}
