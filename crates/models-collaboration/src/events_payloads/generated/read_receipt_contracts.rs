// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=110f3442df382c602cece0f2f5e0b4f2af3a0374f493911960b3cf6216f99a95
//
// Input: schemas/current-state.schema.json
// sha256=7df2b471b4cf8fdd16049ce20e07129c8669d5de08f2bd80e1ecd0d142162973
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc73c01cf2bfb7cc6d4969c8f2f7faa6e44275c4a585ad81f3c94ac408daab8c

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
