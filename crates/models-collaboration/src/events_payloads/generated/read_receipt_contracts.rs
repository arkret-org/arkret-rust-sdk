// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=9ef2ffb9153fc0557bf79eed03e5208c50205883014166111bfaded0e52c9651
//
// Input: schemas/current-state.schema.json
// sha256=12c6338f4680c74863df4fb44a782ce08bf15a489ee12c019864141f0f6962f2
//
// Bindings: tools/closed-model-bindings.json
// sha256=3d8286ffa86f9dd01d3c540d77924093bfc6e9642d4effb361307f36e3ffd625

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
