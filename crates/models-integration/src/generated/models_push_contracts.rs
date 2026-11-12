// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/push-operations.schema.json
// sha256=4bbdb549699dfa03e28322ebb5846fe61384e18d4d9c693173b286d659e5ef8a
//
// Bindings: tools/closed-model-bindings.json
// sha256=ba1e9867d9c38f8d402c9e6bcf11c24593e800ed0ccefe6ced03bcd0bf4272ba

/// Counterpart: `push-operations.schema.json#/$defs/push_gateway_submission_outcome`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_gateway_submission_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushGatewaySubmissionOutcome {
    pub device_id: DeviceId,
    pub gateway_status: PushNotifyGatewayStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason_code: Option<PushNotifyReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub retry_after_ms: Option<u64>,
}
