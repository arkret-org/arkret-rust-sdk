// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/push-operations.schema.json
// sha256=3ce209feeed97d0daef11fc72787d94f9b47e2e9c01223675be6981fda33055f
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

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
