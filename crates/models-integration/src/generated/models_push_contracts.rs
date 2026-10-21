// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/push-operations.schema.json
// sha256=2dee9005fb46e3e9234ae4e0d135780161f1bc6ebb4a06a31026a6b8234f5d31
//
// Bindings: tools/closed-model-bindings.json
// sha256=493cae310937341f71c829355ac772a12a878b5f7c2e20a5e915ba45fda6c2aa

/// Counterpart: `push-operations.schema.json#/$defs/push_notify_device_outcome`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_notify_device_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotifyDeviceOutcome {
    pub device_id: DeviceId,
    pub gateway_status: PushNotifyGatewayStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason_code: Option<PushNotifyReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub retry_after_ms: Option<u64>,
}
