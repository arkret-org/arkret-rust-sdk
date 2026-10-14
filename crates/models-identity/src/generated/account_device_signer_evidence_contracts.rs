// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-device-signer-evidence.schema.json
// sha256=be138f3d8efb65161e94f9c0c5891c4dd2016168aeb8f89d519e0508fa748022
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

/// Counterpart: `account-device-signer-evidence.schema.json`.
/// `account-device-signer-evidence.schema.json` exact two-member root.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDeviceSignerEvidence {
    pub device_projection_attestation: DeviceProjectionAttestation,
    pub service_resolution: AuthenticatedServiceResolution,
}

/// Counterpart:
/// `account-device-signer-evidence.schema.json#/$defs/forward_account_device_signer_evidence`.
/// Closed authority-forward sibling; never accepted as a directory row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ForwardAccountDeviceSignerEvidence {
    pub device_projection_attestation: arkret_models_crypto::ForwardDeviceProjectionAttestation,
    pub service_resolution: AuthenticatedServiceResolution,
}
