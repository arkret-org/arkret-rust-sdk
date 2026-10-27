// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-device-signer-evidence.schema.json
// sha256=76f68ead54860463e63b2d6eddb58bf64e022b9af1ba4a1f9e89749132a2957f
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c8b4ad76a778828f23891614ed9c259161da8c53eb669c8825b9bb8a5da8ff2

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
