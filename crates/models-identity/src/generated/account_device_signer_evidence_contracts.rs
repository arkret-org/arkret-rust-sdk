// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-device-signer-evidence.schema.json
// sha256=76f68ead54860463e63b2d6eddb58bf64e022b9af1ba4a1f9e89749132a2957f
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

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
