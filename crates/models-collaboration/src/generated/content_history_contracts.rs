// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=f15299dcf50eb9d402f226b2dd6829be638f416fb46629b78d24e7dbce5c5f30
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_source`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoverySource {
    pub attestation: ContentRecoverySourceAttestation,
    pub origin_resolution: AuthenticatedServiceResolution,
}

/// Counterpart: `content-encryption.schema.json#/$defs/backup_source`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentBackupSource {
    pub attestation: ContentBackupSourceAttestation,
    pub origin_resolution: AuthenticatedServiceResolution,
}

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_scope_cleanup_source`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoveryScopeCleanupSource {
    pub attestation: arkret_models_crypto::ContentRecoveryScopeCleanupAuthorization,
    pub origin_resolution: AuthenticatedServiceResolution,
}
