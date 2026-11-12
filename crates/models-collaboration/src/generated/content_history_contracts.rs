// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=6b4bdb9e89c47735f1faa9b4b06d7b50dbdcecbcf14e50a0d6818ae5618a5d07
//
// Bindings: tools/closed-model-bindings.json
// sha256=2db9dc0b757e082d561722a2301e943a7422e79691dd5632a5a2ec129045cc3f

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
