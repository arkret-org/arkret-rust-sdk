// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=ae721190eb5b882241bc9b1579213be18c0ed0317540f9b82371c493e10c7739
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc73c01cf2bfb7cc6d4969c8f2f7faa6e44275c4a585ad81f3c94ac408daab8c

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
