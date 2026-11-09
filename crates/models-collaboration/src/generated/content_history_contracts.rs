// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=19f32215dc0fb4c9a2a42eac12881b4247370af6cc320ddb98af27aabc0e04ee
//
// Bindings: tools/closed-model-bindings.json
// sha256=586dcc2160f190a9fbbcb1f5857251190e1fa6d65f55d7ab65cdec8105d1c8ef

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
