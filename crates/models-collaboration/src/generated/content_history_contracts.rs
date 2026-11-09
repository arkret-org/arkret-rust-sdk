// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=50c13af7b767c57536bc8d7d145d6236424051ae83ce41b15e34f9aaaa4d315d
//
// Bindings: tools/closed-model-bindings.json
// sha256=825d8d6aa965fe516029150f727237abbc8f6c6619f8df578a995cf5da35a97f

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
