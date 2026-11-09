// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=d88b52eea7b7e59339a88d67d629bc88477b57ab4c6646d3af55fce1ff8c509b
//
// Bindings: tools/closed-model-bindings.json
// sha256=973940c1b2f35b239f2e75b4f8e41fe33a818d78b1b608381b2b70df42e49f18

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_source`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoverySource {
    pub attestation: ContentRecoverySourceAttestation,
    pub origin_resolution: AuthenticatedServiceResolution,
}
