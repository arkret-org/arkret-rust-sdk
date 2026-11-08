// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=ccb35fae085d742868258a8ab9b934a8f08c0448058484a4c08439b172d9f25e
//
// Bindings: tools/closed-model-bindings.json
// sha256=f277aac30f4b23b2e663aeb5c59ddf9a6e2b3af9eb64854335f03d715718292a

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_source`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoverySource {
    pub attestation: ContentRecoverySourceAttestation,
    pub origin_resolution: AuthenticatedServiceResolution,
}
