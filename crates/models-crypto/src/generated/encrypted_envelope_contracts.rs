// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=79f44b93062a197a5ed0854fa6ae7b113f028dd8e38369f40276457d00d93e0b
//
// Bindings: tools/closed-model-bindings.json
// sha256=973940c1b2f35b239f2e75b4f8e41fe33a818d78b1b608381b2b70df42e49f18

/// Counterpart: `encrypted-envelope.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub version: String,
    pub content_type: String,
    pub encryption_scheme: EncryptedPayloadScheme,
    pub encryption_context: EncryptedEnvelopeEncryptionContext,
    pub ciphertext: String,
}
