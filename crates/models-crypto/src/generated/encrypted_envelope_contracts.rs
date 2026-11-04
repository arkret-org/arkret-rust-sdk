// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=a0f5bb09fcb5ae9612cd3a27c533f4bf7dfa29f0b19aa178443af54fa4817c10
//
// Bindings: tools/closed-model-bindings.json
// sha256=3d8286ffa86f9dd01d3c540d77924093bfc6e9642d4effb361307f36e3ffd625

/// Counterpart: `encrypted-envelope.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub version: String,
    pub content_type: String,
    pub encryption_context: EncryptedEnvelopeEncryptionContext,
    pub ciphertext: String,
}
