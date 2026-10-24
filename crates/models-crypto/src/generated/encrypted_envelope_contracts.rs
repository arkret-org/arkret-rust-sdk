// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=a0f5bb09fcb5ae9612cd3a27c533f4bf7dfa29f0b19aa178443af54fa4817c10
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

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
