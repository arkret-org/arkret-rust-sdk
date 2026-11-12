// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mimi-operations.schema.json
// sha256=0a1bc2ef6c37a0360b157fcc28fd162929d68b8e00cf37fe4654a952da21e46f
//
// Bindings: tools/closed-model-bindings.json
// sha256=ba1e9867d9c38f8d402c9e6bcf11c24593e800ed0ccefe6ced03bcd0bf4272ba

/// Counterpart: `mimi-operations.schema.json#/$defs/ciphertext`.
/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/ciphertext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ciphertext {
    pub content_type: String,
    pub ciphertext_digest: Hash,
    pub payload: String,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/identifier`.
/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/identifier`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identifier {
    pub kind: String,
    pub identifier_commitment: Hash,
}
