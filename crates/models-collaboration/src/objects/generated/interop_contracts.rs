// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mimi-operations.schema.json
// sha256=23bcdb30a0625be95b1f0ed7532962f5406840a9e7c8d81f182457129ce53eef
//
// Bindings: tools/closed-model-bindings.json
// sha256=449548ffe916fc20fdfa401c27c8bb4c71e9b2b7d85b5d4534c920be64e8ac22

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
