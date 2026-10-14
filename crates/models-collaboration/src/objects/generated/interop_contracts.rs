// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mimi-operations.schema.json
// sha256=edfa36ae8bc99cf7017536d7a5ae5d02da2dfcbf8bb5a4ec17cc3701c0869628
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

/// Counterpart: `mimi-operations.schema.json#/$defs/ciphertext`.
/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/ciphertext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ciphertext {
    pub content_type: String,
    pub ciphertext_digest: Hash,
    pub payload: String,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/group_info`.
/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/group_info`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInfo {
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
    pub group_info: String,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/identifier`.
/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/identifier`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identifier {
    pub kind: String,
    pub identifier_commitment: Hash,
}
