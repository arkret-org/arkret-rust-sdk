// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mimi-operations.schema.json
// sha256=e77636e8329bbf233a363f83931d8c7eff7c221974d377f9af9a7ae7c8eddd5f
//
// Bindings: tools/closed-model-bindings.json
// sha256=ee958bb963f35540b3d330cc3731d78e388ab09c402e48014a9739bbca5c1c40

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
