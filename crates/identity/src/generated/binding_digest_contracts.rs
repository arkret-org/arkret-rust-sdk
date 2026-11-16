// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/did-binding-contracts.schema.json
// sha256=500bc0d7d460f4902b8c063aec7e961e751880e502f62d4c96f3c66da456f3c8
//
// Bindings: tools/closed-model-bindings.json
// sha256=3bfe22afd0deee9b00a0fd4b2c1e2c7eee318ee6752681d944e4cc4b38492100

/// Counterpart: `did-binding-contracts.schema.json#/$defs/evidence_dependencies`.
/// The structured dependency record a binding carries so witness-level
/// invalidation can be selective
/// (`did-binding-contracts.schema.json#/$defs/evidence_dependencies`).
///
/// A witness revocation, an organization merge or a falsified consistency proof
/// arrives as a *coordinate* (witness DID, organization, log head), never as a
/// digest — digests are one-way, so `evidence_digest` cannot answer "which
/// bindings depend on witness X". This record can, and a store that declares
/// evidence-bearing methods MUST index it at least by witness DID.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDependencies {
    pub witness_dids: Vec<Did>,
    pub witness_controlling_organization_dids: Vec<Did>,
    pub history_heads: Vec<String>,
}
