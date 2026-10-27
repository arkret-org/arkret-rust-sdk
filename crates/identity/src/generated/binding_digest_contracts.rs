// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/did-binding-contracts.schema.json
// sha256=24ce65b5dac11e00aba03d5d059426386fd0a4f2bab2e3cf30d2a86eb8dee2d6
//
// Bindings: tools/closed-model-bindings.json
// sha256=13aff1fc7ba8bd04dc6586b917faf46593a6d0e4beeadb69db75284c9e17a6f7

/// Counterpart: `did-binding-contracts.schema.json#/$defs/evidence_dependencies`.
/// The structured dependency record a binding carries so witness-level
/// invalidation can be selective
/// (`did-binding-contracts.schema.json#/$defs/evidence_dependencies`).
///
/// A witness revocation, an organization merge or a falsified consistency proof
/// arrives as a *coordinate* (witness DID, organization, log head), never as a
/// digest â€” digests are one-way, so `evidence_digest` cannot answer "which
/// bindings depend on witness X". This record can, and a store that declares
/// evidence-bearing methods MUST index it at least by witness DID.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDependencies {
    pub witness_dids: Vec<Did>,
    pub witness_controlling_organization_dids: Vec<Did>,
    pub history_heads: Vec<String>,
}
