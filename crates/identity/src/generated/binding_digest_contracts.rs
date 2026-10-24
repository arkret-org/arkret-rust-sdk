// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/did-binding-contracts.schema.json
// sha256=fa20734c177646bef543831d5e8611fbe2d6743bfab11c992154ba2700543abb
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

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
