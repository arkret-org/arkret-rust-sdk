// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/did-binding-contracts.schema.json
// sha256=ebb5bf702cab4bfb1c8fc1a0b843a48021723633d08116cef2b33bc1f54449fa
//
// Bindings: tools/closed-model-bindings.json
// sha256=ee958bb963f35540b3d330cc3731d78e388ab09c402e48014a9739bbca5c1c40

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
