//! Key-transparency evidence wire shapes (`ak.schema.key_transparency.v1`):
//! log head, inclusion/consistency proofs, and witness signatures.

use arkret_wire::DidUrl;
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyTransparencyEvidence {
    pub schema: String,
    pub log_service_id: String,
    pub principal_id: String,
    pub key_material_digest: String,
    pub log_head: TransparencyLogHead,
    pub inclusion_proof: TransparencyInclusionProof,
    pub consistency_proof: TransparencyConsistencyProof,
    pub witness_signatures: Vec<TransparencyWitnessSignature>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLogHead {
    pub leaf_count: u64,
    pub tree_root: String,
    pub issued_at: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyInclusionProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub audit_path: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyConsistencyProof {
    pub from_leaf_count: u64,
    pub to_leaf_count: u64,
    pub audit_path: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyWitnessSignature {
    pub witness_did: String,
    pub verification_method: DidUrl,
    pub signature: String,
}
