//! Key-transparency evidence wire shapes (`ak.schema.key_transparency.v1`):
//! log head, inclusion/consistency proofs, witness signatures, and their
//! structural validation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const KEY_TRANSPARENCY_SCHEMA: &str = "ak.schema.key_transparency.v1";

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
    pub verification_method: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum KeyTransparencyError {
    #[error("key_transparency_proof_missing: schema id is not canonical")]
    SchemaMismatch,
    #[error("key_transparency_proof_missing: log proof tree sizes do not match")]
    TreeSizeMismatch,
    #[error("key_transparency_proof_missing: inclusion leaf is outside the tree")]
    LeafOutsideTree,
    #[error("key_transparency_proof_missing: at least two distinct witnesses are required")]
    InsufficientDistinctWitnesses,
}

impl KeyTransparencyEvidence {
    pub fn validate_structure(&self) -> Result<(), KeyTransparencyError> {
        if self.schema != KEY_TRANSPARENCY_SCHEMA {
            return Err(KeyTransparencyError::SchemaMismatch);
        }
        if self.inclusion_proof.leaf_count != self.log_head.leaf_count
            || self.consistency_proof.to_leaf_count != self.log_head.leaf_count
            || self.consistency_proof.from_leaf_count > self.consistency_proof.to_leaf_count
        {
            return Err(KeyTransparencyError::TreeSizeMismatch);
        }
        if self.inclusion_proof.leaf_index >= self.inclusion_proof.leaf_count {
            return Err(KeyTransparencyError::LeafOutsideTree);
        }
        let witnesses = self
            .witness_signatures
            .iter()
            .map(|signature| signature.witness_did.as_str())
            .collect::<BTreeSet<_>>();
        if witnesses.len() < 2 {
            return Err(KeyTransparencyError::InsufficientDistinctWitnesses);
        }
        Ok(())
    }
}
