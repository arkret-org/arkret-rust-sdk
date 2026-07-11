use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const KEY_TRANSPARENCY_SCHEMA: &str = "ak.schema.key_transparency.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyTransparencyEvidence {
    pub schema: String,
    pub log_service_did: String,
    pub principal_id: String,
    pub key_material_digest: String,
    pub log_head: TransparencyLogHead,
    pub inclusion_proof: TransparencyInclusionProof,
    pub consistency_proof: TransparencyConsistencyProof,
    pub witness_signatures: Vec<TransparencyWitnessSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLogHead {
    pub tree_size: u64,
    pub root_hash: String,
    pub issued_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyInclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub audit_path: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyConsistencyProof {
    pub from_tree_size: u64,
    pub to_tree_size: u64,
    pub audit_path: Vec<String>,
}

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
        if self.inclusion_proof.tree_size != self.log_head.tree_size
            || self.consistency_proof.to_tree_size != self.log_head.tree_size
            || self.consistency_proof.from_tree_size > self.consistency_proof.to_tree_size
        {
            return Err(KeyTransparencyError::TreeSizeMismatch);
        }
        if self.inclusion_proof.leaf_index >= self.inclusion_proof.tree_size {
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
