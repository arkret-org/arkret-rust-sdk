use arkret_wire::Did;
use serde::{Deserialize, Serialize};

use super::merkle::sha256_digest;
use crate::{Hash, PayloadSignature, RealmId, Result, WireError};

/// Signed commitment from the snapshot generator. Receivers verify this
/// proof against the generator DID before trusting any chunks. Once
/// verified, the receiver can fetch chunks lazily and verify each one
/// against `merkle_root` via [`super::merkle::SnapshotMerkleTree::verify`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorProof {
    /// DID of the snapshot generator (typically the principal server's
    /// `service_id`).
    pub generator_did: Did,
    /// Realm whose state this snapshot covers.
    pub realm_id: RealmId,
    /// Canonical state-root from `effective_seal_view` at the snapshot
    /// frontier — what the snapshot claims to materialize.
    pub state_root: Hash,
    /// Root of the chunk-digest Merkle tree.
    pub merkle_root: Hash,
    /// Total number of chunks in the tree.
    pub chunk_count: u32,
    /// Total chunk-bytes (sum of per-chunk lengths). Lets receivers
    /// size buffers before fetching.
    pub total_bytes: u64,
    /// Per-chunk byte budget the chunker used. Receivers verify
    /// `chunks[i].bytes.len() == chunk_bytes` for `i < chunk_count - 1`
    /// (the last chunk MAY be smaller).
    pub chunk_bytes: u32,
    /// Signature over the canonical bytes of all the body fields above
    /// (everything except `signature`). The body is hashed via
    /// `proof.body_digest()`.
    pub signature: PayloadSignature,
}

#[derive(Serialize)]
struct GeneratorProofBody<'a> {
    generator_did: &'a Did,
    realm_id: &'a RealmId,
    state_root: &'a Hash,
    merkle_root: &'a Hash,
    chunk_count: u32,
    total_bytes: u64,
    chunk_bytes: u32,
}

impl GeneratorProof {
    /// Canonical bytes the generator signs and the receiver verifies
    /// against `signature.payload_digest`.
    pub fn body_bytes(
        generator_did: &Did,
        realm_id: &RealmId,
        state_root: &Hash,
        merkle_root: &Hash,
        chunk_count: u32,
        total_bytes: u64,
        chunk_bytes: u32,
    ) -> Result<Vec<u8>> {
        let body = GeneratorProofBody {
            generator_did,
            realm_id,
            state_root,
            merkle_root,
            chunk_count,
            total_bytes,
            chunk_bytes,
        };
        Ok(crate::canonical::canonical_json_bytes(&body)?)
    }

    /// SHA-256 of the canonical body bytes — convenience helper for
    /// generators populating `signature.payload_digest`.
    pub fn body_digest(
        generator_did: &Did,
        realm_id: &RealmId,
        state_root: &Hash,
        merkle_root: &Hash,
        chunk_count: u32,
        total_bytes: u64,
        chunk_bytes: u32,
    ) -> Result<Hash> {
        let bytes = Self::body_bytes(
            generator_did,
            realm_id,
            state_root,
            merkle_root,
            chunk_count,
            total_bytes,
            chunk_bytes,
        )?;
        Ok(sha256_digest(&bytes))
    }

    /// Recompute the canonical bytes for **this** proof and check
    /// whether they match `signature.payload_digest`. Returns Ok on
    /// match, Err with a diagnostic message otherwise. Does NOT verify
    /// the JWS itself — that's the caller's job (signature pluggability).
    pub fn verify_payload_digest(&self) -> Result<()> {
        let derived = Self::body_digest(
            &self.generator_did,
            &self.realm_id,
            &self.state_root,
            &self.merkle_root,
            self.chunk_count,
            self.total_bytes,
            self.chunk_bytes,
        )?;
        if derived != self.signature.payload_digest {
            return Err(WireError::Protocol(format!(
                "GeneratorProof payload_digest mismatch: declared {} but body hashes to {}",
                self.signature.payload_digest, derived
            )));
        }
        Ok(())
    }
}
