//! Snapshot chunk v2 — multi-chunk Merkle output with signed generator
//! proofs.
//!
//! The v1 snapshot wire is a single base64-url JSON blob: fine for small
//! Spaces, but doesn't scale to multi-megabyte projection dumps and
//! doesn't let receivers verify a single chunk without trusting the
//! whole bundle.
//!
//! v2 introduces three primitives:
//!
//! - [`SnapshotChunker`] — deterministically partitions a serialized
//!   snapshot blob into fixed-size byte ranges, each addressable by an
//!   ordinal `chunk_id` starting at 0. Boundaries are at exact byte
//!   offsets (`target_chunk_bytes`) so two implementations always
//!   produce the same chunk layout for the same input.
//! - [`SnapshotMerkleTree`] — a binary Merkle tree over chunk digests
//!   keyed by `chunk_id`. RFC 6962-style audit paths let receivers
//!   verify a single chunk's leaf hash against the root using just
//!   `O(log n)` sibling hashes.
//! - [`GeneratorProof`] — the generator's signed commitment to a
//!   snapshot frontier (`state_root` + `merkle_root` + `chunk_count`).
//!   Receivers verify the proof against the generator DID before
//!   trusting any chunks; chunks themselves don't need per-chunk
//!   signatures because their digests are committed in the Merkle root
//!   that the proof signs.
//!
//! Wire shape (round 8): the snapshot manifest endpoint
//! (`/api/v1/snapshot/head`) returns `chunk_count`, `merkle_root`,
//! and `generator_proof`; the chunk endpoint
//! (`/api/v1/snapshot/chunk?chunk_id=N`) returns the chunk bytes
//! plus the `audit_path[]` Merkle siblings. Receivers verify per-chunk.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Did, Error, Hash, MoveSignature, Result, SpaceId};

/// Default chunk size in bytes (256 KiB). Picked so a 100 MB snapshot
/// becomes ~400 chunks — small enough for HTTP delivery, large enough
/// that the per-chunk audit-path overhead stays negligible.
pub const DEFAULT_SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;

/// One byte range of a snapshot, addressable by `chunk_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotChunk {
    /// Ordinal index starting at 0. Chunks MUST be delivered in
    /// `chunk_id` order when streaming the whole snapshot.
    pub chunk_id: u32,
    /// Raw chunk bytes. The producer is responsible for the encoding
    /// (typically the canonical-JSON bytes of the snapshot blob); the
    /// chunker treats them as opaque.
    #[serde(with = "base64_url")]
    pub bytes: Vec<u8>,
    /// `sha256:<hex>` digest of `bytes`. Receivers recompute this
    /// before trusting the chunk.
    pub digest: Hash,
}

mod base64_url {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Deterministic snapshot chunker. Same input always produces the same
/// chunk layout, regardless of implementation.
#[derive(Clone, Debug)]
pub struct SnapshotChunker {
    /// Target bytes per chunk. The last chunk may be smaller; all
    /// non-final chunks are exactly this size. Must be > 0.
    pub target_chunk_bytes: usize,
}

impl Default for SnapshotChunker {
    fn default() -> Self {
        Self { target_chunk_bytes: DEFAULT_SNAPSHOT_CHUNK_BYTES }
    }
}

impl SnapshotChunker {
    pub fn new(target_chunk_bytes: usize) -> Result<Self> {
        if target_chunk_bytes == 0 {
            return Err(Error::Protocol(
                "SnapshotChunker target_chunk_bytes must be > 0".to_owned(),
            ));
        }
        Ok(Self { target_chunk_bytes })
    }

    /// Partition `bytes` into chunks. Empty input produces an empty
    /// vector — callers MAY treat that as a sentinel ("nothing to
    /// snapshot") or as an error depending on their use case.
    pub fn chunk(&self, bytes: &[u8]) -> Vec<SnapshotChunk> {
        if bytes.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(bytes.len().div_ceil(self.target_chunk_bytes));
        for (chunk_id, slice) in bytes.chunks(self.target_chunk_bytes).enumerate() {
            let digest = sha256_hash(slice);
            out.push(SnapshotChunk { chunk_id: chunk_id as u32, bytes: slice.to_vec(), digest });
        }
        out
    }
}

/// Binary Merkle tree over snapshot chunk digests.
///
/// Construction:
/// - Leaves are chunk digests in `chunk_id` order.
/// - Internal nodes are `sha256(left || right)` (raw 32-byte concat).
/// - Odd levels duplicate the last node (RFC 6962-style "promote single
///   child up").
/// - Single-leaf tree returns the leaf as root.
#[derive(Clone, Debug)]
pub struct SnapshotMerkleTree {
    leaves: Vec<Hash>,
    /// Per-level node lists from leaves up to root. `levels[0]` is the
    /// leaf level, `levels.last()` is `[root]`.
    levels: Vec<Vec<Hash>>,
}

impl SnapshotMerkleTree {
    /// Build a tree from chunks. Chunks MUST be in `chunk_id` order;
    /// the caller is responsible for sorting if the source iteration
    /// order isn't already ascending.
    pub fn build(chunks: &[SnapshotChunk]) -> Result<Self> {
        if chunks.is_empty() {
            return Err(Error::Protocol(
                "SnapshotMerkleTree requires at least one chunk".to_owned(),
            ));
        }
        // Verify ordering — fail closed instead of silently building a
        // tree that won't match the receiver's tree.
        for (i, chunk) in chunks.iter().enumerate() {
            if chunk.chunk_id as usize != i {
                return Err(Error::Protocol(format!(
                    "SnapshotMerkleTree chunk {i} has chunk_id={} (expected {i})",
                    chunk.chunk_id
                )));
            }
        }
        let leaves: Vec<Hash> = chunks.iter().map(|c| c.digest.clone()).collect();
        let levels = build_levels(&leaves)?;
        Ok(Self { leaves, levels })
    }

    /// Number of leaf chunks.
    pub fn tree_size(&self) -> usize {
        self.leaves.len()
    }

    /// Root hash. Single-leaf trees return the leaf.
    pub fn root(&self) -> &Hash {
        self.levels.last().and_then(|l| l.first()).expect("levels invariant: non-empty")
    }

    /// RFC 6962-style audit path: siblings from leaf up to root,
    /// bottom-up. Returns `None` when `leaf_index >= tree_size`.
    pub fn audit_path(&self, leaf_index: usize) -> Option<Vec<Hash>> {
        if leaf_index >= self.tree_size() {
            return None;
        }
        let mut path = Vec::new();
        let mut idx = leaf_index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 {
                if idx + 1 < level.len() { idx + 1 } else { idx } // promoted: same node
            } else {
                idx - 1
            };
            path.push(level[sibling_idx].clone());
            idx /= 2;
        }
        Some(path)
    }

    /// Verify that `leaf` at `leaf_index` reconstructs to `root` given
    /// `audit_path`. Stateless — receivers can call this without
    /// rebuilding the tree.
    pub fn verify(
        root: &Hash,
        leaf: &Hash,
        leaf_index: usize,
        audit_path: &[Hash],
        tree_size: usize,
    ) -> bool {
        if leaf_index >= tree_size {
            return false;
        }
        let Some(mut current) = parse_sha256(leaf) else {
            return false;
        };
        let mut idx = leaf_index;
        let mut layer_size = tree_size;
        for sibling in audit_path {
            let Some(sib_bytes) = parse_sha256(sibling) else {
                return false;
            };
            let (left, right) = if idx % 2 == 0 {
                // We're left, sibling is right (or promoted self).
                (current, sib_bytes)
            } else {
                (sib_bytes, current)
            };
            current = hash_pair(&left, &right);
            idx /= 2;
            // Layer-size for the next layer up.
            layer_size = layer_size.div_ceil(2);
        }
        let _ = layer_size;
        let Some(root_bytes) = parse_sha256(root) else {
            return false;
        };
        current == root_bytes
    }
}

fn build_levels(leaves: &[Hash]) -> Result<Vec<Vec<Hash>>> {
    let mut levels: Vec<Vec<Hash>> = vec![leaves.to_vec()];
    while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let current = levels.last().expect("non-empty");
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            let left = parse_sha256(&current[i]).ok_or_else(|| {
                Error::Protocol(format!("Merkle leaf {i} not sha256: {}", current[i]))
            })?;
            // Promote single child up when odd.
            let right_idx = if i + 1 < current.len() { i + 1 } else { i };
            let right = parse_sha256(&current[right_idx]).ok_or_else(|| {
                Error::Protocol(format!(
                    "Merkle leaf {right_idx} not sha256: {}",
                    current[right_idx]
                ))
            })?;
            let combined = hash_pair(&left, &right);
            next.push(format_hash(&combined));
            i += 2;
        }
        levels.push(next);
    }
    Ok(levels)
}

fn sha256_hash(bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Hash::new(format!("sha256:{hex}")).expect("sha256 wire form")
}

fn parse_sha256(hash: &Hash) -> Option<[u8; 32]> {
    let suffix = hash.as_str().strip_prefix("sha256:")?;
    if suffix.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&suffix[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn format_hash(bytes: &[u8; 32]) -> Hash {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Hash::new(format!("sha256:{hex}")).expect("sha256 wire form")
}

/// Signed commitment from the snapshot generator. Receivers verify this
/// proof against the generator DID before trusting any chunks. Once
/// verified, the receiver can fetch chunks lazily and verify each one
/// against `merkle_root` via [`SnapshotMerkleTree::verify`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GeneratorProof {
    /// DID of the snapshot generator (typically the principal server's
    /// `service_did`).
    pub generator_did: Did,
    /// Space whose state this snapshot covers.
    pub space_id: SpaceId,
    /// Canonical state-root from `effective_anchor_view` at the snapshot
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
    pub signature: MoveSignature,
}

#[derive(Serialize)]
struct GeneratorProofBody<'a> {
    generator_did: &'a Did,
    space_id: &'a SpaceId,
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
        space_id: &SpaceId,
        state_root: &Hash,
        merkle_root: &Hash,
        chunk_count: u32,
        total_bytes: u64,
        chunk_bytes: u32,
    ) -> Result<Vec<u8>> {
        let body = GeneratorProofBody {
            generator_did,
            space_id,
            state_root,
            merkle_root,
            chunk_count,
            total_bytes,
            chunk_bytes,
        };
        crate::canonical::canonical_json_bytes(&body)
    }

    /// SHA-256 of the canonical body bytes — convenience helper for
    /// generators populating `signature.payload_digest`.
    pub fn body_digest(
        generator_did: &Did,
        space_id: &SpaceId,
        state_root: &Hash,
        merkle_root: &Hash,
        chunk_count: u32,
        total_bytes: u64,
        chunk_bytes: u32,
    ) -> Result<Hash> {
        let bytes = Self::body_bytes(
            generator_did,
            space_id,
            state_root,
            merkle_root,
            chunk_count,
            total_bytes,
            chunk_bytes,
        )?;
        Ok(sha256_hash(&bytes))
    }

    /// Recompute the canonical bytes for **this** proof and check
    /// whether they match `signature.payload_digest`. Returns Ok on
    /// match, Err with a diagnostic message otherwise. Does NOT verify
    /// the JWS itself — that's the caller's job (signature pluggability).
    pub fn verify_payload_digest(&self) -> Result<()> {
        let derived = Self::body_digest(
            &self.generator_did,
            &self.space_id,
            &self.state_root,
            &self.merkle_root,
            self.chunk_count,
            self.total_bytes,
            self.chunk_bytes,
        )?;
        if derived != self.signature.payload_digest {
            return Err(Error::Protocol(format!(
                "GeneratorProof payload_digest mismatch: declared {} but body hashes to {}",
                self.signature.payload_digest, derived
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::new("did:web:generator.example".to_owned()).unwrap()
    }

    fn space() -> SpaceId {
        SpaceId::new("cx:space:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    // ── Chunker ───────────────────────────────────────────────────────

    #[test]
    fn chunker_zero_target_rejected() {
        let err = SnapshotChunker::new(0).unwrap_err();
        assert!(format!("{err}").contains("target_chunk_bytes must be > 0"));
    }

    #[test]
    fn chunker_empty_input_yields_empty() {
        let c = SnapshotChunker::default();
        assert!(c.chunk(&[]).is_empty());
    }

    #[test]
    fn chunker_partitions_with_last_chunk_short() {
        let c = SnapshotChunker::new(4).unwrap();
        let chunks = c.chunk(b"hello world!"); // 12 bytes → 3 chunks of 4
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].chunk_id, 0);
        assert_eq!(chunks[0].bytes, b"hell");
        assert_eq!(chunks[1].chunk_id, 1);
        assert_eq!(chunks[1].bytes, b"o wo");
        assert_eq!(chunks[2].chunk_id, 2);
        assert_eq!(chunks[2].bytes, b"rld!");

        // 13-byte input → 3 chunks (4 / 4 / 5? no — 4 / 4 / 5 isn't right;
        // chunks() of size 4 → 4,4,5 only if step > 4. std slice::chunks
        // is fixed-size so 13/4 = 3 full + 1 short = 4 chunks. Let me re-check.
        let c2 = SnapshotChunker::new(4).unwrap();
        let chunks2 = c2.chunk(b"hello world!!"); // 13 bytes
        assert_eq!(chunks2.len(), 4); // 4+4+4+1
        assert_eq!(chunks2[3].bytes.len(), 1);
    }

    #[test]
    fn chunker_digests_match_recomputation() {
        let c = SnapshotChunker::new(8).unwrap();
        let chunks = c.chunk(b"the quick brown fox jumps over the lazy dog");
        for chunk in &chunks {
            let recomputed = sha256_hash(&chunk.bytes);
            assert_eq!(chunk.digest, recomputed);
        }
    }

    #[test]
    fn chunker_is_deterministic_across_runs() {
        let c = SnapshotChunker::new(16).unwrap();
        let a = c.chunk(b"the quick brown fox jumps over the lazy dog");
        let b = c.chunk(b"the quick brown fox jumps over the lazy dog");
        assert_eq!(a, b);
    }

    // ── Merkle tree ───────────────────────────────────────────────────

    fn chunks(n: u32) -> Vec<SnapshotChunk> {
        let c = SnapshotChunker::new(4).unwrap();
        let mut bytes = Vec::new();
        for i in 0..(n * 4) {
            bytes.push((i % 256) as u8);
        }
        c.chunk(&bytes)
    }

    #[test]
    fn merkle_empty_rejected() {
        let err = SnapshotMerkleTree::build(&[]).unwrap_err();
        assert!(format!("{err}").contains("at least one chunk"));
    }

    #[test]
    fn merkle_out_of_order_rejected() {
        let mut cs = chunks(2);
        cs.swap(0, 1);
        let err = SnapshotMerkleTree::build(&cs).unwrap_err();
        assert!(format!("{err}").contains("expected"));
    }

    #[test]
    fn merkle_single_leaf_root_equals_leaf() {
        let cs = chunks(1);
        let tree = SnapshotMerkleTree::build(&cs).unwrap();
        assert_eq!(tree.tree_size(), 1);
        assert_eq!(tree.root(), &cs[0].digest);
        // Audit path is empty for single-leaf trees.
        assert_eq!(tree.audit_path(0).unwrap().len(), 0);
    }

    #[test]
    fn merkle_two_leaves_root_is_hash_pair() {
        let cs = chunks(2);
        let tree = SnapshotMerkleTree::build(&cs).unwrap();
        // root = sha256(leaf0 || leaf1).
        let left = parse_sha256(&cs[0].digest).unwrap();
        let right = parse_sha256(&cs[1].digest).unwrap();
        let expected = hash_pair(&left, &right);
        assert_eq!(*tree.root(), format_hash(&expected));
    }

    #[test]
    fn merkle_audit_path_verifies_each_leaf() {
        for n in [1u32, 2, 3, 4, 5, 8, 11] {
            let cs = chunks(n);
            let tree = SnapshotMerkleTree::build(&cs).unwrap();
            let root = tree.root().clone();
            for (i, chunk) in cs.iter().enumerate() {
                let path = tree.audit_path(i).unwrap();
                assert!(
                    SnapshotMerkleTree::verify(&root, &chunk.digest, i, &path, tree.tree_size()),
                    "audit_path verification failed for n={n} leaf={i}"
                );
            }
        }
    }

    #[test]
    fn merkle_audit_path_rejects_wrong_leaf() {
        let cs = chunks(4);
        let tree = SnapshotMerkleTree::build(&cs).unwrap();
        let path = tree.audit_path(0).unwrap();
        // Try to use leaf-0's path with leaf-1's digest — should fail.
        assert!(!SnapshotMerkleTree::verify(
            tree.root(),
            &cs[1].digest,
            0,
            &path,
            tree.tree_size()
        ));
    }

    #[test]
    fn merkle_out_of_range_index_rejected() {
        let cs = chunks(2);
        let tree = SnapshotMerkleTree::build(&cs).unwrap();
        assert!(tree.audit_path(2).is_none());
    }

    // ── GeneratorProof ─────────────────────────────────────────────────

    fn move_sig(payload_digest: Hash) -> MoveSignature {
        MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:generator.example#k1".to_owned(),
            payload_digest,
            created_at: chrono::Utc::now(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
    }

    #[test]
    fn generator_proof_body_digest_round_trips() {
        let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        let digest =
            GeneratorProof::body_digest(&did(), &space(), &state_root, &merkle_root, 42, 1024, 256)
                .unwrap();

        let proof = GeneratorProof {
            generator_did: did(),
            space_id: space(),
            state_root: state_root.clone(),
            merkle_root: merkle_root.clone(),
            chunk_count: 42,
            total_bytes: 1024,
            chunk_bytes: 256,
            signature: move_sig(digest.clone()),
        };
        proof.verify_payload_digest().unwrap();
    }

    #[test]
    fn generator_proof_mismatched_payload_digest_rejected() {
        let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        let wrong = Hash::new(format!("sha256:{}", "ee".repeat(32))).unwrap();
        let proof = GeneratorProof {
            generator_did: did(),
            space_id: space(),
            state_root,
            merkle_root,
            chunk_count: 1,
            total_bytes: 4,
            chunk_bytes: 4,
            signature: move_sig(wrong),
        };
        let err = proof.verify_payload_digest().unwrap_err();
        assert!(format!("{err}").contains("payload_digest mismatch"));
    }

    #[test]
    fn generator_proof_changing_chunk_count_changes_digest() {
        let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        let d1 = GeneratorProof::body_digest(&did(), &space(), &state_root, &merkle_root, 1, 4, 4)
            .unwrap();
        let d2 = GeneratorProof::body_digest(&did(), &space(), &state_root, &merkle_root, 2, 4, 4)
            .unwrap();
        assert_ne!(d1, d2, "chunk_count must be in the canonical bytes");
    }

    #[test]
    fn generator_proof_serializes_with_all_fields() {
        let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        let digest =
            GeneratorProof::body_digest(&did(), &space(), &state_root, &merkle_root, 3, 12, 4)
                .unwrap();
        let proof = GeneratorProof {
            generator_did: did(),
            space_id: space(),
            state_root,
            merkle_root,
            chunk_count: 3,
            total_bytes: 12,
            chunk_bytes: 4,
            signature: move_sig(digest),
        };
        let v: serde_json::Value = serde_json::to_value(&proof).unwrap();
        for f in [
            "generator_did",
            "space_id",
            "state_root",
            "merkle_root",
            "chunk_count",
            "total_bytes",
            "chunk_bytes",
            "signature",
        ] {
            assert!(v.get(f).is_some(), "missing {f}");
        }
    }

    #[test]
    fn snapshot_chunk_round_trips_base64() {
        let chunk = SnapshotChunk {
            chunk_id: 7,
            bytes: vec![0x00, 0xff, 0x42, 0x55],
            digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
        };
        let s = serde_json::to_string(&chunk).unwrap();
        let back: SnapshotChunk = serde_json::from_str(&s).unwrap();
        assert_eq!(back, chunk);
    }
}
