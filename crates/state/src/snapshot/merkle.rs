use super::types::SnapshotChunk;
use crate::{Error, Hash, Result};

/// Binary Merkle tree over snapshot chunk digests.
///
/// Construction:
/// - Leaves are `sha256(0x00 || raw_digest)` in `chunk_id` order.
/// - Internal nodes are `sha256(0x01 || left || right)`.
/// - Odd levels promote the last node to the next level **unchanged** (RFC 6962-style; never
///   duplicate — see spec `event-auth-state-resolution.md` §4.2.2 for the house odd-layer rule).
///   Duplication would make `[A,B,C]` and `[A,B,C,C]` share a root (CVE-2012-2459-shaped
///   ambiguity).
/// - Single-leaf tree returns the domain-separated leaf hash as root.
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
        let leaf_data: Vec<Hash> = chunks.iter().map(|c| c.digest.clone()).collect();
        let levels = build_levels(&leaf_data)?;
        let leaves = levels[0].clone();
        Ok(Self { leaves, levels })
    }

    /// Number of leaf chunks.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Root hash. Single-leaf trees return the leaf.
    pub fn root(&self) -> &Hash {
        self.levels
            .last()
            .and_then(|l| l.first())
            .expect("levels invariant: non-empty")
    }

    /// RFC 6962-style audit path: siblings from leaf up to root,
    /// bottom-up. Promoted nodes (last node of an odd-sized level)
    /// contribute no sibling, so path lengths vary per leaf. Returns
    /// `None` when `leaf_index >= leaf_count`.
    pub fn audit_path(&self, leaf_index: usize) -> Option<Vec<Hash>> {
        if leaf_index >= self.leaf_count() {
            return None;
        }
        let mut path = Vec::new();
        let mut idx = leaf_index;
        for level in &self.levels[..self.levels.len() - 1] {
            if idx == level.len() - 1 && level.len() % 2 == 1 {
                // Promoted node: no sibling at this level.
            } else {
                let sibling_idx = if idx.is_multiple_of(2) {
                    idx + 1
                } else {
                    idx - 1
                };
                path.push(level[sibling_idx].clone());
            }
            idx /= 2;
        }
        Some(path)
    }

    /// Verify that `leaf` at `leaf_index` reconstructs to `root` given
    /// `audit_path`. Stateless — receivers can call this without
    /// rebuilding the tree. `leaf_count` drives the layer walk, so a
    /// proof is only accepted when `audit_path` has exactly the length
    /// the claimed `(leaf_index, leaf_count)` pair implies.
    pub fn verify(
        root: &Hash,
        leaf: &Hash,
        leaf_index: usize,
        audit_path: &[Hash],
        leaf_count: usize,
    ) -> bool {
        if leaf_count == 0 || leaf_index >= leaf_count {
            return false;
        }
        let Some(leaf_data) = parse_sha256(leaf) else {
            return false;
        };
        let mut current = hash_leaf(&leaf_data);
        let mut idx = leaf_index;
        let mut layer_size = leaf_count;
        let mut siblings = audit_path.iter();
        while layer_size > 1 {
            if idx == layer_size - 1 && layer_size % 2 == 1 {
                // Promoted node: consumes no sibling at this level.
            } else {
                let Some(sibling) = siblings.next() else {
                    return false; // path too short for the claimed leaf_count
                };
                let Some(sib_bytes) = parse_sha256(sibling) else {
                    return false;
                };
                let (left, right) = if idx.is_multiple_of(2) {
                    // We're left, sibling is right.
                    (current, sib_bytes)
                } else {
                    (sib_bytes, current)
                };
                current = hash_pair(&left, &right);
            }
            idx /= 2;
            // Layer-size for the next layer up.
            layer_size = layer_size.div_ceil(2);
        }
        if siblings.next().is_some() {
            return false; // path longer than the claimed leaf_count implies
        }
        let Some(root_bytes) = parse_sha256(root) else {
            return false;
        };
        current == root_bytes
    }
}

/// Build RFC 6962 levels from caller-supplied leaf data digests.
///
/// The input hashes are leaf *data*, not already-domain-separated Merkle
/// leaves. This distinction prevents callers from accidentally accepting the
/// legacy unprefixed tree.
pub(crate) fn build_levels(leaf_data: &[Hash]) -> Result<Vec<Vec<Hash>>> {
    let leaves = leaf_data
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            parse_sha256(leaf)
                .map(|bytes| format_hash(&hash_leaf(&bytes)))
                .ok_or_else(|| Error::Protocol(format!("Merkle leaf {index} not sha256: {leaf}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut levels: Vec<Vec<Hash>> = vec![leaves];
    while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let current = levels.last().expect("non-empty");
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                let left = parse_sha256(&current[i]).ok_or_else(|| {
                    Error::Protocol(format!("Merkle leaf {i} not sha256: {}", current[i]))
                })?;
                let right = parse_sha256(&current[i + 1]).ok_or_else(|| {
                    Error::Protocol(format!(
                        "Merkle leaf {} not sha256: {}",
                        i + 1,
                        current[i + 1]
                    ))
                })?;
                next.push(format_hash(&hash_pair(&left, &right)));
                i += 2;
            } else {
                // Odd node count: promote the single trailing node to the
                // next level unchanged (RFC 6962-style; never duplicate,
                // so [A,B,C] and [A,B,C,C] cannot share a root).
                next.push(current[i].clone());
                i += 1;
            }
        }
        levels.push(next);
    }
    Ok(levels)
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> Hash {
    Hash::new(crate::canonical::sha256_digest(bytes)).expect("sha256 wire form")
}

pub(crate) fn parse_sha256(hash: &Hash) -> Option<[u8; 32]> {
    let suffix = hash.as_str().strip_prefix("sha256:")?;
    if suffix.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(suffix, &mut out).ok()?;
    Some(out)
}

pub(crate) fn hash_leaf(leaf_data: &[u8]) -> [u8; 32] {
    crate::canonical::sha256_bytes_from_slices(&[&[0x00], leaf_data])
}

pub(crate) fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::canonical::sha256_bytes_from_slices(&[&[0x01], &left[..], &right[..]])
}

pub(crate) fn parent_hash(left: &Hash, right: &Hash) -> Result<Hash> {
    let left = parse_sha256(left)
        .ok_or_else(|| Error::Protocol(format!("Merkle node not sha256: {left}")))?;
    let right = parse_sha256(right)
        .ok_or_else(|| Error::Protocol(format!("Merkle node not sha256: {right}")))?;
    Ok(format_hash(&hash_pair(&left, &right)))
}

pub(crate) fn format_hash(bytes: &[u8; 32]) -> Hash {
    let hex = hex::encode(bytes);
    Hash::new(format!("sha256:{hex}")).expect("sha256 wire form")
}
