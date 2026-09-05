use serde_json::Value;

use super::constants::{DEFAULT_SNAPSHOT_CHUNK_BYTES, EMPTY_SHA256_DIGEST, SNAPSHOT_CHUNK_TYPE};
use super::merkle::{build_levels, sha256_digest};
use super::types::{
    BuiltSnapshotChunk, EventSetCommitment, EventSetCommitmentAlgorithm, EventSetLeaf,
    SnapshotChunk, SnapshotChunkDescriptor, SnapshotChunkPayload, SnapshotMaterializedItem,
    SnapshotValidationCode, SnapshotValidationError,
};
use crate::{BlobRef, Hash, Result, SnapshotId, WireError};

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
        Self {
            target_chunk_bytes: DEFAULT_SNAPSHOT_CHUNK_BYTES,
        }
    }
}

impl SnapshotChunker {
    pub fn new(target_chunk_bytes: usize) -> Result<Self> {
        if target_chunk_bytes == 0 {
            return Err(WireError::Protocol(
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
            let digest = sha256_digest(slice);
            out.push(SnapshotChunk {
                chunk_id: chunk_id as u32,
                bytes: slice.to_vec(),
                digest,
            });
        }
        out
    }
}

pub fn snapshot_chunk_payload_bytes(payload: &SnapshotChunkPayload) -> Result<Vec<u8>> {
    Ok(crate::canonical::canonical_json_bytes(payload)?)
}

pub fn build_snapshot_chunks(
    snapshot_ref: &SnapshotId,
    reducer_profile: &str,
    items: Vec<SnapshotMaterializedItem>,
    target_chunk_bytes: usize,
) -> Result<Vec<BuiltSnapshotChunk>> {
    build_snapshot_chunks_with_nonaccepted(
        snapshot_ref,
        reducer_profile,
        items,
        target_chunk_bytes,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

pub fn build_snapshot_chunks_with_nonaccepted(
    snapshot_ref: &SnapshotId,
    reducer_profile: &str,
    mut items: Vec<SnapshotMaterializedItem>,
    target_chunk_bytes: usize,
    conflict_records: Vec<Value>,
    soft_failed: Vec<Value>,
    quarantined: Vec<Value>,
) -> Result<Vec<BuiltSnapshotChunk>> {
    if target_chunk_bytes == 0 {
        return Err(WireError::Protocol(
            "snapshot target_chunk_bytes must be > 0".to_owned(),
        ));
    }
    sort_snapshot_items(&mut items);
    ensure_unique_snapshot_items(&items)?;

    let mut chunks = Vec::new();
    let mut pending = Vec::new();
    let mut pending_item_bytes = 0usize;
    let mut empty_payload_bytes = snapshot_chunk_payload_bytes(&SnapshotChunkPayload {
        chunk_kind: SNAPSHOT_CHUNK_TYPE.to_owned(),
        snapshot_ref: snapshot_ref.clone(),
        index: 0,
        reducer_profile: reducer_profile.to_owned(),
        items: Vec::new(),
        conflict_records: conflict_records.clone(),
        soft_failed: soft_failed.clone(),
        quarantined: quarantined.clone(),
    })?
    .len();
    for item in items {
        let item_bytes = crate::canonical::canonical_json_bytes(&item)?.len();
        let candidate_bytes = empty_payload_bytes
            .saturating_add(pending_item_bytes)
            .saturating_add(item_bytes)
            .saturating_add(pending.len());
        if !pending.is_empty() && candidate_bytes > target_chunk_bytes {
            let payload = SnapshotChunkPayload {
                chunk_kind: SNAPSHOT_CHUNK_TYPE.to_owned(),
                snapshot_ref: snapshot_ref.clone(),
                index: chunks.len() as u32,
                reducer_profile: reducer_profile.to_owned(),
                items: pending,
                conflict_records: if chunks.is_empty() {
                    conflict_records.clone()
                } else {
                    Vec::new()
                },
                soft_failed: if chunks.is_empty() {
                    soft_failed.clone()
                } else {
                    Vec::new()
                },
                quarantined: if chunks.is_empty() {
                    quarantined.clone()
                } else {
                    Vec::new()
                },
            };
            chunks.push(build_chunk_descriptor(payload)?);
            pending = vec![item];
            pending_item_bytes = item_bytes;
            empty_payload_bytes = snapshot_chunk_payload_bytes(&SnapshotChunkPayload {
                chunk_kind: SNAPSHOT_CHUNK_TYPE.to_owned(),
                snapshot_ref: snapshot_ref.clone(),
                index: chunks.len() as u32,
                reducer_profile: reducer_profile.to_owned(),
                items: Vec::new(),
                conflict_records: Vec::new(),
                soft_failed: Vec::new(),
                quarantined: Vec::new(),
            })?
            .len();
        } else {
            pending_item_bytes = pending_item_bytes.saturating_add(item_bytes);
            pending.push(item);
        }
    }

    if !pending.is_empty() || chunks.is_empty() {
        let payload = SnapshotChunkPayload {
            chunk_kind: SNAPSHOT_CHUNK_TYPE.to_owned(),
            snapshot_ref: snapshot_ref.clone(),
            index: chunks.len() as u32,
            reducer_profile: reducer_profile.to_owned(),
            items: pending,
            conflict_records: if chunks.is_empty() {
                conflict_records
            } else {
                Vec::new()
            },
            soft_failed: if chunks.is_empty() {
                soft_failed
            } else {
                Vec::new()
            },
            quarantined: if chunks.is_empty() {
                quarantined
            } else {
                Vec::new()
            },
        };
        chunks.push(build_chunk_descriptor(payload)?);
    }

    Ok(chunks)
}

pub fn state_digest_from_items(items: &[SnapshotMaterializedItem]) -> Result<Hash> {
    let mut sorted = items.to_vec();
    sort_snapshot_items(&mut sorted);
    ensure_unique_snapshot_items(&sorted)?;
    let mut leaves = Vec::with_capacity(sorted.len());
    for item in &sorted {
        leaves.push(snapshot_state_leaf_hash(item)?);
    }
    merkle_root_from_hashes(leaves)
}

/// The `state_digest` leaf of one snapshot item (`snapshot-schema.md` §4).
///
/// Both branches share the `kind:id:<inner digest>` shape; they differ in what
/// the inner digest covers. The `object` branch hashes the materialized object.
/// The `cas_cell` branch has no object, so it hashes the same
/// `{"cell","state"}` preimage that `event-auth-state-resolution.md` §6.2.1
/// gives the governance `state_root` leaf — one definition of a CAS cell's
/// canonical form, not two that can drift.
pub fn snapshot_state_leaf_hash(item: &SnapshotMaterializedItem) -> Result<Hash> {
    let inner = match item {
        SnapshotMaterializedItem::Object { object, .. } => {
            crate::canonical::sha256_digest(&crate::canonical::canonical_json_bytes(object)?)
        }
        SnapshotMaterializedItem::CasCell { cell, state } => {
            let preimage = serde_json::json!({
                "cell": cell.as_str(),
                "state": state,
            });
            crate::canonical::sha256_digest(&crate::canonical::canonical_json_bytes(&preimage)?)
        }
    };
    Ok(sha256_digest(
        format!("{}:{}:{}", item.kind(), item.id(), inner).as_bytes(),
    ))
}

pub fn event_set_commitment(
    algorithm: EventSetCommitmentAlgorithm,
    entries: &[EventSetLeaf],
) -> Result<EventSetCommitment> {
    let root = event_set_root(&algorithm, entries)?;
    Ok(EventSetCommitment {
        algorithm,
        root,
        covered_event_count: entries.len() as u64,
        actor_seq_ranges: Vec::new(),
    })
}

pub fn event_set_root(
    algorithm: &EventSetCommitmentAlgorithm,
    entries: &[EventSetLeaf],
) -> Result<Hash> {
    let sorted = sorted_event_set_entries(entries);
    match algorithm {
        EventSetCommitmentAlgorithm::OrderedEventIdSha256V1 => Ok(sha256_digest(
            &crate::canonical::canonical_json_bytes(&sorted)?,
        )),
        EventSetCommitmentAlgorithm::MerkleEventSetV1 => {
            let mut leaves = Vec::with_capacity(sorted.len());
            for entry in &sorted {
                leaves.push(sha256_digest(&crate::canonical::canonical_json_bytes(
                    entry,
                )?));
            }
            merkle_root_from_hashes(leaves)
        }
    }
}

pub fn merkle_root_from_hashes(leaves: Vec<Hash>) -> Result<Hash> {
    if leaves.is_empty() {
        return Hash::new(EMPTY_SHA256_DIGEST.to_owned()).map_err(WireError::from);
    }
    build_levels(&leaves).and_then(|levels| {
        levels
            .last()
            .and_then(|level| level.first())
            .cloned()
            .ok_or_else(|| WireError::Protocol("Merkle levels are empty".to_owned()))
    })
}

pub fn verify_snapshot_chunk_bytes(
    descriptor: &SnapshotChunkDescriptor,
    bytes: &[u8],
) -> std::result::Result<(), SnapshotValidationError> {
    if bytes.len() as u64 != descriptor.size_bytes {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!(
                "snapshot chunk size mismatch: descriptor {}, bytes {}",
                descriptor.size_bytes,
                bytes.len()
            ),
        ));
    }
    let expected = descriptor
        .chunk_ref
        .as_str()
        .strip_prefix("ak:blob:")
        .expect("validated BlobRef is content-addressed");
    arkret_canonical::canonical::verify_digest(bytes, expected).map_err(|_| {
        SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            "snapshot chunk bytes do not match chunk_ref",
        )
    })
}

fn sort_snapshot_items(items: &mut [SnapshotMaterializedItem]) {
    items.sort_by(|a, b| (a.kind(), a.id()).cmp(&(b.kind(), b.id())));
}

fn ensure_unique_snapshot_items(items: &[SnapshotMaterializedItem]) -> Result<()> {
    for pair in items.windows(2) {
        if pair[0].kind() == pair[1].kind() && pair[0].id() == pair[1].id() {
            return Err(WireError::Protocol(format!(
                "duplicate snapshot item key ({}, {})",
                pair[0].kind(),
                pair[0].id()
            )));
        }
    }
    Ok(())
}

fn build_chunk_descriptor(payload: SnapshotChunkPayload) -> Result<BuiltSnapshotChunk> {
    let canonical_bytes = snapshot_chunk_payload_bytes(&payload)?;
    let digest = sha256_digest(&canonical_bytes);
    let descriptor = SnapshotChunkDescriptor {
        chunk_ref: BlobRef::new(format!("ak:blob:{digest}")).map_err(WireError::from)?,
        size_bytes: canonical_bytes.len() as u64,
    };
    Ok(BuiltSnapshotChunk {
        payload,
        canonical_bytes,
        descriptor,
    })
}

fn sorted_event_set_entries(entries: &[EventSetLeaf]) -> Vec<EventSetLeaf> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_cached_key(|entry| {
        (
            arkret_wire::canonical::canonical_json_bytes(&entry.actor_id)
                .expect("validated ActorId has canonical JSON"),
            entry.actor_seq,
            entry.event_id.clone(),
        )
    });
    sorted
}
