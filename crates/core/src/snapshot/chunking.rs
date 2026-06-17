use std::collections::BTreeSet;

use chrono::Duration;
use serde_json::Value;

use super::constants::{
    DEFAULT_SNAPSHOT_CHUNK_BYTES, DETACHED_JWS_ALG_EDDSA, DETACHED_JWS_PROOF_KIND,
    EMPTY_SHA256_DIGEST, SNAPSHOT_CHUNK_TYPE, SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS,
    SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS,
};
use super::merkle::{build_levels, sha256_digest};
use super::types::{
    BuiltSnapshotChunk, EventSetCommitment, EventSetCommitmentAlgorithm, EventSetLeaf,
    SnapshotChunk, SnapshotChunkDescriptor, SnapshotChunkPayload, SnapshotManifest,
    SnapshotMaterializedItem, SnapshotSecurityClass, SnapshotValidationCode,
    SnapshotValidationError, SnapshotVerifyOptions, SnapshotVerifyReport,
};
use crate::{BlobRef, Error, EventId, Hash, Result, SnapshotId};

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
    crate::canonical::canonical_json_bytes(payload)
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
        return Err(Error::Protocol(
            "snapshot target_chunk_bytes must be > 0".to_owned(),
        ));
    }
    sort_snapshot_items(&mut items);
    ensure_unique_snapshot_items(&items)?;

    let mut chunks = Vec::new();
    let mut pending = Vec::new();
    for item in items {
        let mut candidate = pending.clone();
        candidate.push(item.clone());
        let candidate_payload = SnapshotChunkPayload {
            chunk_type: SNAPSHOT_CHUNK_TYPE.to_owned(),
            snapshot_ref: snapshot_ref.clone(),
            index: chunks.len() as u32,
            reducer_profile: reducer_profile.to_owned(),
            items: candidate,
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
        let candidate_bytes = snapshot_chunk_payload_bytes(&candidate_payload)?;
        if !pending.is_empty() && candidate_bytes.len() > target_chunk_bytes {
            let payload = SnapshotChunkPayload {
                chunk_type: SNAPSHOT_CHUNK_TYPE.to_owned(),
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
        } else {
            pending.push(item);
        }
    }

    if !pending.is_empty() || chunks.is_empty() {
        let payload = SnapshotChunkPayload {
            chunk_type: SNAPSHOT_CHUNK_TYPE.to_owned(),
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

pub fn snapshot_state_leaf_hash(item: &SnapshotMaterializedItem) -> Result<Hash> {
    let object_bytes = crate::canonical::canonical_json_bytes(&item.object)?;
    let object_digest = crate::canonical::sha256_digest(&object_bytes);
    Ok(sha256_digest(
        format!("{}:{}:{}", item.kind, item.id, object_digest).as_bytes(),
    ))
}

pub fn event_set_commitment(
    algorithm: EventSetCommitmentAlgorithm,
    entries: &[EventSetLeaf],
    covered_seals: Vec<EventId>,
) -> Result<EventSetCommitment> {
    let root = event_set_root(&algorithm, entries)?;
    Ok(EventSetCommitment {
        algorithm,
        root,
        covered_event_count: entries.len() as u64,
        covered_seals,
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
        return Hash::new(EMPTY_SHA256_DIGEST.to_owned()).map_err(Error::from);
    }
    build_levels(&leaves).and_then(|levels| {
        levels
            .last()
            .and_then(|level| level.first())
            .cloned()
            .ok_or_else(|| Error::Protocol("Merkle levels are empty".to_owned()))
    })
}

pub fn manifest_frontiers_match(manifest: &SnapshotManifest) -> bool {
    event_id_sets_equal(
        &manifest.frontier.event_ids,
        &manifest.event_set_commitment.covered_seals,
    )
}

pub fn event_id_sets_equal(a: &[EventId], b: &[EventId]) -> bool {
    let left: BTreeSet<_> = a.iter().collect();
    let right: BTreeSet<_> = b.iter().collect();
    left == right
}

pub fn verify_snapshot_chunk_descriptors(
    descriptors: &[SnapshotChunkDescriptor],
    payloads: &[SnapshotChunkPayload],
) -> Result<()> {
    if descriptors.len() != payloads.len() {
        return Err(Error::Protocol("snapshot chunk count mismatch".to_owned()));
    }
    for (expected, payload) in descriptors.iter().zip(payloads.iter()) {
        let bytes = snapshot_chunk_payload_bytes(payload)?;
        let digest = sha256_digest(&bytes);
        if expected.digest != digest {
            return Err(Error::Protocol(format!(
                "snapshot chunk {} digest mismatch",
                payload.index
            )));
        }
        if expected.size_bytes != bytes.len() as u64 {
            return Err(Error::Protocol(format!(
                "snapshot chunk {} size_bytes mismatch",
                payload.index
            )));
        }
        verify_snapshot_chunk_ref_digest(expected).map_err(|err| Error::Protocol(err.message))?;
    }
    Ok(())
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
    let actual = sha256_digest(bytes);
    if descriptor.digest != actual {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!(
                "snapshot chunk digest mismatch: descriptor {}, bytes {}",
                descriptor.digest, actual
            ),
        ));
    }
    verify_snapshot_chunk_ref_digest(descriptor)
}

pub fn parse_verified_snapshot_chunk_bytes(
    descriptor: &SnapshotChunkDescriptor,
    bytes: &[u8],
) -> std::result::Result<SnapshotChunkPayload, SnapshotValidationError> {
    verify_snapshot_chunk_bytes(descriptor, bytes)?;
    serde_json::from_slice(bytes).map_err(|err| {
        SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!("snapshot chunk JSON decode failed: {err}"),
        )
    })
}

pub fn verify_snapshot_manifest(
    manifest: &SnapshotManifest,
    chunks: &[SnapshotChunkPayload],
    options: &SnapshotVerifyOptions,
) -> std::result::Result<SnapshotVerifyReport, SnapshotValidationError> {
    manifest.validate_manifest_only(options)?;
    if chunks.len() != manifest.chunks.len() {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!(
                "snapshot chunk count mismatch: manifest has {}, payloads have {}",
                manifest.chunks.len(),
                chunks.len()
            ),
        ));
    }

    let mut keys = BTreeSet::new();
    let mut previous_key: Option<(String, String)> = None;
    let mut items = Vec::new();
    let mut source_event_ids = Vec::new();
    for (index, (descriptor, payload)) in manifest.chunks.iter().zip(chunks.iter()).enumerate() {
        let bytes = snapshot_chunk_payload_bytes(payload).map_err(|err| {
            SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!("snapshot chunk {index} canonicalization failed: {err}"),
            )
        })?;
        verify_snapshot_chunk_bytes(descriptor, &bytes)?;
        if payload.chunk_type != SNAPSHOT_CHUNK_TYPE {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!(
                    "snapshot chunk {index} has invalid type '{}'",
                    payload.chunk_type
                ),
            ));
        }
        if payload.snapshot_ref != manifest.id {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!("snapshot chunk {index} snapshot_ref does not match manifest id"),
            ));
        }
        if payload.index != index as u32 {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!("snapshot chunk {index} payload index is {}", payload.index),
            ));
        }
        if payload.reducer_profile != manifest.reducer_profile {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!("snapshot chunk {index} reducer_profile mismatch"),
            ));
        }
        for item in &payload.items {
            let key = (item.kind.clone(), item.id.clone());
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(SnapshotValidationError::new(
                    SnapshotValidationCode::DigestMismatch,
                    "snapshot chunk items are not strictly sorted by (kind,id)",
                ));
            }
            if !keys.insert(key.clone()) {
                return Err(SnapshotValidationError::new(
                    SnapshotValidationCode::DigestMismatch,
                    format!("duplicate snapshot item ({},{})", key.0, key.1),
                ));
            }
            previous_key = Some(key);
            source_event_ids.push(item.source_event_id.clone());
            items.push(item.clone());
        }
    }

    let computed_state_digest = state_digest_from_items(&items).map_err(|err| {
        SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!("snapshot state_digest could not be computed: {err}"),
        )
    })?;
    if computed_state_digest != manifest.state_digest {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!(
                "snapshot state_digest mismatch: manifest {}, computed {}",
                manifest.state_digest, computed_state_digest
            ),
        ));
    }

    Ok(SnapshotVerifyReport {
        item_count: keys.len(),
        chunk_count: chunks.len(),
        state_digest: computed_state_digest,
        source_event_ids,
    })
}

fn verify_snapshot_chunk_ref_digest(
    descriptor: &SnapshotChunkDescriptor,
) -> std::result::Result<(), SnapshotValidationError> {
    if let Some(hex) = descriptor
        .chunk_ref
        .as_str()
        .strip_prefix("ck:blob:sha256:")
    {
        let expected = format!("sha256:{hex}");
        if expected != descriptor.digest.as_str() {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                "snapshot chunk_ref digest does not match descriptor digest",
            ));
        }
    }
    Ok(())
}

fn sort_snapshot_items(items: &mut [SnapshotMaterializedItem]) {
    items.sort_by(|a, b| {
        let left = (&a.kind, &a.id);
        let right = (&b.kind, &b.id);
        left.cmp(&right)
    });
}

fn ensure_unique_snapshot_items(items: &[SnapshotMaterializedItem]) -> Result<()> {
    for pair in items.windows(2) {
        if pair[0].kind == pair[1].kind && pair[0].id == pair[1].id {
            return Err(Error::Protocol(format!(
                "duplicate snapshot item key ({}, {})",
                pair[0].kind, pair[0].id
            )));
        }
    }
    Ok(())
}

fn build_chunk_descriptor(payload: SnapshotChunkPayload) -> Result<BuiltSnapshotChunk> {
    let canonical_bytes = snapshot_chunk_payload_bytes(&payload)?;
    let digest = sha256_digest(&canonical_bytes);
    let descriptor = SnapshotChunkDescriptor {
        chunk_ref: BlobRef::new(format!("ck:blob:{digest}")).map_err(Error::from)?,
        digest,
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
    sorted.sort_by(|a, b| {
        let left = (a.actor_id.as_str(), a.actor_seq, a.event_id.as_str());
        let right = (b.actor_id.as_str(), b.actor_seq, b.event_id.as_str());
        left.cmp(&right)
    });
    sorted
}

impl SnapshotManifest {
    pub fn validate_manifest_only(
        &self,
        options: &SnapshotVerifyOptions,
    ) -> std::result::Result<(), SnapshotValidationError> {
        if self.reducer_profile != options.expected_reducer_profile {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!(
                    "snapshot reducer_profile '{}' does not match expected '{}'",
                    self.reducer_profile, options.expected_reducer_profile
                ),
            ));
        }
        if self.schema_profile_refs.is_empty() {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SnapshotUnavailable,
                "snapshot schema_profile_refs must not be empty",
            ));
        }
        if self.chunks.is_empty() {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SnapshotUnavailable,
                "snapshot chunks must not be empty",
            ));
        }
        if self.authority_binding.issuer != self.created_by {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SnapshotAuthorityUnverified,
                "snapshot authority_binding.issuer does not match created_by",
            ));
        }
        if self.signature.kind != DETACHED_JWS_PROOF_KIND
            || self.signature.alg != DETACHED_JWS_ALG_EDDSA
            || self.signature.verification_method.trim().is_empty()
            || self.signature.jws.trim().is_empty()
        {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SnapshotAuthorityUnverified,
                "snapshot signature is not a production EdDSA detached JWS proof",
            ));
        }
        let expected_digest = self.expected_signature_digest().map_err(|err| {
            SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!("snapshot signature payload digest could not be computed: {err}"),
            )
        })?;
        if self.signature.payload_digest != expected_digest {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                "snapshot signature payload_digest does not match manifest canonical bytes",
            ));
        }
        if !manifest_frontiers_match(self) {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::InclusionProofFailed,
                "event_set_commitment.covered_seals does not match frontier.event_ids",
            ));
        }

        let max_age = match self.security_class {
            SnapshotSecurityClass::Standard => {
                Duration::milliseconds(SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS)
            }
            SnapshotSecurityClass::HighAssurance => {
                if !options.allow_high_assurance {
                    return Err(SnapshotValidationError::new(
                        SnapshotValidationCode::InclusionProofFailed,
                        "high_assurance snapshot verification is not enabled",
                    ));
                }
                Duration::milliseconds(SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS)
            }
        };
        if self.created_at > options.now + Duration::minutes(5) {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SnapshotAuthorityUnverified,
                "snapshot created_at is too far in the future",
            ));
        }
        if options.now - self.created_at > max_age {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SnapshotIssuerRevoked,
                "snapshot manifest is outside the acceptance window",
            ));
        }
        Ok(())
    }
}
