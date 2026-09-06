use arkret_canonical::DigestSuite;
use serde::Serialize;

use super::constants::{
    DEFAULT_REALM_STATE_SNAPSHOT_CHUNK_BYTES, EMPTY_SHA256_DIGEST, REALM_STATE_SNAPSHOT_CHUNK_TYPE,
};
use super::merkle::{build_levels, sha256_digest};
use super::types::{
    BuiltRealmStateSnapshotChunk, EventSetCommitment, EventSetCommitmentAlgorithm, EventSetLeaf,
    RealmStateSnapshotChunk, RealmStateSnapshotChunkDescriptor, RealmStateSnapshotChunkPayload,
    RealmStateSnapshotConflictRecord, RealmStateSnapshotMaterializedItem,
    RealmStateSnapshotValidationCode, RealmStateSnapshotValidationError, SnapshotErasureStub,
    SnapshotNonAcceptedInput,
};
use crate::{BlobRef, Hash, RealmStateSnapshotId, Result, WireError};

/// Deterministic snapshot chunker. Same input always produces the same
/// chunk layout, regardless of implementation.
#[derive(Clone, Debug)]
pub struct RealmStateSnapshotChunker {
    /// Target bytes per chunk. The last chunk may be smaller; all
    /// non-final chunks are exactly this size. Must be > 0.
    pub target_chunk_bytes: usize,
}

impl Default for RealmStateSnapshotChunker {
    fn default() -> Self {
        Self {
            target_chunk_bytes: DEFAULT_REALM_STATE_SNAPSHOT_CHUNK_BYTES,
        }
    }
}

impl RealmStateSnapshotChunker {
    pub fn new(target_chunk_bytes: usize) -> Result<Self> {
        if target_chunk_bytes == 0 {
            return Err(WireError::Protocol(
                "RealmStateSnapshotChunker target_chunk_bytes must be > 0".to_owned(),
            ));
        }
        Ok(Self { target_chunk_bytes })
    }

    /// Partition `bytes` into chunks. Empty input produces an empty
    /// vector — callers MAY treat that as a sentinel ("nothing to
    /// snapshot") or as an error depending on their use case.
    pub fn chunk(&self, bytes: &[u8]) -> Vec<RealmStateSnapshotChunk> {
        if bytes.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(bytes.len().div_ceil(self.target_chunk_bytes));
        for (chunk_id, slice) in bytes.chunks(self.target_chunk_bytes).enumerate() {
            let digest = sha256_digest(slice);
            out.push(RealmStateSnapshotChunk {
                chunk_id: chunk_id as u32,
                bytes: slice.to_vec(),
                digest,
            });
        }
        out
    }
}

pub fn realm_state_snapshot_chunk_payload_bytes(
    payload: &RealmStateSnapshotChunkPayload,
) -> Result<Vec<u8>> {
    Ok(crate::canonical::canonical_json_bytes(payload)?)
}

/// The four auxiliary lists a chunk payload carries beside `items[]`
/// (`realm-state-snapshot-schema.md` §3). None of them is a `state_digest` leaf; each is
/// committed through its own manifest `verification_hints.*_digest`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotAuxiliaryLists {
    pub conflict_records: Vec<RealmStateSnapshotConflictRecord>,
    pub soft_failed: Vec<SnapshotNonAcceptedInput>,
    pub quarantined: Vec<SnapshotNonAcceptedInput>,
    pub erasure_stubs: Vec<SnapshotErasureStub>,
}

pub fn build_realm_state_snapshot_chunks(
    realm_state_snapshot_ref: &RealmStateSnapshotId,
    reducer_profile: &str,
    items: Vec<RealmStateSnapshotMaterializedItem>,
    target_chunk_bytes: usize,
) -> Result<Vec<BuiltRealmStateSnapshotChunk>> {
    build_realm_state_snapshot_chunks_with_auxiliary_lists(
        realm_state_snapshot_ref,
        reducer_profile,
        items,
        target_chunk_bytes,
        SnapshotAuxiliaryLists::default(),
    )
}

/// Build the chunk payloads of one snapshot.
///
/// Items are sorted by cell id (Unicode code point order, `realm-state-snapshot-schema.md`
/// §3) and must be unique; chunk boundaries fall on whole items. The auxiliary
/// lists ride in the first chunk — the digest rule concatenates them across
/// chunks in index order, so where they sit does not change any commitment.
pub fn build_realm_state_snapshot_chunks_with_auxiliary_lists(
    realm_state_snapshot_ref: &RealmStateSnapshotId,
    reducer_profile: &str,
    mut items: Vec<RealmStateSnapshotMaterializedItem>,
    target_chunk_bytes: usize,
    auxiliary: SnapshotAuxiliaryLists,
) -> Result<Vec<BuiltRealmStateSnapshotChunk>> {
    if target_chunk_bytes == 0 {
        return Err(WireError::Protocol(
            "snapshot target_chunk_bytes must be > 0".to_owned(),
        ));
    }
    sort_realm_state_snapshot_items(&mut items);
    ensure_unique_realm_state_snapshot_items(&items)?;

    let payload = |index: usize,
                   items: Vec<RealmStateSnapshotMaterializedItem>,
                   auxiliary: Option<SnapshotAuxiliaryLists>| {
        let auxiliary = auxiliary.unwrap_or_default();
        RealmStateSnapshotChunkPayload {
            chunk_kind: REALM_STATE_SNAPSHOT_CHUNK_TYPE.to_owned(),
            realm_state_snapshot_ref: realm_state_snapshot_ref.clone(),
            index: index as u32,
            reducer_profile: reducer_profile.to_owned(),
            items,
            conflict_records: auxiliary.conflict_records,
            soft_failed: auxiliary.soft_failed,
            quarantined: auxiliary.quarantined,
            erasure_stubs: auxiliary.erasure_stubs,
        }
    };

    let mut auxiliary = Some(auxiliary);
    let mut chunks = Vec::new();
    let mut pending = Vec::new();
    let mut pending_item_bytes = 0usize;
    let mut empty_payload_bytes =
        realm_state_snapshot_chunk_payload_bytes(&payload(0, Vec::new(), auxiliary.clone()))?.len();
    for item in items {
        let item_bytes = crate::canonical::canonical_json_bytes(&item)?.len();
        let candidate_bytes = empty_payload_bytes
            .saturating_add(pending_item_bytes)
            .saturating_add(item_bytes)
            .saturating_add(pending.len());
        if !pending.is_empty() && candidate_bytes > target_chunk_bytes {
            chunks.push(build_chunk_descriptor(payload(
                chunks.len(),
                std::mem::take(&mut pending),
                auxiliary.take(),
            ))?);
            pending = vec![item];
            pending_item_bytes = item_bytes;
            empty_payload_bytes =
                realm_state_snapshot_chunk_payload_bytes(&payload(chunks.len(), Vec::new(), None))?
                    .len();
        } else {
            pending_item_bytes = pending_item_bytes.saturating_add(item_bytes);
            pending.push(item);
        }
    }

    if !pending.is_empty() || chunks.is_empty() {
        chunks.push(build_chunk_descriptor(payload(
            chunks.len(),
            pending,
            auxiliary.take(),
        ))?);
    }

    Ok(chunks)
}

/// `state_digest` over already-validated items under SHA-256.
///
/// Sorting and de-duplication are applied here because a producer's item set
/// is unordered; a consumer verifying delivered chunks must use
/// [`state_digest_from_chunk_payloads`], which refuses to reorder.
pub fn state_digest_from_items(items: &[RealmStateSnapshotMaterializedItem]) -> Result<Hash> {
    state_digest_from_items_with_digest_suite(items, DigestSuite::Sha256)
}

/// [`state_digest_from_items`] under the Realm's live digest suite
/// (`realm-state-snapshot-schema.md` §4: `state_digest` and the Seal `state_root` share
/// one suite).
pub fn state_digest_from_items_with_digest_suite(
    items: &[RealmStateSnapshotMaterializedItem],
    digest_suite: DigestSuite,
) -> Result<Hash> {
    let mut sorted = items.to_vec();
    sort_realm_state_snapshot_items(&mut sorted);
    ensure_unique_realm_state_snapshot_items(&sorted)?;
    state_digest_from_sorted_items(sorted.iter(), digest_suite)
}

/// The consumer-side `state_digest` recomputation of `realm-state-snapshot-schema.md`
/// §3 / §4 over delivered chunk payloads.
///
/// It enforces what a producer's builder guarantees and a verifier must not
/// assume: contiguous chunk indexes, the manifest's `reducer_profile` in every
/// chunk, and items strictly ascending by cell id across the whole snapshot
/// with no duplicate. Nothing is reordered on the consumer's behalf — an
/// unsorted or duplicated item set is a malformed snapshot, not a hint.
pub fn state_digest_from_chunk_payloads(
    chunks: &[RealmStateSnapshotChunkPayload],
    expected_reducer_profile: &str,
    digest_suite: DigestSuite,
) -> Result<Hash> {
    if chunks.is_empty() {
        return Err(WireError::Protocol(
            "a snapshot carries at least one chunk payload".to_owned(),
        ));
    }
    for (position, chunk) in chunks.iter().enumerate() {
        if chunk.chunk_kind != REALM_STATE_SNAPSHOT_CHUNK_TYPE {
            return Err(WireError::Protocol(format!(
                "snapshot chunk {position} has chunk_kind {:?}; expected {REALM_STATE_SNAPSHOT_CHUNK_TYPE:?}",
                chunk.chunk_kind
            )));
        }
        if chunk.index as usize != position {
            return Err(WireError::Protocol(format!(
                "snapshot chunk at position {position} declares index {}; chunks must be \
                 contiguous and in ascending index order",
                chunk.index
            )));
        }
        if chunk.reducer_profile != expected_reducer_profile {
            return Err(WireError::Protocol(format!(
                "snapshot chunk {position} carries reducer_profile {:?}; the manifest says {:?}",
                chunk.reducer_profile, expected_reducer_profile
            )));
        }
    }
    let items = chunks.iter().flat_map(|chunk| chunk.items.iter());
    let mut previous: Option<&RealmStateSnapshotMaterializedItem> = None;
    for item in items.clone() {
        if let Some(previous) = previous
            && previous.id().as_bytes() >= item.id().as_bytes()
        {
            return Err(WireError::Protocol(format!(
                "snapshot items must be strictly ascending by cell id across chunks; {} is not \
                 after {}",
                item.id(),
                previous.id()
            )));
        }
        previous = Some(item);
    }
    state_digest_from_sorted_items(items, digest_suite)
}

fn state_digest_from_sorted_items<'a>(
    items: impl Iterator<Item = &'a RealmStateSnapshotMaterializedItem>,
    digest_suite: DigestSuite,
) -> Result<Hash> {
    let leaf_data = items
        .map(|item| crate::canonical::canonical_json_bytes(&item.leaf_preimage()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    crate::state::state_root::seal_merkle_root_from_leaf_data(&leaf_data, digest_suite)
}

/// The `state_digest` leaf of one snapshot item under SHA-256
/// (`realm-state-snapshot-schema.md` §4).
pub fn realm_state_snapshot_state_leaf_hash(
    item: &RealmStateSnapshotMaterializedItem,
) -> Result<Hash> {
    realm_state_snapshot_state_leaf_hash_with_digest_suite(item, DigestSuite::Sha256)
}

/// The `state_digest` leaf of one snapshot item: byte-identical to the
/// governance `state_root` leaf `H(0x00 || canonical_json({"cell","state"}))`
/// of `event-auth-state-resolution.md` §6.2.1, so a control cell has one
/// canonical leaf whether it is proven through a Seal or shipped in a snapshot.
pub fn realm_state_snapshot_state_leaf_hash_with_digest_suite(
    item: &RealmStateSnapshotMaterializedItem,
    digest_suite: DigestSuite,
) -> Result<Hash> {
    crate::state::state_root::state_leaf_hash_from_state_object(
        item.cell(),
        item.state().to_state_object(),
        digest_suite,
    )
}

/// Digest of one auxiliary list concatenated across chunks in ascending index
/// order (`realm-state-snapshot-schema.md` §3): `<suite>:hex(H(canonical_json(rows)))`.
pub fn realm_state_snapshot_auxiliary_list_digest<'a, T: Serialize + 'a>(
    rows: impl IntoIterator<Item = &'a T>,
    digest_suite: DigestSuite,
) -> Result<Hash> {
    let rows = rows.into_iter().collect::<Vec<_>>();
    let bytes = crate::canonical::canonical_json_bytes(&rows)?;
    Hash::new(arkret_canonical::digest(digest_suite, bytes)).map_err(WireError::from)
}

/// `verification_hints.conflict_records_digest` over delivered chunks.
pub fn realm_state_snapshot_conflict_records_digest(
    chunks: &[RealmStateSnapshotChunkPayload],
    digest_suite: DigestSuite,
) -> Result<Hash> {
    realm_state_snapshot_auxiliary_list_digest(
        chunks
            .iter()
            .flat_map(|chunk| chunk.conflict_records.iter()),
        digest_suite,
    )
}

/// `verification_hints.soft_failed_digest` over delivered chunks.
pub fn realm_state_snapshot_soft_failed_digest(
    chunks: &[RealmStateSnapshotChunkPayload],
    digest_suite: DigestSuite,
) -> Result<Hash> {
    realm_state_snapshot_auxiliary_list_digest(
        chunks.iter().flat_map(|chunk| chunk.soft_failed.iter()),
        digest_suite,
    )
}

/// `verification_hints.quarantined_digest` over delivered chunks.
pub fn realm_state_snapshot_quarantined_digest(
    chunks: &[RealmStateSnapshotChunkPayload],
    digest_suite: DigestSuite,
) -> Result<Hash> {
    realm_state_snapshot_auxiliary_list_digest(
        chunks.iter().flat_map(|chunk| chunk.quarantined.iter()),
        digest_suite,
    )
}

/// `verification_hints.erasure_stubs_digest` over delivered chunks.
pub fn realm_state_snapshot_erasure_stubs_digest(
    chunks: &[RealmStateSnapshotChunkPayload],
    digest_suite: DigestSuite,
) -> Result<Hash> {
    realm_state_snapshot_auxiliary_list_digest(
        chunks.iter().flat_map(|chunk| chunk.erasure_stubs.iter()),
        digest_suite,
    )
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

pub fn verify_realm_state_snapshot_chunk_bytes(
    descriptor: &RealmStateSnapshotChunkDescriptor,
    bytes: &[u8],
) -> std::result::Result<(), RealmStateSnapshotValidationError> {
    if bytes.len() as u64 != descriptor.size_bytes {
        return Err(RealmStateSnapshotValidationError::new(
            RealmStateSnapshotValidationCode::DigestMismatch,
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
        RealmStateSnapshotValidationError::new(
            RealmStateSnapshotValidationCode::DigestMismatch,
            "snapshot chunk bytes do not match chunk_ref",
        )
    })
}

/// `realm-state-snapshot-schema.md` §3: items sort by cell id in Unicode code point order,
/// which for UTF-8 is byte order — the same order §6.2.1 gives `state_root`
/// leaves.
fn sort_realm_state_snapshot_items(items: &mut [RealmStateSnapshotMaterializedItem]) {
    items.sort_by(|a, b| a.id().as_bytes().cmp(b.id().as_bytes()));
}

fn ensure_unique_realm_state_snapshot_items(
    items: &[RealmStateSnapshotMaterializedItem],
) -> Result<()> {
    for pair in items.windows(2) {
        if pair[0].id() == pair[1].id() {
            return Err(WireError::Protocol(format!(
                "duplicate snapshot item cell {}",
                pair[0].id()
            )));
        }
    }
    Ok(())
}

fn build_chunk_descriptor(
    payload: RealmStateSnapshotChunkPayload,
) -> Result<BuiltRealmStateSnapshotChunk> {
    let canonical_bytes = realm_state_snapshot_chunk_payload_bytes(&payload)?;
    let digest = sha256_digest(&canonical_bytes);
    let descriptor = RealmStateSnapshotChunkDescriptor {
        chunk_ref: BlobRef::new(format!("ak:blob:{digest}")).map_err(WireError::from)?,
        size_bytes: canonical_bytes.len() as u64,
    };
    Ok(BuiltRealmStateSnapshotChunk {
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
