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
//! - [`SnapshotChunker`] — deterministically partitions a serialized snapshot blob into fixed-size
//!   byte ranges, each addressable by an ordinal `chunk_id` starting at 0. Boundaries are at exact
//!   byte offsets (`target_chunk_bytes`) so two implementations always produce the same chunk
//!   layout for the same input.
//! - [`SnapshotMerkleTree`] — a binary Merkle tree over chunk digests keyed by `chunk_id`. RFC
//!   6962-style audit paths let receivers verify a single chunk's leaf hash against the root using
//!   just `O(log n)` sibling hashes.
//! - [`GeneratorProof`] — the generator's signed commitment to a snapshot frontier (`state_root` +
//!   `merkle_root` + `chunk_count`). Receivers verify the proof against the generator DID before
//!   trusting any chunks; chunks themselves don't need per-chunk signatures because their digests
//!   are committed in the Merkle root that the proof signs.
//!
//! Wire shape (round 8): the snapshot manifest endpoint
//! (`/_cokret/self/snapshot/head`) returns `chunk_count`, `merkle_root`,
//! and `generator_proof`; the chunk endpoint
//! (`/_cokret/self/snapshot/chunk?chunk_id=N`) returns the chunk bytes
//! plus the `audit_path[]` Merkle siblings. Receivers verify per-chunk.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{ERROR_CODE_SNAPSHOT_AUTHORITY_UNVERIFIED, ERROR_CODE_SNAPSHOT_UNAVAILABLE};
use crate::{BlobRef, Did, Error, EventId, Hash, Hlc, MoveSignature, RealmId, Result, SnapshotId};

/// Default chunk size in bytes (256 KiB). Picked so a 100 MB snapshot
/// becomes ~400 chunks — small enough for HTTP delivery, large enough
/// that the per-chunk audit-path overhead stays negligible.
pub const DEFAULT_SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;
pub const SNAPSHOT_MANIFEST_SCHEMA_V1: &str = "ck.schema.snapshot.v1";
pub const SNAPSHOT_CHUNK_TYPE: &str = "snapshot_chunk";
pub const SNAPSHOT_REDUCER_PROFILE_V1: &str = "ck.reducer.v1";
pub const EVENT_SET_ALGORITHM_ORDERED_SHA256_V1: &str = "ordered_event_id_sha256_v1";
pub const EVENT_SET_ALGORITHM_MERKLE_V1: &str = "merkle_event_set_v1";
pub const SNAPSHOT_SECURITY_STANDARD: &str = "standard";
pub const SNAPSHOT_SECURITY_HIGH_ASSURANCE: &str = "high_assurance";
pub const DETACHED_JWS_PROOF_KIND: &str = "detached_jws";
pub const DETACHED_JWS_ALG_EDDSA: &str = "EdDSA";
pub const SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS: i64 = 2_592_000_000;
pub const SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS: i64 = 604_800_000;
pub const EMPTY_SHA256_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Full `ck.schema.snapshot.v1` manifest returned by `ck.self.snapshot.head`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotManifest {
    pub id: SnapshotId,
    pub realm_id: RealmId,
    pub reducer_profile: String,
    #[serde(default)]
    pub schema_profile_refs: Vec<String>,
    pub state_digest: Hash,
    pub frontier: SnapshotFrontier,
    pub event_set_commitment: EventSetCommitment,
    #[serde(default)]
    pub chunks: Vec<SnapshotChunkDescriptor>,
    pub security_class: SnapshotSecurityClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<SnapshotVerificationHints>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    pub authority_binding: AuthorityBinding,
    pub signature: DetachedJwsProof,
}

/// Snapshot manifest view used for canonical signing bytes.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UnsignedSnapshotManifest<'a> {
    pub id: &'a SnapshotId,
    pub realm_id: &'a RealmId,
    pub reducer_profile: &'a str,
    pub schema_profile_refs: &'a [String],
    pub state_digest: &'a Hash,
    pub frontier: &'a SnapshotFrontier,
    pub event_set_commitment: &'a EventSetCommitment,
    pub chunks: &'a [SnapshotChunkDescriptor],
    pub security_class: &'a SnapshotSecurityClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<&'a SnapshotVerificationHints>,
    pub created_by: &'a Did,
    pub created_at: DateTime<Utc>,
    pub authority_binding: &'a AuthorityBinding,
}

impl SnapshotManifest {
    pub fn unsigned_view(&self) -> UnsignedSnapshotManifest<'_> {
        UnsignedSnapshotManifest {
            id: &self.id,
            realm_id: &self.realm_id,
            reducer_profile: &self.reducer_profile,
            schema_profile_refs: &self.schema_profile_refs,
            state_digest: &self.state_digest,
            frontier: &self.frontier,
            event_set_commitment: &self.event_set_commitment,
            chunks: &self.chunks,
            security_class: &self.security_class,
            verification_hints: self.verification_hints.as_ref(),
            created_by: &self.created_by,
            created_at: self.created_at,
            authority_binding: &self.authority_binding,
        }
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.unsigned_view().canonical_bytes()
    }

    pub fn signature_payload_value(&self) -> Result<Value> {
        serde_json::to_value(self.unsigned_view()).map_err(Error::from)
    }

    pub fn signature_payload_bytes(&self) -> Result<Vec<u8>> {
        self.unsigned_canonical_bytes()
    }

    pub fn expected_signature_digest(&self) -> Result<Hash> {
        self.unsigned_view().payload_digest()
    }

    pub fn signature_as_proof(&self) -> crate::model::Proof {
        crate::model::Proof {
            kind: self.signature.kind.clone(),
            alg: self.signature.alg.clone(),
            verification_method: self.signature.verification_method.clone(),
            event_digest: self.signature.payload_digest.clone(),
            created_at: self.signature.created_at,
            domain: None,
            audience: None,
            jws: self.signature.jws.clone(),
        }
    }

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
                "event_set_commitment.covered_frontier does not match frontier.event_ids",
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

impl UnsignedSnapshotManifest<'_> {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        crate::canonical::canonical_json_bytes(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Ok(sha256_digest(&self.canonical_bytes()?))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotFrontier {
    #[serde(default)]
    pub event_ids: Vec<EventId>,
    pub timeline_hlc: Hlc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSecurityClass {
    Standard,
    HighAssurance,
}

impl SnapshotSecurityClass {
    pub fn max_acceptance_age(&self) -> Duration {
        match self {
            Self::Standard => Duration::days(30),
            Self::HighAssurance => Duration::days(7),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotChunkDescriptor {
    pub chunk_ref: BlobRef,
    pub digest: Hash,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventSetCommitment {
    pub algorithm: EventSetCommitmentAlgorithm,
    pub root: Hash,
    pub covered_event_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_frontier: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_seq_ranges: Vec<ActorSeqRangeCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventSetCommitmentAlgorithm {
    OrderedEventIdSha256V1,
    MerkleEventSetV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ActorSeqRangeCommitment {
    pub actor_id: Did,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventSetLeaf {
    pub event_id: EventId,
    pub event_digest: Hash,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: Hlc,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthorityBinding {
    pub issuer: Did,
    pub authority_kind: SnapshotAuthorityKind,
    pub auth_state_digest: Hash,
    #[serde(default)]
    pub auth_frontier: Vec<EventId>,
    pub checked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_attestations: Vec<crate::model::Proof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SnapshotAuthorityKind {
    RealmOwner,
    RealmPolicySnapshotIssuer,
    WitnessQuorum,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DetachedJwsProof {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

impl DetachedJwsProof {
    pub fn eddsa(
        verification_method: String,
        payload_digest: Hash,
        created_at: DateTime<Utc>,
        jws: String,
    ) -> Self {
        Self {
            kind: DETACHED_JWS_PROOF_KIND.to_owned(),
            alg: DETACHED_JWS_ALG_EDDSA.to_owned(),
            verification_method,
            payload_digest,
            created_at,
            jws,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotVerificationHints {
    pub verification_profile: SnapshotSecurityClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_proof_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_window_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_quorum: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict_records_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_failed_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_digest: Option<Hash>,
}

/// Materialized reducer output item stored inside spec snapshot chunks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotMaterializedItem {
    pub kind: String,
    pub id: String,
    pub object: Value,
    pub source_event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotChunkPayload {
    #[serde(rename = "type")]
    pub chunk_type: String,
    pub snapshot_ref: SnapshotId,
    pub index: u32,
    pub reducer_profile: String,
    #[serde(default)]
    pub items: Vec<SnapshotMaterializedItem>,
    #[serde(default)]
    pub conflict_records: Vec<Value>,
    #[serde(default)]
    pub soft_failed: Vec<Value>,
    #[serde(default)]
    pub quarantined: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltSnapshotChunk {
    pub payload: SnapshotChunkPayload,
    pub canonical_bytes: Vec<u8>,
    pub descriptor: SnapshotChunkDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotValidationCode {
    DigestMismatch,
    SnapshotAuthorityUnverified,
    SnapshotIssuerRevoked,
    InclusionProofFailed,
    SnapshotUnavailable,
}

impl SnapshotValidationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DigestMismatch => crate::ERROR_CODE_DIGEST_MISMATCH,
            Self::SnapshotAuthorityUnverified => ERROR_CODE_SNAPSHOT_AUTHORITY_UNVERIFIED,
            Self::SnapshotIssuerRevoked => "snapshot_issuer_revoked",
            Self::InclusionProofFailed => "inclusion_proof_failed",
            Self::SnapshotUnavailable => ERROR_CODE_SNAPSHOT_UNAVAILABLE,
        }
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("{code:?}: {message}")]
pub struct SnapshotValidationError {
    pub code: SnapshotValidationCode,
    pub message: String,
}

impl SnapshotValidationError {
    pub fn new(code: SnapshotValidationCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotVerifyOptions {
    pub now: DateTime<Utc>,
    pub expected_reducer_profile: String,
    pub allow_high_assurance: bool,
}

impl SnapshotVerifyOptions {
    pub fn standard(now: DateTime<Utc>, expected_reducer_profile: impl Into<String>) -> Self {
        Self {
            now,
            expected_reducer_profile: expected_reducer_profile.into(),
            allow_high_assurance: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotVerifyReport {
    pub item_count: usize,
    pub chunk_count: usize,
    pub state_digest: Hash,
    pub source_event_ids: Vec<EventId>,
}

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
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::base64url::{base64url_decode, base64url_encode};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64url_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        base64url_decode(&s).map_err(serde::de::Error::custom)
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
    covered_frontier: Vec<EventId>,
) -> Result<EventSetCommitment> {
    let root = event_set_root(&algorithm, entries)?;
    Ok(EventSetCommitment {
        algorithm,
        root,
        covered_event_count: entries.len() as u64,
        covered_frontier,
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
        &manifest.event_set_commitment.covered_frontier,
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

/// Binary Merkle tree over snapshot chunk digests.
///
/// Construction:
/// - Leaves are chunk digests in `chunk_id` order.
/// - Internal nodes are `sha256(left || right)` (raw 32-byte concat).
/// - Odd levels promote the last node to the next level **unchanged** (RFC 6962-style; never
///   duplicate — see spec `event-auth-state-resolution.md` §4.2.2 for the house odd-layer rule).
///   Duplication would make `[A,B,C]` and `[A,B,C,C]` share a root (CVE-2012-2459-shaped
///   ambiguity).
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
        self.levels
            .last()
            .and_then(|l| l.first())
            .expect("levels invariant: non-empty")
    }

    /// RFC 6962-style audit path: siblings from leaf up to root,
    /// bottom-up. Promoted nodes (last node of an odd-sized level)
    /// contribute no sibling, so path lengths vary per leaf. Returns
    /// `None` when `leaf_index >= tree_size`.
    pub fn audit_path(&self, leaf_index: usize) -> Option<Vec<Hash>> {
        if leaf_index >= self.tree_size() {
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
    /// rebuilding the tree. `tree_size` drives the layer walk, so a
    /// proof is only accepted when `audit_path` has exactly the length
    /// the claimed `(leaf_index, tree_size)` pair implies.
    pub fn verify(
        root: &Hash,
        leaf: &Hash,
        leaf_index: usize,
        audit_path: &[Hash],
        tree_size: usize,
    ) -> bool {
        if tree_size == 0 || leaf_index >= tree_size {
            return false;
        }
        let Some(mut current) = parse_sha256(leaf) else {
            return false;
        };
        let mut idx = leaf_index;
        let mut layer_size = tree_size;
        let mut siblings = audit_path.iter();
        while layer_size > 1 {
            if idx == layer_size - 1 && layer_size % 2 == 1 {
                // Promoted node: consumes no sibling at this level.
            } else {
                let Some(sibling) = siblings.next() else {
                    return false; // path too short for the claimed tree_size
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
            return false; // path longer than the claimed tree_size implies
        }
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

fn sha256_digest(bytes: &[u8]) -> Hash {
    Hash::new(crate::canonical::sha256_digest(bytes)).expect("sha256 wire form")
}

fn parse_sha256(hash: &Hash) -> Option<[u8; 32]> {
    let suffix = hash.as_str().strip_prefix("sha256:")?;
    if suffix.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(suffix, &mut out).ok()?;
    Some(out)
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn format_hash(bytes: &[u8; 32]) -> Hash {
    let hex = hex::encode(bytes);
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
    /// Realm whose state this snapshot covers.
    pub realm_id: RealmId,
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
        crate::canonical::canonical_json_bytes(&body)
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

    fn realm() -> RealmId {
        RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn snapshot_v1_event_id(suffix: &str) -> EventId {
        EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix}")).unwrap()
    }

    fn snapshot_v1_id() -> SnapshotId {
        SnapshotId::new("ck:snapshot:01904100-0000-7000-8000-000000000001".to_owned()).unwrap()
    }

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
    }

    fn manifest_for_items(
        items: Vec<SnapshotMaterializedItem>,
    ) -> (SnapshotManifest, Vec<SnapshotChunkPayload>, Vec<Vec<u8>>) {
        let state_digest = state_digest_from_items(&items).unwrap();
        let built =
            build_snapshot_chunks(&snapshot_v1_id(), SNAPSHOT_REDUCER_PROFILE_V1, items, 4096)
                .unwrap();
        let chunk_payloads = built
            .iter()
            .map(|chunk| chunk.payload.clone())
            .collect::<Vec<_>>();
        let chunk_bytes = built
            .iter()
            .map(|chunk| chunk.canonical_bytes.clone())
            .collect::<Vec<_>>();
        let descriptors = built
            .into_iter()
            .map(|chunk| chunk.descriptor)
            .collect::<Vec<_>>();
        let created_at = "2026-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut manifest = SnapshotManifest {
            id: snapshot_v1_id(),
            realm_id: realm(),
            reducer_profile: SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
            schema_profile_refs: vec!["ck.profile.core_event_store.v1".to_owned()],
            state_digest,
            frontier: SnapshotFrontier {
                event_ids: vec![snapshot_v1_event_id("000000000001")],
                timeline_hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            },
            event_set_commitment: EventSetCommitment {
                algorithm: EventSetCommitmentAlgorithm::MerkleEventSetV1,
                root: hash(9),
                covered_event_count: 1,
                covered_frontier: vec![snapshot_v1_event_id("000000000001")],
                actor_seq_ranges: Vec::new(),
            },
            chunks: descriptors,
            security_class: SnapshotSecurityClass::Standard,
            verification_hints: None,
            created_by: did(),
            created_at,
            authority_binding: AuthorityBinding {
                issuer: did(),
                authority_kind: SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
                auth_state_digest: hash(1),
                auth_frontier: vec![snapshot_v1_event_id("000000000001")],
                checked_at: created_at,
                witness_attestations: Vec::new(),
            },
            signature: DetachedJwsProof::eddsa(
                "did:web:generator.example#snapshot".to_owned(),
                hash(2),
                created_at,
                "header..signature".to_owned(),
            ),
        };
        manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
        (manifest, chunk_payloads, chunk_bytes)
    }

    #[test]
    fn snapshot_v1_manifest_and_chunk_verify() {
        let item = SnapshotMaterializedItem {
            kind: "flow".to_owned(),
            id: "ck:flow:01904100-0000-7000-8000-000000000001".to_owned(),
            object: serde_json::json!({
                "id": "ck:flow:01904100-0000-7000-8000-000000000001",
                "schema": "ck.schema.flow.v1"
            }),
            source_event_id: snapshot_v1_event_id("000000000001"),
        };
        let (manifest, payloads, bytes) = manifest_for_items(vec![item]);
        let decoded = parse_verified_snapshot_chunk_bytes(&manifest.chunks[0], &bytes[0]).unwrap();
        assert_eq!(decoded, payloads[0]);
        let report = verify_snapshot_manifest(
            &manifest,
            &payloads,
            &SnapshotVerifyOptions::standard(
                "2026-06-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
                SNAPSHOT_REDUCER_PROFILE_V1,
            ),
        )
        .unwrap();
        assert_eq!(report.item_count, 1);
        assert_eq!(report.chunk_count, 1);
    }

    #[test]
    fn snapshot_v1_covered_frontier_mismatch_rejects() {
        let (mut manifest, payloads, _) = manifest_for_items(Vec::new());
        manifest.event_set_commitment.covered_frontier = vec![snapshot_v1_event_id("000000000002")];
        manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
        let err = verify_snapshot_manifest(
            &manifest,
            &payloads,
            &SnapshotVerifyOptions::standard(
                "2026-06-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
                SNAPSHOT_REDUCER_PROFILE_V1,
            ),
        )
        .unwrap_err();
        assert_eq!(err.code, SnapshotValidationCode::InclusionProofFailed);
    }

    #[test]
    fn snapshot_v1_stale_standard_manifest_rejects() {
        let (manifest, payloads, _) = manifest_for_items(Vec::new());
        let err = verify_snapshot_manifest(
            &manifest,
            &payloads,
            &SnapshotVerifyOptions::standard(
                "2026-07-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
                SNAPSHOT_REDUCER_PROFILE_V1,
            ),
        )
        .unwrap_err();
        assert_eq!(err.code, SnapshotValidationCode::SnapshotIssuerRevoked);
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
            let recomputed = sha256_digest(&chunk.bytes);
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

    #[test]
    fn merkle_duplicate_tail_leaf_changes_root() {
        // Promote-without-duplication: [A,B,C] and [A,B,C,C] MUST NOT
        // share a root (CVE-2012-2459-shaped ambiguity).
        let cs3 = chunks(3);
        let tree3 = SnapshotMerkleTree::build(&cs3).unwrap();
        let mut cs4 = cs3.clone();
        cs4.push(SnapshotChunk {
            chunk_id: 3,
            bytes: cs3[2].bytes.clone(),
            digest: cs3[2].digest.clone(),
        });
        let tree4 = SnapshotMerkleTree::build(&cs4).unwrap();
        assert_ne!(tree3.root(), tree4.root());
    }

    #[test]
    fn merkle_verify_rejects_mismatched_tree_size() {
        let cs = chunks(3);
        let tree = SnapshotMerkleTree::build(&cs).unwrap();
        let path = tree.audit_path(2).unwrap();
        assert!(SnapshotMerkleTree::verify(
            tree.root(),
            &cs[2].digest,
            2,
            &path,
            3
        ));
        // The same proof under a different claimed tree_size MUST fail.
        assert!(!SnapshotMerkleTree::verify(
            tree.root(),
            &cs[2].digest,
            3,
            &path,
            4
        ));
        assert!(!SnapshotMerkleTree::verify(
            tree.root(),
            &cs[2].digest,
            2,
            &path,
            4
        ));
    }

    // ── GeneratorProof ─────────────────────────────────────────────────

    fn move_sig(payload_digest: Hash) -> MoveSignature {
        MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:generator.example#k1".to_owned(),
            payload_digest,
            created_at: Utc::now(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
    }

    #[test]
    fn generator_proof_body_digest_round_trips() {
        let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        let digest =
            GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 42, 1024, 256)
                .unwrap();

        let proof = GeneratorProof {
            generator_did: did(),
            realm_id: realm(),
            state_root,
            merkle_root,
            chunk_count: 42,
            total_bytes: 1024,
            chunk_bytes: 256,
            signature: move_sig(digest),
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
            realm_id: realm(),
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
        let d1 = GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 1, 4, 4)
            .unwrap();
        let d2 = GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 2, 4, 4)
            .unwrap();
        assert_ne!(d1, d2, "chunk_count must be in the canonical bytes");
    }

    #[test]
    fn generator_proof_serializes_with_all_fields() {
        let state_root = Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        let merkle_root = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        let digest =
            GeneratorProof::body_digest(&did(), &realm(), &state_root, &merkle_root, 3, 12, 4)
                .unwrap();
        let proof = GeneratorProof {
            generator_did: did(),
            realm_id: realm(),
            state_root,
            merkle_root,
            chunk_count: 3,
            total_bytes: 12,
            chunk_bytes: 4,
            signature: move_sig(digest),
        };
        let v: Value = serde_json::to_value(&proof).unwrap();
        for f in [
            "generator_did",
            "realm_id",
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

    fn event_id(suffix: &str) -> EventId {
        EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix}")).unwrap()
    }

    fn snapshot_id() -> SnapshotId {
        SnapshotId::new("ck:snapshot:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn state_item(kind: &str, id: &str, source_suffix: &str) -> SnapshotMaterializedItem {
        SnapshotMaterializedItem {
            kind: kind.to_owned(),
            id: id.to_owned(),
            object: serde_json::json!({
                "id": id,
                "kind": kind,
                "schema": "ck.schema.test.v1"
            }),
            source_event_id: event_id(source_suffix),
        }
    }

    #[test]
    fn spec_merkle_empty_root_is_sha256_empty() {
        let root = merkle_root_from_hashes(Vec::new()).unwrap();
        assert_eq!(root.as_str(), EMPTY_SHA256_DIGEST);
    }

    #[test]
    fn event_set_commitment_sorts_entries_before_hashing() {
        let a = EventSetLeaf {
            event_id: event_id("000000000001"),
            event_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            actor_seq: 1,
            hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        };
        let b = EventSetLeaf {
            event_id: event_id("000000000002"),
            event_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            actor_id: Did::new("did:web:bob.example").unwrap(),
            actor_seq: 1,
            hlc: Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
        };

        let forward = event_set_root(
            &EventSetCommitmentAlgorithm::MerkleEventSetV1,
            &[a.clone(), b.clone()],
        )
        .unwrap();
        let reversed =
            event_set_root(&EventSetCommitmentAlgorithm::MerkleEventSetV1, &[b, a]).unwrap();

        assert_eq!(forward, reversed);
    }

    #[test]
    fn spec_chunk_builder_uses_item_boundaries_and_digest_refs() {
        let items = vec![
            state_item(
                "message",
                "ck:message:01904100-0000-7000-8000-000000000002",
                "000000000002",
            ),
            state_item(
                "flow",
                "ck:flow:01904100-0000-7000-8000-000000000001",
                "000000000001",
            ),
        ];

        let built =
            build_snapshot_chunks(&snapshot_id(), SNAPSHOT_REDUCER_PROFILE_V1, items, 240).unwrap();

        assert_eq!(
            built
                .iter()
                .map(|chunk| chunk.payload.items.len())
                .sum::<usize>(),
            2
        );
        for (index, chunk) in built.iter().enumerate() {
            assert_eq!(chunk.payload.index, index as u32);
            assert_eq!(
                chunk.descriptor.digest,
                sha256_digest(&chunk.canonical_bytes)
            );
            assert_eq!(
                chunk.descriptor.chunk_ref.as_str(),
                format!("ck:blob:{}", chunk.descriptor.digest).as_str()
            );
        }
    }

    #[test]
    fn state_digest_rejects_duplicate_kind_id() {
        let item = state_item(
            "flow",
            "ck:flow:01904100-0000-7000-8000-000000000001",
            "000000000001",
        );
        let err = state_digest_from_items(&[item.clone(), item]).unwrap_err();
        assert!(format!("{err}").contains("duplicate snapshot item key"));
    }
}
