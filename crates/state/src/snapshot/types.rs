use arkret_wire::DidUrl;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::constants::DETACHED_JWS_PROOF_KIND;
use super::merkle::sha256_digest;
use crate::{BlobRef, Did, Error, EventId, Hash, Hlc, RealmId, Result, SnapshotId};

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

/// Full `ak.schema.snapshot.v1` manifest returned by `ak.self.snapshot.read.manifest_head`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub id: SnapshotId,
    pub realm_id: RealmId,
    pub reducer_profile: String,
    pub security_class: SnapshotSecurityClass,
    #[serde(default)]
    pub schema_profile_refs: Vec<String>,
    pub state_digest: Hash,
    pub frontier: SnapshotFrontier,
    pub event_set_commitment: EventSetCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<SnapshotVerificationHints>,
    #[serde(default)]
    pub chunks: Vec<SnapshotChunkDescriptor>,
    pub created_by: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    pub security_class: &'a SnapshotSecurityClass,
    pub schema_profile_refs: &'a [String],
    pub state_digest: &'a Hash,
    pub frontier: &'a SnapshotFrontier,
    pub event_set_commitment: &'a EventSetCommitment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<&'a SnapshotVerificationHints>,
    pub chunks: &'a [SnapshotChunkDescriptor],
    pub created_by: &'a Did,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
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

    pub fn signature_as_proof(&self) -> crate::models::Proof {
        crate::models::Proof {
            kind: self.signature.kind.clone(),
            verification_method: self.signature.verification_method.clone(),
            event_digest: self.signature.payload_digest.clone(),
            created_at: self.signature.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: self.signature.jws.clone(),
        }
    }
}

impl UnsignedSnapshotManifest<'_> {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(crate::canonical::canonical_json_bytes(self)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Ok(sha256_digest(&self.canonical_bytes()?))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotFrontier {
    #[serde(default)]
    pub event_ids: Vec<EventId>,
    pub timeline_hlc: Hlc,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunkDescriptor {
    pub chunk_ref: BlobRef,
    pub digest: Hash,
    pub size_bytes: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSetCommitment {
    pub algorithm: EventSetCommitmentAlgorithm,
    pub root: Hash,
    pub covered_event_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_seq_ranges: Vec<ActorSeqRangeCommitment>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSetCommitmentAlgorithm {
    OrderedEventIdSha256V1,
    MerkleEventSetV1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorSeqRangeCommitment {
    pub actor_id: Did,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSetLeaf {
    pub event_id: EventId,
    pub event_digest: Hash,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: Hlc,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityBinding {
    pub issuer: Did,
    pub authority_kind: SnapshotAuthorityKind,
    pub auth_state_digest: Hash,
    #[serde(default)]
    pub auth_frontier: Vec<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub checked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_attestations: Vec<crate::models::Proof>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotAuthorityKind {
    RealmOwner,
    RealmPolicySnapshotIssuer,
    WitnessQuorum,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedJwsProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

impl DetachedJwsProof {
    pub fn ed25519(
        verification_method: DidUrl,
        payload_digest: Hash,
        created_at: DateTime<Utc>,
        jws: String,
    ) -> Self {
        Self {
            kind: DETACHED_JWS_PROOF_KIND.to_owned(),
            verification_method,
            payload_digest,
            created_at,
            jws,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMaterializedItem {
    pub kind: String,
    pub id: String,
    pub object: Value,
    pub source_event_id: EventId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunkPayload {
    pub chunk_kind: String,
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
            Self::DigestMismatch => crate::ErrorCode::DIGEST_MISMATCH,
            Self::SnapshotAuthorityUnverified => {
                crate::error::ErrorCode::SNAPSHOT_AUTHORITY_UNVERIFIED
            }
            Self::SnapshotIssuerRevoked => "snapshot_issuer_revoked",
            Self::InclusionProofFailed => "inclusion_proof_failed",
            Self::SnapshotUnavailable => crate::error::ErrorCode::SNAPSHOT_UNAVAILABLE,
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
