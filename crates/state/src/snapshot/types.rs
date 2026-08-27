use std::collections::BTreeSet;

use arkret_wire::{DidCoreId, DidUrl, ProofContextId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::constants::DETACHED_JWS_PROOF_KIND;
use super::merkle::sha256_digest;
use crate::{BlobRef, EventId, Hash, Hlc, RealmId, Result, SnapshotId};

/// Object-family context of `authority_binding.witness_attestations[]`. It is
/// deliberately not the manifest's `ak.snapshot_proof.v1`: a witness signature
/// produced under the manifest context is rejected even when the JWS verifies
/// (`snapshot-schema.md` §5.1).
pub const SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT: &str =
    ProofContextId::SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1;

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

/// Full `ak.schema.snapshot.v1` manifest returned by `ak.self.snapshot.read.manifest_head.v1`.
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
    pub created_by: DidCoreId,
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
    pub created_by: &'a DidCoreId,
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

    pub fn expected_signature_digest(&self) -> Result<Hash> {
        self.unsigned_view().payload_digest()
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

impl SnapshotManifest {
    /// Exact canonical `SnapshotWitnessAttestation` projection of
    /// `snapshot-schema.md` §5.1.
    ///
    /// Every value is recomputed from the manifest and the row's `witness_id`.
    /// The proof itself, `signature`, the whole `witness_attestations[]`,
    /// `verification_hints`, `chunks[]`, `created_by` (whose value must equal
    /// the included `issuer`) and `authority_binding.checked_at` are excluded —
    /// that exclusion is what keeps a witness from ever signing a transcript
    /// containing its own or another witness's signature.
    pub fn witness_attestation_projection(&self, witness_id: &DidCoreId) -> Result<Value> {
        Ok(serde_json::json!({
            "context": SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT,
            "witness_id": witness_id,
            "snapshot_id": self.id,
            "realm_id": self.realm_id,
            "reducer_profile": self.reducer_profile,
            "schema_profile_refs": self.schema_profile_refs,
            "security_class": self.security_class,
            "state_digest": self.state_digest,
            "frontier": self.frontier,
            "event_set_commitment": self.event_set_commitment,
            "issuer": self.created_by,
            "authority_kind": self.authority_binding.authority_kind,
            "auth_state_digest": self.authority_binding.auth_state_digest,
            "auth_frontier": self.authority_binding.auth_frontier,
            "snapshot_created_at": arkret_canonical::canonical::format_timestamp_canonical(
                self.created_at,
            ),
        }))
    }

    pub fn witness_attestation_canonical_bytes(&self, witness_id: &DidCoreId) -> Result<Vec<u8>> {
        Ok(crate::canonical::canonical_json_bytes(
            &self.witness_attestation_projection(witness_id)?,
        )?)
    }

    /// `payload_digest` every witness attestation for this manifest must carry.
    pub fn witness_attestation_digest(&self, witness_id: &DidCoreId) -> Result<Hash> {
        Ok(sha256_digest(
            &self.witness_attestation_canonical_bytes(witness_id)?,
        ))
    }

    /// Witness-quorum admission of `snapshot-schema.md` §5.1.
    ///
    /// Callers must have already accepted the top-level issuer signature: the
    /// manifest signature covers the final ordered witness list, so verifying it
    /// first is what makes an added, dropped or reordered row detectable. This
    /// function then enforces ordering and uniqueness, recomputes each row's
    /// projection under the witness context, and applies the policy-derived
    /// threshold. Cryptographic JWS verification stays with the caller's DID
    /// resolver, exactly as for the manifest signature.
    /// Schema-level witness-list conditions that need no auth state: presence
    /// for `authority_kind=witness_quorum`, strict ascending `witness_id` order
    /// and `witness_id` uniqueness. Violations are rejected, never normalized
    /// first (`snapshot-schema.md` §5.1).
    pub fn validate_witness_attestation_shape(
        &self,
    ) -> std::result::Result<(), SnapshotValidationError> {
        let attestations = &self.authority_binding.witness_attestations;
        if self.authority_binding.authority_kind != SnapshotAuthorityKind::WitnessQuorum {
            if attestations.is_empty() {
                return Ok(());
            }
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SchemaViolation,
                "witness_attestations are only carried by authority_kind=witness_quorum",
            ));
        }
        if attestations.is_empty() {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SchemaViolation,
                "authority_kind=witness_quorum requires a non-empty witness_attestations list",
            ));
        }
        for pair in attestations.windows(2) {
            if pair[0].witness_id.as_str() >= pair[1].witness_id.as_str() {
                return Err(SnapshotValidationError::new(
                    SnapshotValidationCode::SchemaViolation,
                    "witness_attestations must be sorted by unique witness_id in UTF-8 byte order",
                ));
            }
        }
        Ok(())
    }

    pub fn verify_witness_attestations(
        &self,
        policy: &SnapshotWitnessQuorumPolicy,
    ) -> std::result::Result<(), SnapshotValidationError> {
        self.validate_witness_attestation_shape()?;
        let attestations = &self.authority_binding.witness_attestations;
        if self.authority_binding.authority_kind != SnapshotAuthorityKind::WitnessQuorum {
            return Ok(());
        }

        for attestation in attestations {
            if !policy
                .authorized_witnesses
                .contains(&attestation.witness_id)
            {
                return Err(SnapshotValidationError::new(
                    SnapshotValidationCode::SnapshotAuthorityUnverified,
                    format!(
                        "witness {} is not an authorized non-revoked snapshot witness at created_at",
                        attestation.witness_id
                    ),
                ));
            }
            if attestation.proof.kind != DETACHED_JWS_PROOF_KIND
                || attestation.proof.jws.trim().is_empty()
            {
                return Err(SnapshotValidationError::new(
                    SnapshotValidationCode::SignatureInvalid,
                    "witness attestation proof is not a structurally valid detached JWS proof",
                ));
            }
            let controller = attestation
                .proof
                .verification_method
                .as_str()
                .split_once('#')
                .map(|(controller, _)| controller)
                .ok_or_else(|| {
                    SnapshotValidationError::new(
                        SnapshotValidationCode::SignatureInvalid,
                        "witness attestation verification_method has no controller",
                    )
                })?;
            let controller = project_witness_controller(controller).ok_or_else(|| {
                SnapshotValidationError::new(
                    SnapshotValidationCode::SignatureInvalid,
                    "witness attestation verification_method controller is not projectable by a registered DID method adapter",
                )
            })?;
            if controller != attestation.witness_id {
                return Err(SnapshotValidationError::new(
                    SnapshotValidationCode::SignatureInvalid,
                    "witness attestation verification_method controller does not project to witness_id",
                ));
            }
            let expected = self
                .witness_attestation_digest(&attestation.witness_id)
                .map_err(|error| {
                    SnapshotValidationError::new(
                        SnapshotValidationCode::DigestMismatch,
                        format!("witness attestation projection could not be computed: {error}"),
                    )
                })?;
            if attestation.proof.payload_digest != expected {
                return Err(SnapshotValidationError::new(
                    SnapshotValidationCode::SignatureInvalid,
                    "witness attestation payload_digest does not match the canonical witness projection",
                ));
            }
        }

        if attestations.len() < policy.threshold as usize {
            return Err(SnapshotValidationError::new(
                SnapshotValidationCode::SnapshotAuthorityUnverified,
                "deduplicated valid witness count is below the policy-derived threshold",
            ));
        }
        Ok(())
    }
}

/// Project a bare controller DID to its stable `did_core_id` through the
/// registered method adapter. Direct full-DID / core-id string comparison is
/// forbidden (`snapshot-schema.md` §5.1).
fn project_witness_controller(controller: &str) -> Option<DidCoreId> {
    let full_id = arkret_wire::DidFullId::new(controller).ok()?;
    arkret_wire::project_full_id_to_core_id(&full_id).ok()
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
    pub actor_id: DidCoreId,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSetLeaf {
    pub event_id: EventId,
    pub event_digest: Hash,
    pub actor_id: DidCoreId,
    pub actor_seq: u64,
    pub hlc: Hlc,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityBinding {
    pub authority_kind: SnapshotAuthorityKind,
    pub auth_state_digest: Hash,
    #[serde(default)]
    pub auth_frontier: Vec<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub checked_at: DateTime<Utc>,
    /// Typed witness quorum evidence, sorted by `witness_id` in UTF-8 byte
    /// order with `witness_id` unique across rows. v1 has no untyped equivalent
    /// quorum carrier (`snapshot-schema.md` §5.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_attestations: Vec<SnapshotWitnessAttestation>,
}

/// One witness statement that the snapshot issuer held snapshot-sealing
/// authority for this exact reduced state at manifest `created_at`
/// (`snapshot.schema.json#/$defs/snapshot_witness_attestation`).
///
/// It is a separate object family from the manifest: the witness signs the
/// canonical signature-free projection of `snapshot-schema.md` §5.1 under
/// `ak.snapshot_witness_attestation_proof.v1`. Reusing the manifest-level
/// `ak.snapshot_proof.v1` context here is rejected.
///
/// This is the **verification model** half of the snapshot model, alongside
/// [`SnapshotManifest`] and [`AuthorityBinding`]: it carries the typed
/// [`DetachedJwsProof`] this crate signs and verifies, and it is the half that
/// owns [`SnapshotManifest::witness_attestation_projection`] and
/// [`SnapshotManifest::verify_witness_attestations`]. The **wire DTO** half is
/// `arkret_models_collaboration::sync_frames::snapshot::SnapshotWitnessAttestationItem`,
/// which mirrors the schema verbatim with the full shared `PayloadProof` leaf.
/// The two halves are named apart on purpose — same as [`SnapshotChunkDescriptor`]
/// vs `SnapshotChunksItem` — so neither shadows the other in the `arkret_sdk`
/// prelude.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotWitnessAttestation {
    /// Stable `did_core_id` of the witness. Quorum counting is per
    /// `witness_id`, so several keys of one witness count once.
    pub witness_id: DidCoreId,
    pub proof: DetachedJwsProof,
}

/// Witness-quorum admission inputs resolved from the accepted Realm
/// auth/policy state at `manifest.created_at` through
/// `authority_binding.auth_frontier` / `auth_state_digest`
/// (`snapshot-schema.md` §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotWitnessQuorumPolicy {
    /// Witnesses authorized at `manifest.created_at` whose signing keys the
    /// resolver confirmed valid and not revoked at that instant. A witness the
    /// resolver could not confirm MUST be left out so it cannot reach quorum.
    pub authorized_witnesses: BTreeSet<DidCoreId>,
    /// Threshold derived from the same accepted auth/policy state.
    pub threshold: u32,
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
    SchemaViolation,
    SignatureInvalid,
    SnapshotAuthorityUnverified,
    SnapshotIssuerRevoked,
    InclusionProofFailed,
    SnapshotUnavailable,
}

impl SnapshotValidationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DigestMismatch => crate::ErrorCode::DIGEST_MISMATCH,
            Self::SchemaViolation => crate::error::ErrorCode::SCHEMA_VIOLATION,
            Self::SignatureInvalid => crate::error::ErrorCode::SIGNATURE_INVALID,
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
