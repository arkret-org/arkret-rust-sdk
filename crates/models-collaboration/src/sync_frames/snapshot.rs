//! Sync, realm, and snapshot schema artifact counterparts.

use arkret_wire::{ActorId, PayloadProof, SchemaId};

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/snapshot.schema.json#/properties/frontier`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotFrontierValue {
    pub event_ids: Vec<EventId>,
    pub timeline_hlc: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEventSetCommitmentActorSeqRangesItem {
    pub actor_id: ActorId,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEventSetCommitment {
    pub algorithm: String,
    pub root: Hash,
    pub covered_event_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_seq_ranges: Option<Vec<SnapshotEventSetCommitmentActorSeqRangesItem>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotVerificationHintsValue {
    pub verification_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_records_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_failed_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_digest: Option<Hash>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotChunksItem {
    pub chunk_ref: BlobRef,
    pub size_bytes: u64,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/snapshot.schema.json#/$defs/snapshot_witness_attestation`.
///
/// A distinct object family from the manifest: the witness signs the canonical
/// signature-free projection of `snapshot-schema.md` §5.1 under
/// `ak.snapshot_witness_attestation_proof.v1`, never the manifest transcript.
///
/// This is the **wire DTO** half of the snapshot model, alongside [`Snapshot`]
/// and [`SnapshotAuthorityBinding`]; it mirrors the schema shape verbatim and
/// carries the full shared proof leaf as `PayloadProof`. The **verification
/// model** half lives in `arkret_state::snapshot`, where
/// `SnapshotWitnessAttestation` hangs off `SnapshotManifest` /
/// `AuthorityBinding` and owns the canonical projection builder and the
/// quorum verifier. The two halves are named apart on purpose — same as
/// [`SnapshotChunksItem`] vs `SnapshotChunkDescriptor` — so neither shadows the
/// other in the `arkret_sdk` prelude.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotWitnessAttestationItem {
    pub witness_id: DidCoreId,
    pub proof: PayloadProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAuthorityBinding {
    pub authority_kind: String,
    pub auth_state_digest: Hash,
    pub auth_frontier: Vec<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub checked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_attestations: Option<Vec<SnapshotWitnessAttestationItem>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub id: String,
    pub realm_id: RealmId,
    pub reducer_profile: String,
    pub security_class: String,
    pub schema_profile_refs: Vec<String>,
    pub state_digest: Hash,
    pub frontier: SnapshotFrontierValue,
    pub event_set_commitment: SnapshotEventSetCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<SnapshotVerificationHintsValue>,
    pub chunks: Vec<SnapshotChunksItem>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub authority_binding: SnapshotAuthorityBinding,
    pub signature: PayloadProof,
}

impl Snapshot {
    pub const SCHEMA: &'static str = SchemaId::SNAPSHOT_V1;
}

/// Snapshot acceleration hint returned by event range queries and federation
/// pulls. The referenced snapshot manifest remains the authoritative signed
/// object; consumers must verify it before applying any snapshot state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotBootstrap {
    pub snapshot_ref: SnapshotId,
    pub state_digest: Hash,
    pub snapshot_frontier: Vec<EventId>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub authority_binding: SnapshotAuthorityBinding,
    pub signature: PayloadProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<SnapshotVerificationHintsValue>,
}
