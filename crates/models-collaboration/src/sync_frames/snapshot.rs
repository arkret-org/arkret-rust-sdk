//! Sync, realm, and snapshot schema artifact counterparts.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/range-completeness-attestation.schema.json#/properties/event_range/
/// properties/from_frontier`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeCompletenessAttestationEventRangeFromFrontier {
    pub realm_frontier: Vec<EventId>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/range-completeness-attestation.schema.json#/properties/event_range/
/// properties/to_frontier`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeCompletenessAttestationEventRangeToFrontier {
    pub realm_frontier: Vec<EventId>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeCompletenessAttestationEventRangeActorSeqRangesItem {
    pub actor_id: Did,
    pub from_seq_exclusive: i64,
    pub to_seq_inclusive: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeCompletenessAttestationEventRange {
    pub from_frontier: RangeCompletenessAttestationEventRangeFromFrontier,
    pub to_frontier: RangeCompletenessAttestationEventRangeToFrontier,
    pub actor_seq_ranges: Vec<RangeCompletenessAttestationEventRangeActorSeqRangesItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeCompletenessAttestationWitnessAttestationWitnessesItem {
    pub issuer: Did,
    pub verification_method: String,
    pub controlling_organization: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub attested_at: Option<DateTime<Utc>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeCompletenessAttestationWitnessAttestation {
    pub kind: String,
    pub witnesses: Vec<RangeCompletenessAttestationWitnessAttestationWitnessesItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeCompletenessAttestation {
    pub attestation_id: String,
    pub schema: String,
    pub issuer: Did,
    pub issuer_role: String,
    pub realm_id: RealmId,
    pub event_range: RangeCompletenessAttestationEventRange,
    pub root: Hash,
    pub count: u64,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub observed_at: DateTime<Utc>,
    pub witness_attestation: RangeCompletenessAttestationWitnessAttestation,
    pub proofs: Vec<Proof>,
}

/// Counterpart for `spec/v1/artifacts/schemas/realm.schema.json#/$defs/cell_lattice`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellLattice {
    pub cell_family: String,
    pub lattice: String,
    pub bottom: String,
    pub cell_role: String,
    pub plane: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentinel_writers: Option<Vec<String>>,
}

pub use crate::objects::realm::SyncEndpoint;

/// Counterpart for `spec/v1/artifacts/schemas/snapshot.schema.json`.
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
    pub actor_id: Did,
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
    pub covered_event_ids: Option<Vec<EventId>>,
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
    pub witness_quorum: Option<u64>,
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
    pub chunk_ref: BlobId,
    pub digest: Hash,
    pub size_bytes: u64,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAuthorityBinding {
    pub issuer: Did,
    pub authority_kind: String,
    pub auth_state_digest: Hash,
    pub auth_frontier: Vec<EventId>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub checked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_attestations: Option<Vec<Proof>>,
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
    pub created_by: Did,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    pub authority_binding: SnapshotAuthorityBinding,
    pub signature: PayloadProof,
}

/// Snapshot acceleration hint returned by event range queries and federation
/// pulls. The referenced snapshot manifest remains the authoritative signed
/// object; consumers must verify it before applying any snapshot state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotBootstrap {
    pub snapshot_ref: SnapshotId,
    pub state_digest: Hash,
    pub snapshot_frontier: Vec<EventId>,
    pub created_by: Did,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    pub authority_binding: SnapshotAuthorityBinding,
    pub signature: PayloadProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<SnapshotVerificationHintsValue>,
}
