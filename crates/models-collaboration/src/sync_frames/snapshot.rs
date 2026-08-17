//! Sync, realm, and snapshot schema artifact counterparts.

use arkret_wire::{DidCoreId, PayloadProof, ProofContextId, SchemaId, UnsignedPayloadProof};

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
    pub actor_id: DidCoreId,
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
    pub issuer: DidCoreId,
    pub verification_method: DidUrl,
    pub controlling_organization: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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
    pub issuer: DidCoreId,
    pub issuer_role: String,
    pub realm_id: RealmId,
    pub event_range: RangeCompletenessAttestationEventRange,
    pub root: Hash,
    pub count: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub witness_attestation: RangeCompletenessAttestationWitnessAttestation,
    pub proofs: Vec<PayloadProof>,
}

impl RangeCompletenessAttestation {
    pub const SCHEMA: &'static str = SchemaId::RANGE_COMPLETENESS_ATTESTATION_V1;

    /// Canonical proof transcript. Proofs are detached from the payload they
    /// authenticate, so every producer and verifier must use this single
    /// omission rule instead of editing serialized JSON independently.
    pub fn proof_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or_else(|| {
            Error::Protocol("range completeness attestation must serialize as an object".to_owned())
        })?;
        object.remove("proofs");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(
            &self.proof_payload_bytes()?,
        ))?)
    }

    /// Canonical detached-proof transcript used before a JWS exists.
    ///
    /// Producers must use the unsigned proof state rather than constructing a
    /// production `PayloadProof` with an empty JWS.
    pub fn proof_signing_bytes(&self, proof: &UnsignedPayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest {
            return Err(Error::Protocol(
                "range completeness proof payload_digest mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::Map::from_iter([
            (
                "context".to_owned(),
                Value::String(ProofContextId::RANGE_COMPLETENESS_ATTESTATION_PROOF_V1.to_owned()),
            ),
            (
                "payload_digest".to_owned(),
                serde_json::to_value(&payload_digest)?,
            ),
            ("issuer".to_owned(), serde_json::to_value(&self.issuer)?),
            (
                "scope".to_owned(),
                serde_json::json!({
                    "realm_id": self.realm_id,
                    "event_range": self.event_range,
                }),
            ),
            (
                "verification_method".to_owned(),
                serde_json::to_value(&proof.verification_method)?,
            ),
            (
                "created_at".to_owned(),
                Value::String(canonical::format_timestamp_canonical(proof.created_at)),
            ),
        ]);
        if let Some(domain) = &proof.domain {
            binding.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &proof.audience {
            binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(&Value::Object(binding))?)
    }

    /// Canonical detached-proof transcript registered for the range
    /// completeness object family.
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        self.proof_signing_bytes(&proof.unsigned())
    }
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
    pub actor_id: DidCoreId,
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

/// Counterpart for
/// `spec/v1/artifacts/schemas/snapshot.schema.json#/$defs/snapshot_witness_attestation`.
///
/// A distinct object family from the manifest: the witness signs the canonical
/// signature-free projection of `snapshot-schema.md` §5.1 under
/// `ak.snapshot-witness-attestation-proof-v1`, never the manifest transcript.
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
    pub issuer: DidCoreId,
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
    pub created_by: DidCoreId,
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
    pub created_by: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub authority_binding: SnapshotAuthorityBinding,
    pub signature: PayloadProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<SnapshotVerificationHintsValue>,
}
