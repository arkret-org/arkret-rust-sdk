use std::collections::BTreeSet;

use arkret_wire::{ActorId, DidCoreId, DidUrl, ProofContextId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::constants::DETACHED_JWS_PROOF_KIND;
use super::merkle::sha256_digest;
use crate::{
    BlobRef, CellRef, EventId, Hash, Hlc, RealmId, RealmStateSnapshotId, Result, WireError,
};

/// Object-family context of `authority_binding.witness_attestations[]`. It is
/// deliberately not the manifest's `ak.realm_state_snapshot_proof.v1`: a witness signature
/// produced under the manifest context is rejected even when the JWS verifies
/// (`realm-state-snapshot-schema.md` §5.1).
pub const REALM_STATE_SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT: &str =
    ProofContextId::REALM_STATE_SNAPSHOT_WITNESS_ATTESTATION_PROOF_V1;

/// Exact authorization context bound by every snapshot chunk.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEligibilityContext {
    pub authority_refs: Vec<crate::SealId>,
    pub closure_command_refs: Vec<EventId>,
    pub reducer_contract_digest: Hash,
}

impl SnapshotEligibilityContext {
    pub fn digest(&self) -> Result<Hash> {
        if self.authority_refs.iter().collect::<BTreeSet<_>>().len() != self.authority_refs.len()
            || self
                .closure_command_refs
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.closure_command_refs.len()
            || !self.reducer_contract_digest.as_str().starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "snapshot eligibility context requires unique references and a SHA-256 contract digest"
                    .to_owned(),
            ));
        }
        Ok(sha256_digest(&crate::canonical::canonical_json_bytes(
            self,
        )?))
    }
}

/// Original signed evidence retained for reclassification after later closures.
#[derive(Clone, Debug)]
pub struct SnapshotReplayEvidence {
    pub eligibility_context: SnapshotEligibilityContext,
    pub replay_events: Vec<arkret_wire::Event>,
    pub replay_authority_refs: Vec<crate::SealId>,
}

/// Full `ak.schema.realm_state_snapshot.v1` manifest returned by
/// `ak.self.realm_state_snapshot.read.manifest_head.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStateSnapshotManifest {
    pub id: RealmStateSnapshotId,
    pub realm_id: RealmId,
    pub reducer_profile: String,
    pub security_class: RealmStateSnapshotSecurityClass,
    pub schema_profile_refs: Vec<String>,
    pub state_digest: Hash,
    pub frontier: RealmStateSnapshotFrontier,
    pub event_set_commitment: EventSetCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<RealmStateSnapshotVerificationHints>,
    pub chunks: Vec<RealmStateSnapshotChunkDescriptor>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub authority_binding: AuthorityBinding,
    pub signature: DetachedJwsProof,
    pub eligibility_context: SnapshotEligibilityContext,
}

/// Snapshot manifest view used for canonical signing bytes.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UnsignedRealmStateSnapshotManifest<'a> {
    pub id: &'a RealmStateSnapshotId,
    pub realm_id: &'a RealmId,
    pub reducer_profile: &'a str,
    pub security_class: &'a RealmStateSnapshotSecurityClass,
    pub schema_profile_refs: &'a [String],
    pub state_digest: &'a Hash,
    pub frontier: &'a RealmStateSnapshotFrontier,
    pub event_set_commitment: &'a EventSetCommitment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<&'a RealmStateSnapshotVerificationHints>,
    pub chunks: &'a [RealmStateSnapshotChunkDescriptor],
    pub created_by: &'a ActorId,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub authority_binding: &'a AuthorityBinding,
    pub eligibility_context: &'a SnapshotEligibilityContext,
}

impl RealmStateSnapshotManifest {
    pub fn unsigned_view(&self) -> UnsignedRealmStateSnapshotManifest<'_> {
        UnsignedRealmStateSnapshotManifest {
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
            eligibility_context: &self.eligibility_context,
        }
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.unsigned_view().canonical_bytes()
    }

    pub fn expected_signature_digest(&self) -> Result<Hash> {
        self.unsigned_view().payload_digest()
    }
}

impl UnsignedRealmStateSnapshotManifest<'_> {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(crate::canonical::canonical_json_bytes(self)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Ok(sha256_digest(&self.canonical_bytes()?))
    }
}

impl RealmStateSnapshotManifest {
    /// Exact canonical `RealmStateSnapshotWitnessAttestation` projection of
    /// `realm-state-snapshot-schema.md` §5.1.
    ///
    /// Every value is recomputed from the manifest and the row's `witness_id`.
    /// The proof itself, `signature`, the whole `witness_attestations[]`,
    /// `verification_hints`, `chunks[]`, `created_by` (whose value must equal
    /// the included `issuer`) and `authority_binding.checked_at` are excluded —
    /// that exclusion is what keeps a witness from ever signing a transcript
    /// containing its own or another witness's signature.
    pub fn witness_attestation_projection(&self, witness_id: &DidCoreId) -> Result<Value> {
        Ok(serde_json::json!({
            "context": REALM_STATE_SNAPSHOT_WITNESS_ATTESTATION_PROOF_CONTEXT,
            "witness_id": witness_id,
            "realm_state_snapshot_id": self.id,
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
            "realm_state_snapshot_created_at": arkret_canonical::canonical::format_timestamp_canonical(
                self.created_at,
            ),
            "eligibility_context": self.eligibility_context,
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

    /// Witness-quorum admission of `realm-state-snapshot-schema.md` §5.1.
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
    /// first (`realm-state-snapshot-schema.md` §5.1).
    pub fn validate_witness_attestation_shape(
        &self,
    ) -> std::result::Result<(), RealmStateSnapshotValidationError> {
        let attestations = &self.authority_binding.witness_attestations;
        if self.authority_binding.authority_kind != RealmStateSnapshotAuthorityKind::WitnessQuorum {
            if attestations.is_empty() {
                return Ok(());
            }
            return Err(RealmStateSnapshotValidationError::new(
                RealmStateSnapshotValidationCode::SchemaViolation,
                "witness_attestations are only carried by authority_kind=witness_quorum",
            ));
        }
        if attestations.is_empty() {
            return Err(RealmStateSnapshotValidationError::new(
                RealmStateSnapshotValidationCode::SchemaViolation,
                "authority_kind=witness_quorum requires a non-empty witness_attestations list",
            ));
        }
        for pair in attestations.windows(2) {
            if pair[0].witness_id.as_str() >= pair[1].witness_id.as_str() {
                return Err(RealmStateSnapshotValidationError::new(
                    RealmStateSnapshotValidationCode::SchemaViolation,
                    "witness_attestations must be sorted by unique witness_id in UTF-8 byte order",
                ));
            }
        }
        Ok(())
    }

    pub fn verify_witness_attestations(
        &self,
        policy: &RealmStateSnapshotWitnessQuorumPolicy,
    ) -> std::result::Result<(), RealmStateSnapshotValidationError> {
        self.validate_witness_attestation_shape()?;
        let attestations = &self.authority_binding.witness_attestations;
        if self.authority_binding.authority_kind != RealmStateSnapshotAuthorityKind::WitnessQuorum {
            return Ok(());
        }

        for attestation in attestations {
            if !policy
                .authorized_witnesses
                .contains(&attestation.witness_id)
            {
                return Err(RealmStateSnapshotValidationError::new(
                    RealmStateSnapshotValidationCode::SnapshotAuthorityUnverified,
                    format!(
                        "witness {} is not an authorized non-revoked snapshot witness at created_at",
                        attestation.witness_id
                    ),
                ));
            }
            if attestation.proof.kind != DETACHED_JWS_PROOF_KIND
                || attestation.proof.jws.trim().is_empty()
            {
                return Err(RealmStateSnapshotValidationError::new(
                    RealmStateSnapshotValidationCode::SignatureInvalid,
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
                    RealmStateSnapshotValidationError::new(
                        RealmStateSnapshotValidationCode::SignatureInvalid,
                        "witness attestation verification_method has no controller",
                    )
                })?;
            let controller = project_witness_controller(controller).ok_or_else(|| {
                RealmStateSnapshotValidationError::new(
                    RealmStateSnapshotValidationCode::SignatureInvalid,
                    "witness attestation verification_method controller is not projectable by a registered DID method adapter",
                )
            })?;
            if controller != attestation.witness_id {
                return Err(RealmStateSnapshotValidationError::new(
                    RealmStateSnapshotValidationCode::SignatureInvalid,
                    "witness attestation verification_method controller does not project to witness_id",
                ));
            }
            let expected = self
                .witness_attestation_digest(&attestation.witness_id)
                .map_err(|error| {
                    RealmStateSnapshotValidationError::new(
                        RealmStateSnapshotValidationCode::DigestMismatch,
                        format!("witness attestation projection could not be computed: {error}"),
                    )
                })?;
            if attestation.proof.payload_digest != expected {
                return Err(RealmStateSnapshotValidationError::new(
                    RealmStateSnapshotValidationCode::SignatureInvalid,
                    "witness attestation payload_digest does not match the canonical witness projection",
                ));
            }
        }

        if attestations.len() < policy.threshold as usize {
            return Err(RealmStateSnapshotValidationError::new(
                RealmStateSnapshotValidationCode::SnapshotAuthorityUnverified,
                "deduplicated valid witness count is below the policy-derived threshold",
            ));
        }
        Ok(())
    }
}

/// Project a bare controller DID to its stable `did_core_id` through the
/// registered method adapter. Direct DID / core-id string comparison is
/// forbidden (`realm-state-snapshot-schema.md` §5.1).
fn project_witness_controller(controller: &str) -> Option<DidCoreId> {
    let did = arkret_wire::Did::new(controller).ok()?;
    arkret_wire::project_did_to_core_id(&did).ok()
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmStateSnapshotFrontier {
    pub event_ids: Vec<EventId>,
    pub timeline_hlc: Hlc,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmStateSnapshotSecurityClass {
    Standard,
    HighAssurance,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStateSnapshotChunkDescriptor {
    pub chunk_ref: BlobRef,
    pub size_bytes: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ActorSeqRangeCommitment {
    pub actor_id: ActorId,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSetLeaf {
    pub event_id: EventId,
    pub event_digest: Hash,
    pub actor_id: ActorId,
    pub actor_seq: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_event_hlc"
    )]
    pub hlc: Option<Hlc>,
}

fn present_event_hlc<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Hlc>, D::Error> {
    Hlc::deserialize(deserializer).map(Some)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityBinding {
    pub authority_kind: RealmStateSnapshotAuthorityKind,
    pub auth_state_digest: Hash,
    pub auth_frontier: Vec<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub checked_at: DateTime<Utc>,
    /// Typed witness quorum evidence, sorted by `witness_id` in UTF-8 byte
    /// order with `witness_id` unique across rows. v1 has no untyped equivalent
    /// quorum carrier (`realm-state-snapshot-schema.md` §5.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_attestations: Vec<RealmStateSnapshotWitnessAttestation>,
}

/// One witness statement that the snapshot issuer held snapshot-sealing
/// authority for this exact reduced state at manifest `created_at`
/// (`realm-state-snapshot.schema.json#/$defs/realm_state_snapshot_witness_attestation`).
///
/// It is a separate object family from the manifest: the witness signs the
/// canonical signature-free projection of `realm-state-snapshot-schema.md` §5.1 under
/// `ak.realm_state_snapshot_witness_attestation_proof.v1`. Reusing the manifest-level
/// `ak.realm_state_snapshot_proof.v1` context here is rejected.
///
/// This is the **verification model** half of the snapshot model, alongside
/// [`RealmStateSnapshotManifest`] and [`AuthorityBinding`]: it carries the typed
/// [`DetachedJwsProof`] this crate signs and verifies, and it is the half that
/// owns [`RealmStateSnapshotManifest::witness_attestation_projection`] and
/// [`RealmStateSnapshotManifest::verify_witness_attestations`]. The **wire DTO** half is
/// `arkret_models_collaboration::sync_frames::realm_state_snapshot::RealmStateSnapshotWitnessSignature`,
/// which mirrors the schema verbatim with the full shared `PayloadProof` leaf.
/// The two halves are named apart on purpose — same as
/// [`RealmStateSnapshotChunkDescriptor`]
/// vs `RealmStateSnapshotChunkRef` — so neither shadows the other in the
/// `arkret_sdk` prelude.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmStateSnapshotWitnessAttestation {
    /// Stable `did_core_id` of the witness. Quorum counting is per
    /// `witness_id`, so several keys of one witness count once.
    pub witness_id: DidCoreId,
    pub proof: DetachedJwsProof,
}

/// Witness-quorum admission inputs resolved from the accepted Realm
/// auth/policy state at `manifest.created_at` through
/// `authority_binding.auth_frontier` / `auth_state_digest`
/// (`realm-state-snapshot-schema.md` §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmStateSnapshotWitnessQuorumPolicy {
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
pub enum RealmStateSnapshotAuthorityKind {
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
pub struct RealmStateSnapshotVerificationHints {
    pub verification_profile: RealmStateSnapshotSecurityClass,
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
    /// Digest of `erasure_stubs[]` concatenated across chunks in index order.
    /// Present whenever any chunk carries an erasure stub: erased cells are not
    /// `state_digest` leaves, so this is their only commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_stubs_digest: Option<Hash>,
}

/// The literal kind of every registered snapshot Cell item.
pub const SNAPSHOT_CELL_KIND: &str = "cell";

/// Complete registered model state at one authenticated eligibility context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmStateSnapshotMaterializedItem {
    cell: CellRef,
    state: arkret_wire::CanonicalCellState,
}

impl RealmStateSnapshotMaterializedItem {
    pub fn new(cell: CellRef, state: arkret_wire::CanonicalCellState) -> Result<Self> {
        state.validate_for_cell(&cell)?;
        Ok(Self { cell, state })
    }

    pub fn from_resolved(
        cell: CellRef,
        state: &crate::state_model::ResolvedCellState,
    ) -> Result<Self> {
        use arkret_wire::EventCellStateModel as Wire;

        use crate::state_model::StateModelKind as Model;
        let model = match arkret_wire::registered_cell_state_model(&cell)? {
            Wire::CausalRegister => Model::CausalRegister,
            Wire::SequencedState => Model::SequencedState,
            Wire::OrSet => Model::OrSet,
            Wire::OrderedLog => Model::OrderedLog,
            Wire::Counter => Model::Counter,
        };
        Self::new(
            cell,
            crate::state_model::canonical_cell_state(model, state)?,
        )
    }

    pub fn cell(&self) -> &CellRef {
        &self.cell
    }
    pub fn state(&self) -> &arkret_wire::CanonicalCellState {
        &self.state
    }
    pub fn kind(&self) -> &'static str {
        SNAPSHOT_CELL_KIND
    }
    pub fn id(&self) -> &str {
        self.cell.as_str()
    }

    pub fn leaf_preimage(&self) -> Value {
        serde_json::json!({"cell": self.cell, "state_model": self.state.state_model(), "state": self.state})
    }
}

/// The flat wire object of one item.
///
/// Kept separate from [`RealmStateSnapshotMaterializedItem`] so the union stays closed:
/// `kind` is checked against the single registered literal and `state` is
/// re-validated against the registry on the way in.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnapshotItem {
    kind: String,
    id: String,
    state: Value,
    state_model: arkret_wire::EventCellStateModel,
}

/// The OpenAPI shape is the flat wire object: `{kind, id, state, state_model}` with `state`
/// being the §6.2.1 state_object. Delegating to [`RawSnapshotItem`] keeps the
/// document describing what is actually serialized.
#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for RealmStateSnapshotMaterializedItem {
    fn to_schema(
        components: &mut salvo_oapi::Components,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        <RawSnapshotItem as salvo_oapi::ToSchema>::to_schema(components)
    }
}

impl Serialize for RealmStateSnapshotMaterializedItem {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        RawSnapshotItem {
            kind: SNAPSHOT_CELL_KIND.to_owned(),
            id: self.cell.as_str().to_owned(),
            state: self.state.to_state_object(),
            state_model: self.state.state_model(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RealmStateSnapshotMaterializedItem {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let raw = RawSnapshotItem::deserialize(deserializer)?;
        if raw.kind != SNAPSHOT_CELL_KIND {
            return Err(D::Error::custom(format!(
                "snapshot items[] is a closed union whose only kind is \"cell\"; got {:?}",
                raw.kind
            )));
        }
        let cell = CellRef::new(raw.id).map_err(D::Error::custom)?;
        let state = arkret_wire::CanonicalCellState::from_state_object(raw.state_model, raw.state)
            .map_err(D::Error::custom)?;
        Self::new(cell, state).map_err(D::Error::custom)
    }
}

/// One row of a chunk's `conflict_records[]` (`realm-state-snapshot-schema.md` §3): either
/// a written non-`causal_register` cell whose join is `⊥` — it has no leaf, but a
/// restoring receiver must fail closed on it rather than read it as never
/// written — or an Event input whose admission is still undecided.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmStateSnapshotConflictRecord {
    BottomCell {
        cell_ref: CellRef,
    },
    Event {
        event_id: EventId,
        actor_id: ActorId,
        actor_seq: u64,
    },
}

/// One non-accepted Event input inside the snapshot frontier, addressable by
/// the `(actor_id, actor_seq)` coordinates §6 gap attribution uses.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotNonAcceptedInput {
    pub event_id: EventId,
    pub actor_id: ActorId,
    pub actor_seq: u64,
}

/// One cell whose canonical value the issuer can no longer reproduce because a
/// hard erasure removed it. It is not a `state_digest` leaf; the
/// `ak.schema.erasure_verification_stub.v1` bound by the erasure receipt is
/// carried instead and committed through `verification_hints.erasure_stubs_digest`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotErasureStub {
    pub cell_ref: CellRef,
    pub stub: arkret_models_collaboration::events_payloads::event_wire::VerificationStub,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// One `ak.schema.realm_state_snapshot_chunk.v1` payload — the canonical JSON behind a
/// manifest `chunks[].chunk_ref` (`realm-state-snapshot-schema.md` §3). Closed on the way
/// in: an unknown member or an item outside the single `cell` branch fails to
/// parse.
#[serde(deny_unknown_fields)]
pub struct RealmStateSnapshotChunkPayload {
    pub chunk_kind: String,
    pub realm_state_snapshot_ref: RealmStateSnapshotId,
    pub index: u32,
    pub reducer_profile: String,
    pub items: Vec<RealmStateSnapshotMaterializedItem>,
    pub conflict_records: Vec<RealmStateSnapshotConflictRecord>,
    pub soft_failed: Vec<SnapshotNonAcceptedInput>,
    pub quarantined: Vec<SnapshotNonAcceptedInput>,
    pub erasure_stubs: Vec<SnapshotErasureStub>,
    pub eligibility_context_digest: Hash,
    pub replay_events: Vec<arkret_wire::Event>,
    pub replay_authority_refs: Vec<crate::SealId>,
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for RealmStateSnapshotChunkPayload {
    fn to_schema(_: &mut salvo_oapi::Components) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        salvo_oapi::Ref::new("https://arkret.org/v1/schemas/realm-state-snapshot-chunk.schema.json")
            .into()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BuiltRealmStateSnapshotChunk {
    pub payload: RealmStateSnapshotChunkPayload,
    pub canonical_bytes: Vec<u8>,
    pub descriptor: RealmStateSnapshotChunkDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealmStateSnapshotValidationCode {
    DigestMismatch,
    SchemaViolation,
    SignatureInvalid,
    SnapshotAuthorityUnverified,
    SnapshotIssuerRevoked,
    InclusionProofFailed,
    SnapshotUnavailable,
}

impl RealmStateSnapshotValidationCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DigestMismatch => crate::ErrorCode::DIGEST_MISMATCH,
            Self::SchemaViolation => crate::error::ErrorCode::SCHEMA_VIOLATION,
            Self::SignatureInvalid => crate::error::ErrorCode::SIGNATURE_INVALID,
            Self::SnapshotAuthorityUnverified => {
                crate::error::ErrorCode::REALM_STATE_SNAPSHOT_AUTHORITY_UNVERIFIED
            }
            Self::SnapshotIssuerRevoked => "realm_state_snapshot_issuer_revoked",
            Self::InclusionProofFailed => "inclusion_proof_failed",
            Self::SnapshotUnavailable => crate::error::ErrorCode::REALM_STATE_SNAPSHOT_UNAVAILABLE,
        }
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("{code:?}: {message}")]
pub struct RealmStateSnapshotValidationError {
    pub code: RealmStateSnapshotValidationCode,
    pub message: String,
}

impl RealmStateSnapshotValidationError {
    pub fn new(code: RealmStateSnapshotValidationCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmStateSnapshotVerifyOptions {
    pub now: DateTime<Utc>,
    pub expected_reducer_profile: String,
    pub allow_high_assurance: bool,
}

impl RealmStateSnapshotVerifyOptions {
    pub fn standard(now: DateTime<Utc>, expected_reducer_profile: impl Into<String>) -> Self {
        Self {
            now,
            expected_reducer_profile: expected_reducer_profile.into(),
            allow_high_assurance: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmStateSnapshotVerifyReport {
    pub item_count: usize,
    pub chunk_count: usize,
    pub state_digest: Hash,
}
