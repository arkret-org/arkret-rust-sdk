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

/// Full `ak.schema.realm_state_snapshot.v1` manifest returned by
/// `ak.self.realm_state_snapshot.read.manifest_head.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmStateSnapshotManifest {
    pub id: RealmStateSnapshotId,
    pub realm_id: RealmId,
    pub reducer_profile: String,
    pub security_class: RealmStateSnapshotSecurityClass,
    #[serde(default)]
    pub schema_profile_refs: Vec<String>,
    pub state_digest: Hash,
    pub frontier: RealmStateSnapshotFrontier,
    pub event_set_commitment: EventSetCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_hints: Option<RealmStateSnapshotVerificationHints>,
    #[serde(default)]
    pub chunks: Vec<RealmStateSnapshotChunkDescriptor>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub authority_binding: AuthorityBinding,
    pub signature: DetachedJwsProof,
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
    #[serde(default)]
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
pub struct RealmStateSnapshotChunkDescriptor {
    pub chunk_ref: BlobRef,
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
    pub actor_id: ActorId,
    pub from_seq: u64,
    pub to_seq: u64,
    pub root: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSetLeaf {
    pub event_id: EventId,
    pub event_digest: Hash,
    pub actor_id: ActorId,
    pub actor_seq: u64,
    pub hlc: Hlc,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityBinding {
    pub authority_kind: RealmStateSnapshotAuthorityKind,
    pub auth_state_digest: Hash,
    #[serde(default)]
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
/// `arkret_models_collaboration::sync_frames::realm_state_snapshot::RealmStateSnapshotWitnessAttestationItem`,
/// which mirrors the schema verbatim with the full shared `PayloadProof` leaf.
/// The two halves are named apart on purpose — same as
/// [`RealmStateSnapshotChunkDescriptor`]
/// vs `RealmStateSnapshotChunksItem` — so neither shadows the other in the
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

/// One still-active `cas_register` write inside a snapshot chunk.
///
/// The wire form of `event-auth-state-resolution.md` §6.2.1's head entry. The
/// identity is the `ak:event:` spelling here rather than the `event_digest` the
/// op log stores, because this is the byte-exact preimage every implementation
/// has to reproduce.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStateSnapshotCasHead {
    pub event_id: EventId,
    pub value: Value,
}

/// The `state` of one snapshot cell item: exactly the `state_object` that
/// `event-auth-state-resolution.md` §6.2.1 gives that cell's registered
/// lattice.
///
/// `{"heads":[…]}` for a `cas_register` cell, `{"value":…}` for every other
/// lattice. The two shapes are mutually exclusive and carry no other member, so
/// a cell's snapshot state and its `state_root` leaf preimage
/// `{"cell","state"}` are one definition, not two that can drift
/// (`realm-state-snapshot-schema.md` §3 / §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotCellState {
    /// Joined lattice value of a materialized non-`cas_register` cell, verbatim.
    /// An encrypted envelope projected from an Event payload stays an
    /// envelope: the issuer never decrypts, re-encrypts or substitutes.
    Value(Value),
    /// Complete active head set of a written `cas_register` cell, ordered by the
    /// decoded 33-octet `event_id` token with identities unique. Never empty:
    /// an unwritten cell is not a member.
    Heads(Vec<RealmStateSnapshotCasHead>),
}

impl SnapshotCellState {
    /// The §6.2.1 `state_object` this state serializes to.
    pub fn to_state_object(&self) -> Value {
        match self {
            Self::Value(value) => serde_json::json!({ "value": value }),
            Self::Heads(heads) => serde_json::json!({ "heads": heads }),
        }
    }
}

impl Serialize for SnapshotCellState {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.to_state_object().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SnapshotCellState {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let mut object = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        let keys = object.keys().cloned().collect::<Vec<_>>();
        match keys.as_slice() {
            [key] if key == "value" => {
                Ok(Self::Value(object.remove("value").unwrap_or(Value::Null)))
            }
            [key] if key == "heads" => {
                let heads = serde_json::from_value::<Vec<RealmStateSnapshotCasHead>>(
                    object.remove("heads").unwrap_or(Value::Null),
                )
                .map_err(D::Error::custom)?;
                cas_heads_are_canonical(&heads).map_err(D::Error::custom)?;
                Ok(Self::Heads(heads))
            }
            _ => Err(D::Error::custom(
                "a snapshot cell state is exactly one of {\"value\":…} or {\"heads\":[…]}",
            )),
        }
    }
}

/// The decoded 33-octet token of an `ak:event:` identity — the §6.2.1 sort key
/// of a head set. Wire strings are never compared directly.
fn event_token_bytes(event_id: &EventId) -> std::result::Result<Vec<u8>, String> {
    let token = event_id
        .as_str()
        .strip_prefix("ak:event:")
        .ok_or_else(|| format!("{event_id} is not an ak:event: identity"))?;
    let bytes = crate::base64url::base64url_decode(token)
        .map_err(|error| format!("{event_id} has an undecodable token: {error}"))?;
    if bytes.len() != 33 {
        return Err(format!("{event_id} does not decode to 33 octets"));
    }
    Ok(bytes)
}

/// §6.2.1: a head set is non-empty, sorted by decoded token in unsigned
/// lexicographic ascending order, and carries each identity once.
fn cas_heads_are_canonical(heads: &[RealmStateSnapshotCasHead]) -> std::result::Result<(), String> {
    if heads.is_empty() {
        return Err(
            "a cas_register snapshot item carries at least one head; an unwritten cell \
                    is not a member"
                .to_owned(),
        );
    }
    let mut previous: Option<Vec<u8>> = None;
    for head in heads {
        let token = event_token_bytes(&head.event_id)?;
        if let Some(previous) = &previous
            && token <= *previous
        {
            return Err(
                "cas_register heads must be sorted by decoded event_id token in ascending order \
                 with unique identities"
                    .to_owned(),
            );
        }
        previous = Some(token);
    }
    Ok(())
}

/// The literal `kind` of every snapshot item (`realm-state-snapshot-schema.md` §3).
pub const SNAPSHOT_CELL_KIND: &str = "cell";

/// One written Realm-scope reducer cell inside a snapshot chunk.
///
/// `realm-state-snapshot-schema.md` §3 makes `items[]` a closed single-branch union:
/// `{"kind":"cell","id":<cell wire id>,"state":<state_object>}`. There is no
/// materialized-object branch — a snapshot ships the reducer's own state and a
/// consumer derives display objects locally, exactly as it does from replay —
/// and no `source_event_id`: write identities live inside the lattice state
/// (CAS heads, or_set dots, ordered_log entries), and one identity could not
/// name several live writes anyway.
///
/// Construction and deserialization both enforce the registry: the family must
/// be one a registered `cell_writes[]` row writes, and the state shape must be
/// the one its lattice gets — `heads` for `cas_register`, `value` otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmStateSnapshotMaterializedItem {
    cell: CellRef,
    state: SnapshotCellState,
}

impl RealmStateSnapshotMaterializedItem {
    /// Build an item for one written cell, validating it against the registry.
    pub fn new(cell: CellRef, state: SnapshotCellState) -> Result<Self> {
        validate_snapshot_cell(&cell, &state)?;
        Ok(Self { cell, state })
    }

    /// An item for a materialized non-`cas_register` cell.
    pub fn value(cell: CellRef, value: Value) -> Result<Self> {
        Self::new(cell, SnapshotCellState::Value(value))
    }

    /// An item for one written `cas_register` cell.
    ///
    /// `heads` comes from [`crate::lattice::cas_register::cas_heads`], already
    /// ordered by the decoded `event_id` token. Each head's identity is
    /// recovered losslessly from its `event_digest`, so the chunk never depends
    /// on a second stored spelling of the same identity.
    ///
    /// An empty head set is rejected rather than emitted: §6.2.1 makes an
    /// unwritten cell a non-member, so an empty entry would put a leaf in the
    /// tree for a cell that must not have one.
    pub fn cas_cell(
        cell: CellRef,
        heads: &[crate::lattice::cas_register::CasHead],
    ) -> Result<Self> {
        let heads = heads
            .iter()
            .map(|head| {
                Ok(RealmStateSnapshotCasHead {
                    event_id: EventId::from_event_digest(&head.move_id)
                        .map_err(|error| WireError::Protocol(error.to_string()))?,
                    value: head.value.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Self::new(cell, SnapshotCellState::Heads(heads))
    }

    pub fn cell(&self) -> &CellRef {
        &self.cell
    }

    pub fn state(&self) -> &SnapshotCellState {
        &self.state
    }

    /// The `kind` this item sorts and deduplicates under.
    pub fn kind(&self) -> &'static str {
        SNAPSHOT_CELL_KIND
    }

    /// The `id` this item sorts and deduplicates under.
    pub fn id(&self) -> &str {
        self.cell.as_str()
    }

    /// The §6.2.1 leaf preimage `{"cell": id, "state": state_object}` — the
    /// same bytes the Seal `state_root` hashes for this cell.
    pub fn leaf_preimage(&self) -> Value {
        serde_json::json!({
            "cell": self.cell.as_str(),
            "state": self.state.to_state_object(),
        })
    }
}

fn validate_snapshot_cell(cell: &CellRef, state: &SnapshotCellState) -> Result<()> {
    if !arkret_wire::is_registered_cell(cell.as_str()) {
        return Err(WireError::Protocol(format!(
            "{cell} is not a cell any registered reducer contract writes; it cannot be a \
             snapshot item"
        )));
    }
    let cas = arkret_wire::is_registered_cas_register_cell(cell.as_str());
    match (cas, state) {
        (true, SnapshotCellState::Heads(heads)) => {
            cas_heads_are_canonical(heads).map_err(WireError::Protocol)
        }
        (false, SnapshotCellState::Value(_)) => Ok(()),
        (true, SnapshotCellState::Value(_)) => Err(WireError::Protocol(format!(
            "{cell} is a cas_register cell; its snapshot state is {{\"heads\":[…]}}, not a value"
        ))),
        (false, SnapshotCellState::Heads(_)) => Err(WireError::Protocol(format!(
            "{cell} is not a cas_register cell; its snapshot state is {{\"value\":…}}, not heads"
        ))),
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
}

/// The OpenAPI shape is the flat wire object: `{kind, id, state}` with `state`
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
        let state =
            serde_json::from_value::<SnapshotCellState>(raw.state).map_err(D::Error::custom)?;
        Self::new(cell, state).map_err(D::Error::custom)
    }
}

/// One row of a chunk's `conflict_records[]` (`realm-state-snapshot-schema.md` §3): either
/// a written non-`cas_register` cell whose join is `⊥` — it has no leaf, but a
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
    pub stub: Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// One `ak.schema.realm_state_snapshot_chunk.v1` payload — the canonical JSON behind a
/// manifest `chunks[].chunk_ref` (`realm-state-snapshot-schema.md` §3). Closed on the way
/// in: an unknown member, a legacy `type` discriminator or an item outside the
/// single `cell` branch fails to parse.
#[serde(deny_unknown_fields)]
pub struct RealmStateSnapshotChunkPayload {
    pub chunk_kind: String,
    pub realm_state_snapshot_ref: RealmStateSnapshotId,
    pub index: u32,
    pub reducer_profile: String,
    #[serde(default)]
    pub items: Vec<RealmStateSnapshotMaterializedItem>,
    #[serde(default)]
    pub conflict_records: Vec<RealmStateSnapshotConflictRecord>,
    #[serde(default)]
    pub soft_failed: Vec<SnapshotNonAcceptedInput>,
    #[serde(default)]
    pub quarantined: Vec<SnapshotNonAcceptedInput>,
    #[serde(default)]
    pub erasure_stubs: Vec<SnapshotErasureStub>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

