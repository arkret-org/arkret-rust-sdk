//! Consumer side of `conformance/realm-state-snapshot-schema.md`.
//!
//! The producer half of this module turns a joined view into a signed manifest
//! and content-addressed chunks. This half is the inverse a receiver runs: it
//! verifies the delivered manifest and chunks against §5's checklist, then
//! materializes `items[]` back into the lattice states the reducer keeps —
//! `cas_register` head sets and joined values for every other lattice.
//!
//! The part that is easy to skip and MUST NOT be is [`CoveredEventSet`]. §3
//! requires a receiver restored from a snapshot to still answer «is this old
//! Event in the covered set `C`» exactly, because §9.3.1.4 evaluates a late
//! branch against `C`; a receiver that answers `false` because it merely
//! forgot resurrects writes that were already superseded. A snapshot manifest
//! commits `C` as a root, not as a list, so the honest answer for most Event
//! ids is [`CoveredEventMembership::Unknown`] — hold, never `false` — until the
//! receiver either retains the committed index or obtains a proof under the
//! manifest's own root.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use super::chunking::{event_set_root, state_digest_from_chunk_payloads};
use super::constants::{
    EMPTY_SHA256_DIGEST, REALM_STATE_SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS,
    REALM_STATE_SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS,
};
use super::merkle::{RealmStateSnapshotMerkleTree, sha256_digest};
use super::types::{
    DetachedJwsProof, EventSetCommitmentAlgorithm, EventSetLeaf, RealmStateSnapshotChunkPayload,
    RealmStateSnapshotManifest, RealmStateSnapshotSecurityClass, RealmStateSnapshotValidationCode,
    RealmStateSnapshotValidationError, RealmStateSnapshotVerifyOptions,
    RealmStateSnapshotVerifyReport, SnapshotCellState, SnapshotErasureStub,
    SnapshotNonAcceptedInput,
};
use super::verify_realm_state_snapshot_chunk_bytes;
use crate::lattice::cas_register::CasHead;
use crate::state::CasHeadsByCell;
use arkret_models_collaboration::sync_frames::realm_state_snapshot::RealmStateSnapshotBootstrap;

use crate::{CellRef, DidUrl, EventId, Hash, RealmStateSnapshotId};

type ValidationResult<T> = Result<T, RealmStateSnapshotValidationError>;

fn digest_mismatch(message: impl Into<String>) -> RealmStateSnapshotValidationError {
    RealmStateSnapshotValidationError::new(
        RealmStateSnapshotValidationCode::DigestMismatch,
        message,
    )
}

fn schema_violation(message: impl Into<String>) -> RealmStateSnapshotValidationError {
    RealmStateSnapshotValidationError::new(
        RealmStateSnapshotValidationCode::SchemaViolation,
        message,
    )
}

fn signature_invalid(message: impl Into<String>) -> RealmStateSnapshotValidationError {
    RealmStateSnapshotValidationError::new(
        RealmStateSnapshotValidationCode::SignatureInvalid,
        message,
    )
}

fn authority_unverified(message: impl Into<String>) -> RealmStateSnapshotValidationError {
    RealmStateSnapshotValidationError::new(
        RealmStateSnapshotValidationCode::SnapshotAuthorityUnverified,
        message,
    )
}

fn inclusion_proof_failed(message: impl Into<String>) -> RealmStateSnapshotValidationError {
    RealmStateSnapshotValidationError::new(
        RealmStateSnapshotValidationCode::InclusionProofFailed,
        message,
    )
}

/// The `realm_state_snapshot_max_acceptance_age_ms` of a security class
/// (`realm-state-snapshot-schema.md` §5): 30 days by default, tightened to 7
/// for `high_assurance`.
pub fn realm_state_snapshot_max_acceptance_age_ms(
    security_class: &RealmStateSnapshotSecurityClass,
) -> i64 {
    match security_class {
        RealmStateSnapshotSecurityClass::Standard => {
            REALM_STATE_SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS
        }
        RealmStateSnapshotSecurityClass::HighAssurance => {
            REALM_STATE_SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS
        }
    }
}

/// Whether one Event belongs to a restored snapshot's covered set `C`.
///
/// Three-valued on purpose. `realm-state-snapshot-schema.md` §3 forbids
/// collapsing the third case into `NotCovered`: a receiver that cannot produce
/// evidence MUST hold, because reading «no evidence» as «the peer never saw it»
/// is exactly what revives a superseded write when §9.3.1.4 merges a late
/// branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoveredEventMembership {
    /// The Event is in `C`, on evidence bound to the manifest's own
    /// `event_set_commitment.root` (or it is a frontier head, which is in `C`
    /// by construction).
    Covered,
    /// The Event is provably not in `C`: the receiver holds the complete
    /// committed index and the Event is absent from it.
    NotCovered,
    /// No evidence either way. The caller MUST hold or fail closed.
    Unknown,
}

/// The covered set `C` of a restored snapshot, as much of it as the receiver
/// can actually prove.
///
/// A manifest commits `C` as `event_set_commitment.root` plus a count; it does
/// not ship the members. So a freshly restored set answers [`CoveredEventMembership::Covered`]
/// only for the frontier heads and [`CoveredEventMembership::Unknown`] for
/// everything else, which is the §3 «hold» outcome rather than a wrong `false`.
/// The two ways §3 allows to do better are both here:
///
/// - [`CoveredEventSet::admit_committed_index`] — «保留共享 membership 索引»:
///   hand back the whole committed entry list, checked by recomputing the root.
///   Only then does an absent id become [`CoveredEventMembership::NotCovered`].
/// - [`CoveredEventSet::admit_inclusion_proof`] — «按现有 root 取得有效证明»:
///   one entry plus its `merkle_event_set_v1` audit path against that same root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoveredEventSet {
    algorithm: EventSetCommitmentAlgorithm,
    root: Hash,
    covered_event_count: u64,
    frontier: BTreeSet<EventId>,
    proven: BTreeMap<EventId, EventSetLeaf>,
    complete: bool,
}

impl CoveredEventSet {
    /// The set a commitment and a frontier alone support.
    ///
    /// Separate from [`Self::from_manifest`] so a receiver that persisted only
    /// the commitment and frontier — which is all §3 obliges it to keep — can
    /// rebuild the oracle across a restart without holding the whole manifest.
    pub fn new(
        algorithm: EventSetCommitmentAlgorithm,
        root: Hash,
        covered_event_count: u64,
        frontier: impl IntoIterator<Item = EventId>,
    ) -> Self {
        Self {
            algorithm,
            root,
            covered_event_count,
            frontier: frontier.into_iter().collect(),
            proven: BTreeMap::new(),
            complete: false,
        }
    }

    /// The set a manifest alone supports: frontier heads only, everything else
    /// unknown.
    pub fn from_manifest(manifest: &RealmStateSnapshotManifest) -> Self {
        Self::new(
            manifest.event_set_commitment.algorithm.clone(),
            manifest.event_set_commitment.root.clone(),
            manifest.event_set_commitment.covered_event_count,
            manifest.frontier.event_ids.iter().cloned(),
        )
    }

    pub fn root(&self) -> &Hash {
        &self.root
    }

    pub fn algorithm(&self) -> &EventSetCommitmentAlgorithm {
        &self.algorithm
    }

    pub fn covered_event_count(&self) -> u64 {
        self.covered_event_count
    }

    /// Whether this set can answer [`CoveredEventMembership::NotCovered`] at
    /// all. `false` means every id outside the frontier answers `Unknown`.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Adopt the full committed entry list as the receiver's membership index.
    ///
    /// The list is only believed when recomputing `event_set_commitment.root`
    /// over it reproduces the manifest's root under the manifest's declared
    /// algorithm, and when its length matches `covered_event_count`. Both
    /// checks matter: the root pins the contents, the count stops a caller
    /// from adopting a prefix as if it were the whole set and then answering
    /// `NotCovered` for the tail.
    pub fn admit_committed_index(&mut self, entries: Vec<EventSetLeaf>) -> ValidationResult<()> {
        if entries.len() as u64 != self.covered_event_count {
            return Err(inclusion_proof_failed(format!(
                "committed index has {} entries; the manifest commits {}",
                entries.len(),
                self.covered_event_count
            )));
        }
        let recomputed = event_set_root(&self.algorithm, &entries).map_err(|error| {
            inclusion_proof_failed(format!("committed index is not hashable: {error}"))
        })?;
        if recomputed != self.root {
            return Err(inclusion_proof_failed(format!(
                "committed index recomputes to {recomputed}; the manifest commits {}",
                self.root
            )));
        }
        self.proven = entries
            .into_iter()
            .map(|entry| (entry.event_id.clone(), entry))
            .collect();
        self.complete = true;
        Ok(())
    }

    /// Admit one entry proven against the manifest's own root.
    ///
    /// `merkle_event_set_v1` only: `ordered_event_id_sha256_v1` hashes the whole
    /// sorted array in one pass and has no per-entry audit path, so a caller
    /// holding a single entry under that algorithm has no proof to offer and
    /// must use [`Self::admit_committed_index`] instead.
    ///
    /// `leaf_index` is the entry's position in the `(actor_id, actor_seq,
    /// event_id)` ordering. It is not carried by the §6.2 challenge response
    /// shape, so a caller consuming that wire form has to recover it from its
    /// own copy of the ordering; an audit path verified without a fixed index
    /// would accept the entry at whatever position happens to fit.
    pub fn admit_inclusion_proof(
        &mut self,
        entry: EventSetLeaf,
        leaf_index: usize,
        audit_path: &[Hash],
    ) -> ValidationResult<()> {
        if !matches!(self.algorithm, EventSetCommitmentAlgorithm::MerkleEventSetV1) {
            return Err(inclusion_proof_failed(format!(
                "{:?} commits the whole sorted entry array and has no per-entry audit path",
                self.algorithm
            )));
        }
        let leaf_data = crate::canonical::canonical_json_bytes(&entry)
            .map_err(|error| inclusion_proof_failed(format!("entry is not canonical: {error}")))?;
        let leaf = sha256_digest(&leaf_data);
        if !RealmStateSnapshotMerkleTree::verify(
            &self.root,
            &leaf,
            leaf_index,
            audit_path,
            self.covered_event_count as usize,
        ) {
            return Err(inclusion_proof_failed(format!(
                "audit path for {} at index {leaf_index} does not reach {}",
                entry.event_id, self.root
            )));
        }
        self.proven.insert(entry.event_id.clone(), entry);
        Ok(())
    }

    /// Answer §3's membership question for one Event.
    pub fn membership(&self, event_id: &EventId) -> CoveredEventMembership {
        if self.proven.contains_key(event_id) || self.frontier.contains(event_id) {
            return CoveredEventMembership::Covered;
        }
        if self.complete {
            return CoveredEventMembership::NotCovered;
        }
        CoveredEventMembership::Unknown
    }

    /// The committed entry for an Event, when the receiver holds one.
    pub fn entry(&self, event_id: &EventId) -> Option<&EventSetLeaf> {
        self.proven.get(event_id)
    }
}

/// One cell as a restored snapshot carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoredCell {
    /// Joined value of a non-`cas_register` lattice, verbatim from the leaf.
    Value(serde_json::Value),
    /// The complete active head set of a `cas_register` cell.
    CasHeads(Vec<CasHead>),
}

/// A verified snapshot, materialized.
///
/// `bottom_cells` and `erasure_stubs` are carried beside the cells rather than
/// dropped: §3 makes both non-leaves, and a receiver that silently omitted them
/// would read a `⊥` cell as never written and an erased cell as non-existent.
#[derive(Clone, Debug)]
pub struct RealmStateSnapshotRestore {
    pub realm_state_snapshot_ref: RealmStateSnapshotId,
    pub report: RealmStateSnapshotVerifyReport,
    /// Non-`cas_register` cells, by cell ref.
    pub values: BTreeMap<CellRef, serde_json::Value>,
    /// `cas_register` cells, in the shape the joined view uses.
    pub cas_heads: CasHeadsByCell,
    /// Cells §3 reported in `⊥`. They have no leaf; the receiver MUST fail
    /// closed on them rather than treat them as unwritten.
    pub bottom_cells: BTreeSet<CellRef>,
    /// Cells whose canonical value a hard erasure removed, with the
    /// `ak.schema.erasure_verification_stub.v1` the receipt bound. Read as
    /// `[erased]`, never as «never existed».
    pub erasure_stubs: BTreeMap<CellRef, serde_json::Value>,
    pub soft_failed: Vec<SnapshotNonAcceptedInput>,
    pub quarantined: Vec<SnapshotNonAcceptedInput>,
    pub covered_events: CoveredEventSet,
}

impl RealmStateSnapshotRestore {
    /// The restored state of one cell, or `None` when the snapshot carried no
    /// leaf for it.
    ///
    /// `None` is not «never written»: check [`Self::bottom_cells`] and
    /// [`Self::erasure_stubs`] first — both are cells the snapshot deliberately
    /// gave no leaf.
    pub fn cell(&self, cell: &CellRef) -> Option<RestoredCell> {
        if let Some(heads) = self.cas_heads.get(cell) {
            return Some(RestoredCell::CasHeads(heads.clone()));
        }
        self.values.get(cell).cloned().map(RestoredCell::Value)
    }
}

/// Verify a delivered snapshot against `realm-state-snapshot-schema.md` §5 and
/// materialize it.
///
/// `chunk_bytes` are the raw payload bytes behind `manifest.chunks[i].chunk_ref`,
/// positionally aligned with that list.
///
/// `verify_issuer_jws` resolves `signature.verification_method` and checks the
/// detached JWS over the transcript bytes this function recomputes. It is a
/// parameter rather than a documented caller obligation because a snapshot
/// whose signature nobody checked is an unauthenticated state dump: making the
/// resolver mandatory is what keeps «I forgot» from being reachable.
pub fn restore_realm_state_snapshot<F>(
    manifest: &RealmStateSnapshotManifest,
    chunk_bytes: &[Vec<u8>],
    options: &RealmStateSnapshotVerifyOptions,
    verify_issuer_jws: F,
) -> ValidationResult<RealmStateSnapshotRestore>
where
    F: FnOnce(&DidUrl, &[u8], &str) -> Result<(), String>,
{
    let chunks = verify_manifest_and_chunks(manifest, chunk_bytes, options, verify_issuer_jws)?;
    let state_digest =
        state_digest_from_chunk_payloads(&chunks, &manifest.reducer_profile, digest_suite(manifest)?)
            .map_err(|error| schema_violation(error.to_string()))?;
    if state_digest != manifest.state_digest {
        return Err(digest_mismatch(format!(
            "chunks recompute state_digest {state_digest}; the manifest commits {}",
            manifest.state_digest
        )));
    }
    verify_auxiliary_list_digests(manifest, &chunks)?;

    let mut values: BTreeMap<CellRef, serde_json::Value> = BTreeMap::new();
    let mut cas_heads: CasHeadsByCell = BTreeMap::new();
    let mut bottom_cells = BTreeSet::new();
    let mut erasure_stubs = BTreeMap::new();
    let mut soft_failed = Vec::new();
    let mut quarantined = Vec::new();
    let mut item_count = 0usize;

    for chunk in &chunks {
        for item in &chunk.items {
            item_count += 1;
            match item.state() {
                SnapshotCellState::Value(value) => {
                    values.insert(item.cell().clone(), value.clone());
                }
                SnapshotCellState::Heads(heads) => {
                    cas_heads.insert(
                        item.cell().clone(),
                        heads
                            .iter()
                            .map(|head| CasHead {
                                move_id: head.event_id.event_digest(),
                                value: head.value.clone(),
                            })
                            .collect(),
                    );
                }
            }
        }
        for record in &chunk.conflict_records {
            if let super::types::RealmStateSnapshotConflictRecord::BottomCell { cell_ref } = record {
                bottom_cells.insert(cell_ref.clone());
            }
        }
        for SnapshotErasureStub { cell_ref, stub } in &chunk.erasure_stubs {
            erasure_stubs.insert(cell_ref.clone(), stub.clone());
        }
        soft_failed.extend(chunk.soft_failed.iter().cloned());
        quarantined.extend(chunk.quarantined.iter().cloned());
    }

    // §3: an erased cell has no leaf, so a leaf and a stub for the same cell is
    // a producer contradiction, not a precedence question.
    if let Some(cell) = erasure_stubs
        .keys()
        .find(|cell| values.contains_key(*cell) || cas_heads.contains_key(*cell))
    {
        return Err(schema_violation(format!(
            "{cell} carries both a state leaf and an erasure stub"
        )));
    }

    Ok(RealmStateSnapshotRestore {
        realm_state_snapshot_ref: manifest.id.clone(),
        report: RealmStateSnapshotVerifyReport {
            item_count,
            chunk_count: chunks.len(),
            state_digest,
        },
        values,
        cas_heads,
        bottom_cells,
        erasure_stubs,
        soft_failed,
        quarantined,
        covered_events: CoveredEventSet::from_manifest(manifest),
    })
}

fn digest_suite(
    manifest: &RealmStateSnapshotManifest,
) -> ValidationResult<arkret_canonical::DigestSuite> {
    // §4 ties the leaf suite to the Realm's live digest suite, which the
    // manifest carries only through the wire prefix of `state_digest`.
    let prefix = manifest
        .state_digest
        .as_str()
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .ok_or_else(|| schema_violation("state_digest carries no suite prefix"))?;
    match prefix {
        "sha256" => Ok(arkret_canonical::DigestSuite::Sha256),
        "blake3" => Ok(arkret_canonical::DigestSuite::Blake3),
        other => Err(schema_violation(format!(
            "state_digest suite {other:?} is not a registered Realm digest suite"
        ))),
    }
}

fn verify_manifest_and_chunks<F>(
    manifest: &RealmStateSnapshotManifest,
    chunk_bytes: &[Vec<u8>],
    options: &RealmStateSnapshotVerifyOptions,
    verify_issuer_jws: F,
) -> ValidationResult<Vec<RealmStateSnapshotChunkPayload>>
where
    F: FnOnce(&DidUrl, &[u8], &str) -> Result<(), String>,
{
    if manifest.reducer_profile != options.expected_reducer_profile {
        return Err(schema_violation(format!(
            "manifest reducer_profile {:?} is not the expected {:?}; §4 does not make two \
             profiles' state_digest comparable",
            manifest.reducer_profile, options.expected_reducer_profile
        )));
    }
    if let Some(hints) = &manifest.verification_hints
        && hints.verification_profile != manifest.security_class
    {
        return Err(schema_violation(format!(
            "verification_hints.verification_profile {:?} contradicts security_class {:?}",
            hints.verification_profile, manifest.security_class
        )));
    }
    if matches!(
        manifest.security_class,
        RealmStateSnapshotSecurityClass::HighAssurance
    ) && !options.allow_high_assurance
    {
        // §6.2: a high-assurance bootstrap MUST run the inclusion challenge or
        // fall back to raw replay before the snapshot counts as accepted state.
        // A caller that has done neither may not adopt it.
        return Err(authority_unverified(
            "high_assurance snapshot adopted without the §6.2 witness or raw-replay path",
        ));
    }
    verify_acceptance_window(manifest, options.now)?;
    verify_issuer_signature(manifest, verify_issuer_jws)?;

    if manifest.chunks.is_empty() {
        return Err(schema_violation("manifest commits no chunks"));
    }
    if chunk_bytes.len() != manifest.chunks.len() {
        return Err(schema_violation(format!(
            "{} chunk payloads delivered for {} manifest descriptors",
            chunk_bytes.len(),
            manifest.chunks.len()
        )));
    }
    let mut payloads = Vec::with_capacity(chunk_bytes.len());
    for (position, (descriptor, bytes)) in manifest.chunks.iter().zip(chunk_bytes).enumerate() {
        verify_realm_state_snapshot_chunk_bytes(descriptor, bytes)?;
        let payload: RealmStateSnapshotChunkPayload = serde_json::from_slice(bytes)
            .map_err(|error| schema_violation(format!("chunk {position} does not parse: {error}")))?;
        if payload.realm_state_snapshot_ref != manifest.id {
            return Err(schema_violation(format!(
                "chunk {position} names snapshot {}; the manifest is {}",
                payload.realm_state_snapshot_ref, manifest.id
            )));
        }
        payloads.push(payload);
    }
    Ok(payloads)
}

fn verify_acceptance_window(
    manifest: &RealmStateSnapshotManifest,
    now: DateTime<Utc>,
) -> ValidationResult<()> {
    let max_age_ms = realm_state_snapshot_max_acceptance_age_ms(&manifest.security_class);
    let age_ms = now
        .signed_duration_since(manifest.created_at)
        .num_milliseconds();
    if age_ms > max_age_ms {
        return Err(authority_unverified(format!(
            "manifest is {age_ms} ms old; {:?} accepts at most {max_age_ms} ms — request a fresh \
             manifest rather than adopting drifted auth state",
            manifest.security_class
        )));
    }
    Ok(())
}

fn verify_issuer_signature<F>(
    manifest: &RealmStateSnapshotManifest,
    verify_issuer_jws: F,
) -> ValidationResult<()>
where
    F: FnOnce(&DidUrl, &[u8], &str) -> Result<(), String>,
{
    let DetachedJwsProof {
        kind,
        verification_method,
        payload_digest,
        jws,
        ..
    } = &manifest.signature;
    if kind != super::constants::DETACHED_JWS_PROOF_KIND {
        return Err(signature_invalid(format!(
            "manifest signature kind {kind:?} is not {:?}",
            super::constants::DETACHED_JWS_PROOF_KIND
        )));
    }
    let transcript = manifest
        .unsigned_canonical_bytes()
        .map_err(|error| signature_invalid(format!("manifest has no transcript: {error}")))?;
    let expected = sha256_digest(&transcript);
    if payload_digest != &expected {
        return Err(signature_invalid(format!(
            "signature commits payload_digest {payload_digest}; the manifest transcript is \
             {expected}"
        )));
    }
    verify_issuer_jws(verification_method, &transcript, jws)
        .map_err(|error| signature_invalid(format!("manifest signature does not verify: {error}")))
}

fn verify_auxiliary_list_digests(
    manifest: &RealmStateSnapshotManifest,
    chunks: &[RealmStateSnapshotChunkPayload],
) -> ValidationResult<()> {
    let suite = arkret_canonical::DigestSuite::Sha256;
    let hints = manifest.verification_hints.as_ref();
    let has_erasure_stubs = chunks.iter().any(|chunk| !chunk.erasure_stubs.is_empty());
    if has_erasure_stubs && hints.and_then(|hints| hints.erasure_stubs_digest.as_ref()).is_none() {
        // §3: erased cells are not leaves, so this digest is their only
        // commitment and is mandatory once any chunk carries one.
        return Err(schema_violation(
            "chunks carry erasure stubs but the manifest commits no erasure_stubs_digest",
        ));
    }
    let Some(hints) = hints else {
        return Ok(());
    };
    let checks: [(&str, Option<&Hash>, crate::Result<Hash>); 4] = [
        (
            "conflict_records",
            hints.conflict_records_digest.as_ref(),
            super::chunking::realm_state_snapshot_conflict_records_digest(chunks, suite),
        ),
        (
            "soft_failed",
            hints.soft_failed_digest.as_ref(),
            super::chunking::realm_state_snapshot_soft_failed_digest(chunks, suite),
        ),
        (
            "quarantined",
            hints.quarantined_digest.as_ref(),
            super::chunking::realm_state_snapshot_quarantined_digest(chunks, suite),
        ),
        (
            "erasure_stubs",
            hints.erasure_stubs_digest.as_ref(),
            super::chunking::realm_state_snapshot_erasure_stubs_digest(chunks, suite),
        ),
    ];
    for (name, committed, recomputed) in checks {
        let Some(committed) = committed else {
            continue;
        };
        let recomputed = recomputed
            .map_err(|error| schema_violation(format!("{name} is not hashable: {error}")))?;
        if &recomputed != committed {
            return Err(digest_mismatch(format!(
                "{name} recomputes to {recomputed}; verification_hints commits {committed}"
            )));
        }
    }
    Ok(())
}

/// Check that a `realm_state_snapshot_bootstrap` hint and a manifest describe
/// the same snapshot.
///
/// The hint rides on an events query and carries no `chunks[]`, so a client
/// that acted on it has to fetch the manifest separately — two responses, and
/// nothing structural stops a server from answering the second with a
/// different snapshot than the first advertised. The fields checked here are
/// exactly the ones both objects carry, so a hint that named the state the
/// client decided to accelerate on cannot be swapped for another after the
/// decision.
pub fn realm_state_snapshot_bootstrap_binds_manifest(
    bootstrap: &RealmStateSnapshotBootstrap,
    manifest: &RealmStateSnapshotManifest,
) -> ValidationResult<()> {
    if bootstrap.realm_state_snapshot_ref != manifest.id {
        return Err(schema_violation(format!(
            "bootstrap hint names snapshot {}; the manifest is {}",
            bootstrap.realm_state_snapshot_ref, manifest.id
        )));
    }
    if bootstrap.state_digest != manifest.state_digest {
        return Err(digest_mismatch(format!(
            "bootstrap hint commits state_digest {}; the manifest commits {}",
            bootstrap.state_digest, manifest.state_digest
        )));
    }
    if bootstrap.realm_state_snapshot_frontier != manifest.frontier.event_ids {
        return Err(schema_violation(
            "bootstrap hint and manifest disagree on the snapshot frontier",
        ));
    }
    if bootstrap.created_by != manifest.created_by || bootstrap.created_at != manifest.created_at {
        return Err(schema_violation(
            "bootstrap hint and manifest disagree on the snapshot issuer or creation time",
        ));
    }
    if bootstrap.signature.payload_digest != manifest.signature.payload_digest {
        return Err(signature_invalid(
            "bootstrap hint and manifest carry different signature payload digests",
        ));
    }
    Ok(())
}

/// The `state_digest` of a snapshot that materialized no cell
/// (`realm-state-snapshot-schema.md` §4: `H` over empty bytes).
pub fn empty_realm_state_snapshot_state_digest() -> Hash {
    Hash::new(EMPTY_SHA256_DIGEST.to_owned()).expect("sha256 wire form")
}
