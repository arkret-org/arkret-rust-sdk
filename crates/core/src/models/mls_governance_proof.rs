//! Complete-materialization proof for full-profile MLS governance bindings.
//!
//! A selective Merkle proof only shows that disclosed leaves exist; it cannot
//! prove that a server omitted no policy or capability leaf. The v1 proof
//! therefore materializes the complete covered digest set and every non-bottom
//! control cell committed by the accepted Seal.

use std::collections::{BTreeMap, BTreeSet};

use arkret_state::{CellState, compute_state_root, control_event_set_root};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;
use crate::{CellId, CellRef, MoveId, NotarySig, Seal, base64url_decode};

pub const MLS_GOVERNANCE_PROOF_BUNDLE_VERSION: u8 = 1;
pub const MLS_GOVERNANCE_PROOF_MANIFEST_VERSION: u8 = 1;
pub const MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE: &str = "complete_control_state_v1";
pub const MLS_GOVERNANCE_MAX_CHUNKS: usize = 1024;
pub const MLS_GOVERNANCE_MAX_RESPONSE_BYTES: usize = 4_194_304;
pub const MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES: usize = 268_435_456;
pub const MLS_GOVERNANCE_MAX_SEAL_PATH_ITEMS: usize = 4096;
pub const MLS_GOVERNANCE_MAX_COVERED_EVENT_DIGESTS: usize = 1_048_576;
pub const MLS_GOVERNANCE_MAX_CONTROL_STATE_ITEMS: usize = 262_144;
pub const MLS_GOVERNANCE_MAX_FRONTIER_EVENTS: usize = 128;
pub const MLS_GOVERNANCE_SEALS_PER_CHUNK: usize = 128;
pub const MLS_GOVERNANCE_DIGESTS_PER_CHUNK: usize = 8192;
pub const MLS_GOVERNANCE_CONTROL_STATE_PER_CHUNK: usize = 1024;
pub const MLS_GOVERNANCE_FRONTIER_EVENTS_PER_CHUNK: usize = 32;

const MLS_GOVERNANCE_REQUEST_DOMAIN: &[u8] = b"arkret-mls-governance-proof-request-v1\n";
const MLS_GOVERNANCE_BUNDLE_DOMAIN: &[u8] = b"arkret-mls-governance-proof-bundle-v1\n";
const MLS_GOVERNANCE_CHUNK_DOMAIN: &[u8] = b"arkret-mls-governance-proof-chunk-v1\n";
// Leaves enough headroom for the repeated response header and JSON delimiters.
const MLS_GOVERNANCE_MAX_CHUNK_ITEM_BYTES: usize = 3_500_000;

const POLICY_COMPONENTS_CELL: &str = "ak.component.realm.policy_components.v1";
const PLAINTEXT_VISIBLE_SERVICES_CELL: &str = "ak.component.realm.plaintext_visible_services.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofRequest {
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub mls_group_id: String,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub binding_profile: String,
    pub reducer_profile: String,
    pub trusted_anchor_seal_id: SealId,
    pub chunk_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_bundle_digest: Option<Hash>,
}

impl MlsGovernanceProofRequest {
    pub fn validate(&self) -> Result<()> {
        if self.effective_scope.realm_id() != &self.realm_id {
            return schema("proof request Realm and effective_scope mismatch");
        }
        let is_genesis = self.previous_epoch == 0 && self.next_epoch == 0;
        let is_commit = self.previous_epoch.checked_add(1) == Some(self.next_epoch);
        if !is_genesis && !is_commit {
            return schema(
                "proof request epochs must be 0 -> 0 for genesis or next_epoch = previous_epoch + 1 for a commit",
            );
        }
        if self.binding_profile != MLS_GOVERNANCE_BINDING_FULL_PROFILE {
            return schema("proof request requires the full governance binding profile");
        }
        if self.reducer_profile.trim().is_empty() {
            return schema("proof request reducer_profile must not be empty");
        }
        if base64url_decode(&self.mls_group_id).is_err() {
            return schema("proof request mls_group_id must be base64url");
        }
        if self.mls_group_id.len() > 512 {
            return schema("proof request mls_group_id exceeds 512 bytes");
        }
        if self.chunk_index as usize >= MLS_GOVERNANCE_MAX_CHUNKS {
            return bounds("proof request chunk_index exceeds 1023");
        }
        if self.chunk_index == 0 && self.expected_bundle_digest.is_some() {
            return schema("expected_bundle_digest is forbidden for chunk_index 0");
        }
        if self.chunk_index > 0 && self.expected_bundle_digest.is_none() {
            return schema("expected_bundle_digest is required after chunk_index 0");
        }
        if self
            .expected_bundle_digest
            .as_ref()
            .is_some_and(|digest| !is_sha256_digest(digest))
        {
            return schema("expected_bundle_digest must use sha256");
        }
        Ok(())
    }

    pub fn proof_request_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Identity<'a> {
            realm_id: &'a RealmId,
            effective_scope: &'a EffectiveScope,
            mls_group_id: &'a str,
            previous_epoch: u64,
            next_epoch: u64,
            binding_profile: &'a str,
            reducer_profile: &'a str,
            trusted_anchor_seal_id: &'a SealId,
        }
        domain_hash(
            MLS_GOVERNANCE_REQUEST_DOMAIN,
            &Identity {
                realm_id: &self.realm_id,
                effective_scope: &self.effective_scope,
                mls_group_id: &self.mls_group_id,
                previous_epoch: self.previous_epoch,
                next_epoch: self.next_epoch,
                binding_profile: &self.binding_profile,
                reducer_profile: &self.reducer_profile,
                trusted_anchor_seal_id: &self.trusted_anchor_seal_id,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofCollectionTotals {
    pub seal_path: u32,
    pub covered_event_digests: u32,
    pub control_state: u32,
    pub frontier_events: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofChunkItemLimits {
    pub seal_path: u32,
    pub covered_event_digests: u32,
    pub control_state: u32,
    pub frontier_events: u32,
}

impl Default for MlsGovernanceProofChunkItemLimits {
    fn default() -> Self {
        Self {
            seal_path: MLS_GOVERNANCE_SEALS_PER_CHUNK as u32,
            covered_event_digests: MLS_GOVERNANCE_DIGESTS_PER_CHUNK as u32,
            control_state: MLS_GOVERNANCE_CONTROL_STATE_PER_CHUNK as u32,
            frontier_events: MLS_GOVERNANCE_FRONTIER_EVENTS_PER_CHUNK as u32,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofChunkManifest {
    pub manifest_version: u8,
    pub chunk_count: u32,
    pub chunks_root: Hash,
    pub total_item_bytes: u64,
    pub collection_totals: MlsGovernanceProofCollectionTotals,
    pub max_response_bytes: u32,
    pub max_total_item_bytes: u32,
    pub max_items_per_chunk: MlsGovernanceProofChunkItemLimits,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "collection", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsGovernanceProofChunk {
    SealPath {
        chunk_index: u32,
        start_index: u32,
        items: Vec<Seal>,
        chunk_digest: Hash,
        chunk_proof: Vec<Hash>,
    },
    CoveredEventDigests {
        chunk_index: u32,
        start_index: u32,
        items: Vec<Hash>,
        chunk_digest: Hash,
        chunk_proof: Vec<Hash>,
    },
    ControlState {
        chunk_index: u32,
        start_index: u32,
        items: Vec<MlsGovernanceControlStateLeaf>,
        chunk_digest: Hash,
        chunk_proof: Vec<Hash>,
    },
    FrontierEvents {
        chunk_index: u32,
        start_index: u32,
        items: Vec<Event>,
        chunk_digest: Hash,
        chunk_proof: Vec<Hash>,
    },
}

impl MlsGovernanceProofChunk {
    pub fn chunk_index(&self) -> u32 {
        match self {
            Self::SealPath { chunk_index, .. }
            | Self::CoveredEventDigests { chunk_index, .. }
            | Self::ControlState { chunk_index, .. }
            | Self::FrontierEvents { chunk_index, .. } => *chunk_index,
        }
    }

    pub fn start_index(&self) -> u32 {
        match self {
            Self::SealPath { start_index, .. }
            | Self::CoveredEventDigests { start_index, .. }
            | Self::ControlState { start_index, .. }
            | Self::FrontierEvents { start_index, .. } => *start_index,
        }
    }

    pub fn chunk_digest(&self) -> &Hash {
        match self {
            Self::SealPath { chunk_digest, .. }
            | Self::CoveredEventDigests { chunk_digest, .. }
            | Self::ControlState { chunk_digest, .. }
            | Self::FrontierEvents { chunk_digest, .. } => chunk_digest,
        }
    }

    pub fn chunk_proof(&self) -> &[Hash] {
        match self {
            Self::SealPath { chunk_proof, .. }
            | Self::CoveredEventDigests { chunk_proof, .. }
            | Self::ControlState { chunk_proof, .. }
            | Self::FrontierEvents { chunk_proof, .. } => chunk_proof,
        }
    }

    pub fn recompute_digest(&self) -> Result<Hash> {
        match self {
            Self::SealPath {
                chunk_index,
                start_index,
                items,
                ..
            } => chunk_hash(*chunk_index, "seal_path", *start_index, items),
            Self::CoveredEventDigests {
                chunk_index,
                start_index,
                items,
                ..
            } => chunk_hash(*chunk_index, "covered_event_digests", *start_index, items),
            Self::ControlState {
                chunk_index,
                start_index,
                items,
                ..
            } => chunk_hash(*chunk_index, "control_state", *start_index, items),
            Self::FrontierEvents {
                chunk_index,
                start_index,
                items,
                ..
            } => chunk_hash(*chunk_index, "frontier_events", *start_index, items),
        }
    }

    fn set_commitment(&mut self, digest: Hash, proof: Vec<Hash>) {
        match self {
            Self::SealPath {
                chunk_digest,
                chunk_proof,
                ..
            }
            | Self::CoveredEventDigests {
                chunk_digest,
                chunk_proof,
                ..
            }
            | Self::ControlState {
                chunk_digest,
                chunk_proof,
                ..
            }
            | Self::FrontierEvents {
                chunk_digest,
                chunk_proof,
                ..
            } => {
                *chunk_digest = digest;
                *chunk_proof = proof;
            }
        }
    }

    fn set_chunk_index(&mut self, index: u32) {
        match self {
            Self::SealPath { chunk_index, .. }
            | Self::CoveredEventDigests { chunk_index, .. }
            | Self::ControlState { chunk_index, .. }
            | Self::FrontierEvents { chunk_index, .. } => *chunk_index = index,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofBundle {
    pub bundle_version: u8,
    pub proof_request_digest: Hash,
    pub bundle_digest: Hash,
    pub materialization_profile: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub reducer_profile: String,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub trusted_anchor_seal_id: SealId,
    pub accepted_seal_id: SealId,
    pub chunk_manifest: MlsGovernanceProofChunkManifest,
    pub chunk: MlsGovernanceProofChunk,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaterializedMlsGovernanceProofBundle {
    pub bundle_version: u8,
    pub proof_request_digest: Hash,
    pub bundle_digest: Hash,
    pub materialization_profile: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub reducer_profile: String,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub trusted_anchor_seal_id: SealId,
    pub accepted_seal_id: SealId,
    pub seal_path: Vec<Seal>,
    pub covered_event_digests: Vec<Hash>,
    pub control_state: Vec<MlsGovernanceControlStateLeaf>,
    pub frontier_events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceControlStateLeaf {
    pub cell: CellRef,
    pub state: MlsGovernanceControlStateValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceControlStateValue {
    pub value: Value,
}

impl MlsGovernanceProofBundle {
    pub fn recompute_bundle_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct DigestView<'a> {
            bundle_version: u8,
            proof_request_digest: &'a Hash,
            materialization_profile: &'a str,
            realm_id: &'a RealmId,
            effective_scope: &'a EffectiveScope,
            reducer_profile: &'a str,
            governance_binding: &'a MlsGovernanceBindingPayload,
            trusted_anchor_seal_id: &'a SealId,
            accepted_seal_id: &'a SealId,
            chunk_manifest: &'a MlsGovernanceProofChunkManifest,
        }
        domain_hash(
            MLS_GOVERNANCE_BUNDLE_DOMAIN,
            &DigestView {
                bundle_version: self.bundle_version,
                proof_request_digest: &self.proof_request_digest,
                materialization_profile: &self.materialization_profile,
                realm_id: &self.realm_id,
                effective_scope: &self.effective_scope,
                reducer_profile: &self.reducer_profile,
                governance_binding: &self.governance_binding,
                trusted_anchor_seal_id: &self.trusted_anchor_seal_id,
                accepted_seal_id: &self.accepted_seal_id,
                chunk_manifest: &self.chunk_manifest,
            },
        )
    }
}

/// Materialize and commit every bounded response chunk for a logical proof.
/// Servers may select the requested entry after this function has committed
/// the complete sequence.
pub fn build_mls_governance_proof_chunks(
    request: &MlsGovernanceProofRequest,
    materialized: &MaterializedMlsGovernanceProofBundle,
) -> Result<Vec<MlsGovernanceProofBundle>> {
    request.validate()?;
    validate_materialized_identity(request, materialized)?;
    validate_collection_totals(materialized)?;

    let zero = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut chunks = Vec::new();
    for (start_index, items) in
        split_items(&materialized.seal_path, MLS_GOVERNANCE_SEALS_PER_CHUNK)?
    {
        chunks.push(MlsGovernanceProofChunk::SealPath {
            chunk_index: 0,
            start_index: start_index as u32,
            items,
            chunk_digest: zero.clone(),
            chunk_proof: Vec::new(),
        });
    }
    for (start_index, items) in split_items(
        &materialized.covered_event_digests,
        MLS_GOVERNANCE_DIGESTS_PER_CHUNK,
    )? {
        chunks.push(MlsGovernanceProofChunk::CoveredEventDigests {
            chunk_index: 0,
            start_index: start_index as u32,
            items,
            chunk_digest: zero.clone(),
            chunk_proof: Vec::new(),
        });
    }
    for (start_index, items) in split_items(
        &materialized.control_state,
        MLS_GOVERNANCE_CONTROL_STATE_PER_CHUNK,
    )? {
        chunks.push(MlsGovernanceProofChunk::ControlState {
            chunk_index: 0,
            start_index: start_index as u32,
            items,
            chunk_digest: zero.clone(),
            chunk_proof: Vec::new(),
        });
    }
    for (start_index, items) in split_items(
        &materialized.frontier_events,
        MLS_GOVERNANCE_FRONTIER_EVENTS_PER_CHUNK,
    )? {
        chunks.push(MlsGovernanceProofChunk::FrontierEvents {
            chunk_index: 0,
            start_index: start_index as u32,
            items,
            chunk_digest: zero.clone(),
            chunk_proof: Vec::new(),
        });
    }
    if !(2..=MLS_GOVERNANCE_MAX_CHUNKS).contains(&chunks.len()) {
        return bounds("MLS governance proof chunk_count must be between 2 and 1024");
    }
    for (index, chunk) in chunks.iter_mut().enumerate() {
        chunk.set_chunk_index(index as u32);
    }
    let chunk_digests = chunks
        .iter()
        .map(MlsGovernanceProofChunk::recompute_digest)
        .collect::<Result<Vec<_>>>()?;
    let chunks_root = merkle_root_hash(&chunk_digests)?;
    for (index, chunk) in chunks.iter_mut().enumerate() {
        let proof = merkle_proof(&chunk_digests, index)?;
        chunk.set_commitment(chunk_digests[index].clone(), proof);
    }

    let total_item_bytes = materialized_total_item_bytes(materialized)?;
    if total_item_bytes == 0 || total_item_bytes > MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES as u64 {
        return bounds("MLS governance proof total_item_bytes is outside the allowed range");
    }
    let manifest = MlsGovernanceProofChunkManifest {
        manifest_version: MLS_GOVERNANCE_PROOF_MANIFEST_VERSION,
        chunk_count: chunks.len() as u32,
        chunks_root,
        total_item_bytes,
        collection_totals: MlsGovernanceProofCollectionTotals {
            seal_path: materialized.seal_path.len() as u32,
            covered_event_digests: materialized.covered_event_digests.len() as u32,
            control_state: materialized.control_state.len() as u32,
            frontier_events: materialized.frontier_events.len() as u32,
        },
        max_response_bytes: MLS_GOVERNANCE_MAX_RESPONSE_BYTES as u32,
        max_total_item_bytes: MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES as u32,
        max_items_per_chunk: MlsGovernanceProofChunkItemLimits::default(),
    };
    let request_digest = request.proof_request_digest()?;
    let mut responses = chunks
        .into_iter()
        .map(|chunk| MlsGovernanceProofBundle {
            bundle_version: MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
            proof_request_digest: request_digest.clone(),
            bundle_digest: zero.clone(),
            materialization_profile: materialized.materialization_profile.clone(),
            realm_id: materialized.realm_id.clone(),
            effective_scope: materialized.effective_scope.clone(),
            reducer_profile: materialized.reducer_profile.clone(),
            governance_binding: materialized.governance_binding.clone(),
            trusted_anchor_seal_id: materialized.trusted_anchor_seal_id.clone(),
            accepted_seal_id: materialized.accepted_seal_id.clone(),
            chunk_manifest: manifest.clone(),
            chunk,
        })
        .collect::<Vec<_>>();
    let bundle_digest = responses[0].recompute_bundle_digest()?;
    if request
        .expected_bundle_digest
        .as_ref()
        .is_some_and(|expected| expected != &bundle_digest)
    {
        return state_mismatch("expected_bundle_digest does not match the materialized bundle");
    }
    for response in &mut responses {
        response.bundle_digest = bundle_digest.clone();
        let encoded = canonical::canonical_json_bytes(response)?;
        if encoded.len() > MLS_GOVERNANCE_MAX_RESPONSE_BYTES {
            return bounds("MLS governance proof response exceeds max_response_bytes");
        }
    }
    Ok(responses)
}

/// Authenticate and assemble a complete chunk sequence. No materialized proof
/// is returned until every index and every collection range is present.
pub fn assemble_mls_governance_proof_chunks(
    request: &MlsGovernanceProofRequest,
    responses: &[MlsGovernanceProofBundle],
) -> Result<MaterializedMlsGovernanceProofBundle> {
    if responses.is_empty() {
        return incomplete("MLS governance proof has no chunks");
    }
    let request_digest = request.proof_request_digest()?;
    let first = &responses[0];
    validate_manifest(&first.chunk_manifest)?;
    if first.proof_request_digest != request_digest {
        return state_mismatch("proof_request_digest does not match the acquisition request");
    }
    if first.trusted_anchor_seal_id != request.trusted_anchor_seal_id {
        return state_mismatch("proof response substituted the trusted anchor");
    }
    let chunk_count = first.chunk_manifest.chunk_count as usize;
    if responses.len() != chunk_count {
        return incomplete("MLS governance proof chunk sequence is incomplete");
    }
    let mut ordered = vec![None; chunk_count];
    for (position, response) in responses.iter().enumerate() {
        if !same_bundle_header(first, response) {
            return state_mismatch("MLS governance proof chunks mix different bundles");
        }
        if response.recompute_bundle_digest()? != response.bundle_digest {
            return state_mismatch("MLS governance proof bundle_digest mismatch");
        }
        if response.chunk.recompute_digest()? != *response.chunk.chunk_digest() {
            return state_mismatch("MLS governance proof chunk_digest mismatch");
        }
        let index = response.chunk.chunk_index() as usize;
        if index >= chunk_count {
            return bounds("MLS governance proof chunk_index is outside the manifest");
        }
        if index != position {
            return schema("MLS governance proof chunks are not in chunk_index order");
        }
        if ordered[index].replace(response).is_some() {
            return schema("MLS governance proof contains a duplicate chunk_index");
        }
    }
    let ordered = ordered
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            Error::Protocol(
                "MLS governance proof is incomplete (mls_governance_proof_incomplete)".to_owned(),
            )
        })?;
    let digests = ordered
        .iter()
        .map(|response| response.chunk.chunk_digest().clone())
        .collect::<Vec<_>>();
    if merkle_root_hash(&digests)? != first.chunk_manifest.chunks_root {
        return state_mismatch("MLS governance proof chunks_root mismatch");
    }
    for (index, response) in ordered.iter().enumerate() {
        if merkle_proof(&digests, index)? != response.chunk.chunk_proof() {
            return state_mismatch("MLS governance proof chunk_proof mismatch");
        }
    }

    let mut seal_path = Vec::new();
    let mut covered_event_digests = Vec::new();
    let mut control_state = Vec::new();
    let mut frontier_events = Vec::new();
    let mut last_collection = 0usize;
    let mut total_item_bytes = 0u64;
    for response in ordered {
        match &response.chunk {
            MlsGovernanceProofChunk::SealPath {
                start_index, items, ..
            } => {
                validate_chunk_range(
                    0,
                    &mut last_collection,
                    *start_index,
                    seal_path.len(),
                    items,
                    MLS_GOVERNANCE_SEALS_PER_CHUNK,
                )?;
                total_item_bytes += item_bytes(items)?;
                seal_path.extend(items.iter().cloned());
            }
            MlsGovernanceProofChunk::CoveredEventDigests {
                start_index, items, ..
            } => {
                validate_chunk_range(
                    1,
                    &mut last_collection,
                    *start_index,
                    covered_event_digests.len(),
                    items,
                    MLS_GOVERNANCE_DIGESTS_PER_CHUNK,
                )?;
                total_item_bytes += item_bytes(items)?;
                covered_event_digests.extend(items.iter().cloned());
            }
            MlsGovernanceProofChunk::ControlState {
                start_index, items, ..
            } => {
                validate_chunk_range(
                    2,
                    &mut last_collection,
                    *start_index,
                    control_state.len(),
                    items,
                    MLS_GOVERNANCE_CONTROL_STATE_PER_CHUNK,
                )?;
                total_item_bytes += item_bytes(items)?;
                control_state.extend(items.iter().cloned());
            }
            MlsGovernanceProofChunk::FrontierEvents {
                start_index, items, ..
            } => {
                validate_chunk_range(
                    3,
                    &mut last_collection,
                    *start_index,
                    frontier_events.len(),
                    items,
                    MLS_GOVERNANCE_FRONTIER_EVENTS_PER_CHUNK,
                )?;
                total_item_bytes += item_bytes(items)?;
                frontier_events.extend(items.iter().cloned());
            }
        }
        if total_item_bytes > MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES as u64 {
            return bounds("MLS governance proof item bytes exceed the hard limit");
        }
    }
    let totals = &first.chunk_manifest.collection_totals;
    if seal_path.len() != totals.seal_path as usize
        || covered_event_digests.len() != totals.covered_event_digests as usize
        || control_state.len() != totals.control_state as usize
        || frontier_events.len() != totals.frontier_events as usize
        || total_item_bytes != first.chunk_manifest.total_item_bytes
    {
        return incomplete("MLS governance proof collection totals do not match the manifest");
    }
    Ok(MaterializedMlsGovernanceProofBundle {
        bundle_version: first.bundle_version,
        proof_request_digest: first.proof_request_digest.clone(),
        bundle_digest: first.bundle_digest.clone(),
        materialization_profile: first.materialization_profile.clone(),
        realm_id: first.realm_id.clone(),
        effective_scope: first.effective_scope.clone(),
        reducer_profile: first.reducer_profile.clone(),
        governance_binding: first.governance_binding.clone(),
        trusted_anchor_seal_id: first.trusted_anchor_seal_id.clone(),
        accepted_seal_id: first.accepted_seal_id.clone(),
        seal_path,
        covered_event_digests,
        control_state,
        frontier_events,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsGovernanceProof {
    pub accepted_seal_id: SealId,
    pub membership_frontier: Vec<EventId>,
    pub policy_root: Hash,
    pub capability_root: Hash,
    pub discussion_metadata_digest: Hash,
}

/// Verify a complete-materialization proof bundle.
///
/// The callbacks own cryptographic signature verification and authorization
/// resolution. This function always validates the signed object digests,
/// topology, complete Merkle materializations, scope, and governance roots
/// before invoking a successful result.
pub fn verify_mls_governance_proof_bundle<VerifySeal, VerifyEvent>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    expected_binding: &MlsGovernanceBindingPayload,
    trusted_anchor: &SealId,
    verify_seal_signature: VerifySeal,
    verify_event_signature: VerifyEvent,
) -> Result<VerifiedMlsGovernanceProof>
where
    VerifySeal: Fn(&Seal) -> Result<()>,
    VerifyEvent: Fn(&Event) -> Result<()>,
{
    verify_bundle_header(bundle, expected_binding, trusted_anchor)?;
    let accepted_seal = verify_seal_path(bundle, verify_seal_signature)?;
    let covered = verify_covered_event_materialization(bundle, accepted_seal)?;
    let control_state = verify_control_state_materialization(bundle, accepted_seal)?;
    verify_frontier_events(bundle, expected_binding, &covered, verify_event_signature)?;

    let policy_root = derive_mls_policy_root(&control_state)?;
    if &policy_root != expected_binding.policy_root() {
        return stale("policy_root does not match the complete control state");
    }
    let capability_root = derive_mls_capability_root(&control_state)?;
    if expected_binding.capability_root() != Some(&capability_root) {
        return stale("capability_root does not match the complete control state");
    }
    let discussion_metadata_digest = derive_mls_discussion_metadata_digest(&bundle.control_state)?;
    if expected_binding.discussion_metadata_digest() != Some(&discussion_metadata_digest) {
        return stale("discussion_metadata_digest does not match the complete control state");
    }

    Ok(VerifiedMlsGovernanceProof {
        accepted_seal_id: bundle.accepted_seal_id.clone(),
        membership_frontier: expected_binding.membership_frontier().to_vec(),
        policy_root,
        capability_root,
        discussion_metadata_digest,
    })
}

fn verify_bundle_header(
    bundle: &MaterializedMlsGovernanceProofBundle,
    expected: &MlsGovernanceBindingPayload,
    trusted_anchor: &SealId,
) -> Result<()> {
    if bundle.bundle_version != MLS_GOVERNANCE_PROOF_BUNDLE_VERSION {
        return schema("unsupported MLS governance proof bundle_version");
    }
    if bundle.materialization_profile != MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE {
        return schema("unsupported MLS governance proof materialization_profile");
    }
    if &bundle.trusted_anchor_seal_id != trusted_anchor {
        return state_mismatch("bundle trust anchor does not match the locally trusted anchor");
    }
    if &bundle.governance_binding != expected {
        return state_mismatch("bundle governance_binding differs from the MLS transcript binding");
    }
    if &bundle.realm_id != expected.realm_id()
        || &bundle.effective_scope != expected.effective_scope()
        || bundle.reducer_profile != expected.reducer_profile()
    {
        return state_mismatch("bundle Realm, scope, or reducer profile mismatch");
    }
    Ok(())
}

fn verify_seal_path<VerifySeal>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    verify_seal_signature: VerifySeal,
) -> Result<&Seal>
where
    VerifySeal: Fn(&Seal) -> Result<()>,
{
    if bundle.seal_path.is_empty() {
        return schema("seal_path must not be empty");
    }
    if bundle.seal_path.last().map(|seal| &seal.id) != Some(&bundle.accepted_seal_id) {
        return state_mismatch("accepted_seal_id must identify the final seal_path entry");
    }

    let mut prior = BTreeSet::new();
    let mut path = BTreeMap::new();
    for seal in &bundle.seal_path {
        if seal.realm_id != bundle.realm_id {
            return state_mismatch("seal_path contains a cross-Realm Seal");
        }
        seal.validate_id()?;
        seal.validate_structural()?;
        verify_seal_payload_digest(seal)?;
        verify_seal_signature(seal)?;
        if path.insert(seal.id.clone(), seal).is_some() {
            return schema("seal_path contains duplicate Seal ids");
        }
        if seal.id != bundle.trusted_anchor_seal_id {
            if seal.predecessor_refs.is_empty() {
                return state_mismatch("untrusted seal_path entry has no predecessor");
            }
            for predecessor in &seal.predecessor_refs {
                if predecessor != &bundle.trusted_anchor_seal_id && !prior.contains(predecessor) {
                    return state_mismatch(
                        "seal_path is not topologically complete from the trusted anchor",
                    );
                }
            }
        }
        prior.insert(seal.id.clone());
    }

    let mut reachable = BTreeSet::new();
    let mut pending = vec![bundle.accepted_seal_id.clone()];
    while let Some(id) = pending.pop() {
        if !reachable.insert(id.clone()) || id == bundle.trusted_anchor_seal_id {
            continue;
        }
        if let Some(seal) = path.get(&id) {
            pending.extend(seal.predecessor_refs.iter().cloned());
        }
    }
    if path.keys().filter(|id| reachable.contains(*id)).count() != path.len() {
        return schema("seal_path contains entries outside the accepted Seal ancestry");
    }

    bundle
        .seal_path
        .last()
        .ok_or_else(|| Error::Protocol("seal_path unexpectedly empty".to_owned()))
}

fn verify_seal_payload_digest(seal: &Seal) -> Result<()> {
    let expected = Hash::new(canonical::sha256_digest(seal.canonical_bytes_for_id()?))?;
    match &seal.notary_signature {
        NotarySig::Single(signature) => {
            if signature.payload_digest != expected {
                return state_mismatch("Seal signature payload_digest mismatch");
            }
        }
        NotarySig::Multi(multi) => {
            if multi
                .signatures
                .iter()
                .any(|signature| signature.payload_digest != expected)
            {
                return state_mismatch("Seal multi-signature payload_digest mismatch");
            }
        }
        NotarySig::Threshold(_) => {}
    }
    Ok(())
}

fn verify_covered_event_materialization(
    bundle: &MaterializedMlsGovernanceProofBundle,
    accepted_seal: &Seal,
) -> Result<BTreeSet<MoveId>> {
    ensure_canonical_order(
        "covered_event_digests",
        bundle
            .covered_event_digests
            .iter()
            .map(|digest| digest.as_str()),
    )?;
    let covered = bundle
        .covered_event_digests
        .iter()
        .map(|digest| MoveId::new(digest.as_str().to_owned()).map_err(Error::from))
        .collect::<Result<BTreeSet<_>>>()?;
    let recomputed = control_event_set_root(&covered)
        .map_err(|error| Error::Protocol(format!("control_event_set_root: {error}")))?;
    if recomputed != accepted_seal.control_event_set_root {
        return state_mismatch("covered_event_digests do not reconstruct control_event_set_root");
    }
    if !accepted_seal.covered_event_digests.is_empty()
        && accepted_seal
            .covered_event_digests
            .iter()
            .ne(covered.iter())
    {
        return state_mismatch(
            "bundle covered_event_digests differ from the compaction Seal manifest",
        );
    }
    Ok(covered)
}

fn verify_control_state_materialization(
    bundle: &MaterializedMlsGovernanceProofBundle,
    accepted_seal: &Seal,
) -> Result<BTreeMap<CellRef, CellState>> {
    ensure_canonical_order(
        "control_state",
        bundle.control_state.iter().map(|leaf| leaf.cell.as_str()),
    )?;
    let control_state = bundle
        .control_state
        .iter()
        .map(|leaf| {
            (
                leaf.cell.clone(),
                CellState::Value(leaf.state.value.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if control_state.len() != bundle.control_state.len() {
        return schema("control_state contains duplicate cell ids");
    }
    let recomputed = compute_state_root(&control_state)?;
    if recomputed != accepted_seal.state_root {
        return state_mismatch("control_state does not reconstruct the accepted Seal state_root");
    }
    Ok(control_state)
}

fn verify_frontier_events<VerifyEvent>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    expected: &MlsGovernanceBindingPayload,
    covered: &BTreeSet<MoveId>,
    verify_event_signature: VerifyEvent,
) -> Result<()>
where
    VerifyEvent: Fn(&Event) -> Result<()>,
{
    ensure_canonical_order(
        "membership_frontier",
        expected.membership_frontier().iter().map(EventId::as_str),
    )?;
    ensure_canonical_order(
        "frontier_events",
        bundle
            .frontier_events
            .iter()
            .map(|event| event.event_id.as_str()),
    )?;
    let expected_ids = expected
        .membership_frontier()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual_ids = bundle
        .frontier_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<BTreeSet<_>>();
    if expected_ids != actual_ids || actual_ids.len() != bundle.frontier_events.len() {
        return state_mismatch(
            "frontier_events do not exactly match governance_binding.membership_frontier",
        );
    }

    for event in &bundle.frontier_events {
        if event.realm_id != bundle.realm_id
            || event.effective_scope.as_ref() != Some(&bundle.effective_scope)
        {
            return state_mismatch("frontier Event Realm or effective_scope mismatch");
        }
        if event.seal_ref.is_some() || event.effects.is_empty() {
            return schema("frontier Event is not a Control Move");
        }
        if !event.effects.iter().any(|effect| {
            CellId::from_ref(&effect.cell)
                .map(|cell| is_mls_membership_frontier_component(cell.component()))
                .unwrap_or(false)
        }) {
            return schema("frontier Event does not affect a membership/device/lifecycle cell");
        }
        event.validate_proof_bindings()?;
        verify_event_signature(event)?;
        let digest = MoveId::new(event.event_digest()?).map_err(Error::from)?;
        if !covered.contains(&digest) {
            return state_mismatch("frontier Event digest is absent from the accepted covered set");
        }
    }
    Ok(())
}

pub fn is_mls_membership_frontier_component(component: &str) -> bool {
    matches!(
        component,
        "ak.component.member.state.v1"
            | "ak.component.realm.create.v1"
            | "ak.component.circle.member.v1"
            | "ak.component.account.status.v1"
            | "ak.component.device.authorization.v1"
            | "ak.component.device.list_update.v1"
            | "ak.component.realm.tombstone.v1"
            | "ak.component.realm.destroy.v1"
    )
}

pub fn derive_mls_policy_root(control_state: &BTreeMap<CellRef, CellState>) -> Result<Hash> {
    filtered_control_state_root(control_state, |cell| {
        let component = cell.component();
        (component.starts_with("ak.component.realm.")
            && (component.contains("policy")
                || matches!(
                    component,
                    "ak.component.realm.join_rule.v1"
                        | "ak.component.realm.history_visibility.v1"
                        | "ak.component.realm.media_service.v1"
                        | "ak.component.realm.policy_components.v1"
                        | "ak.component.realm.plaintext_visible_services.v1"
                )))
            || (component.starts_with("ak.component.circle.")
                && ["policy", "history", "encryption", "lifecycle"]
                    .iter()
                    .any(|marker| component.contains(marker)))
    })
}

pub fn derive_mls_capability_root(control_state: &BTreeMap<CellRef, CellState>) -> Result<Hash> {
    filtered_control_state_root(control_state, |cell| {
        cell.component().starts_with("ak.component.capability.")
    })
}

fn filtered_control_state_root(
    control_state: &BTreeMap<CellRef, CellState>,
    include: impl Fn(&CellId) -> bool,
) -> Result<Hash> {
    let mut filtered = BTreeMap::new();
    for (cell_ref, state) in control_state {
        let cell = CellId::from_ref(cell_ref)?;
        if include(&cell) {
            filtered.insert(cell_ref.clone(), state.clone());
        }
    }
    Ok(compute_state_root(&filtered)?)
}

pub fn derive_mls_discussion_metadata_digest(
    control_state: &[MlsGovernanceControlStateLeaf],
) -> Result<Hash> {
    let mut media_service_decrypts = false;
    let mut plaintext_visible_services = Vec::new();
    for leaf in control_state {
        let cell = CellId::from_ref(&leaf.cell)?;
        match cell.component() {
            POLICY_COMPONENTS_CELL => {
                media_service_decrypts = leaf
                    .state
                    .value
                    .get("media_service_decrypts")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            }
            PLAINTEXT_VISIBLE_SERVICES_CELL => {
                if let Some(services) = leaf.state.value.get("services").and_then(Value::as_array) {
                    for service in services {
                        let exposes_media = service
                            .get("data_classes")
                            .and_then(Value::as_array)
                            .is_some_and(|classes| {
                                classes.iter().any(|class| class == "media_plaintext")
                            });
                        if !exposes_media {
                            continue;
                        }
                        let service_id = service
                            .get("service_id")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                Error::Protocol(
                                    "media_plaintext service is missing service_id".to_owned(),
                                )
                            })?;
                        plaintext_visible_services.push(MediaPlaintextService {
                            service_id: Did::new(service_id.to_owned())?,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    derive_media_decrypt_metadata_digest(&MediaDecryptPolicyValue {
        media_service_decrypts,
        plaintext_visible_services,
    })
}

fn ensure_canonical_order<'a>(
    field: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return schema(&format!(
            "{field} must be canonical sorted and duplicate-free"
        ));
    }
    Ok(())
}

fn domain_hash(domain: &[u8], value: &impl Serialize) -> Result<Hash> {
    let canonical = canonical::canonical_json_bytes(value)?;
    Hash::new(canonical::sha256_digest_from_slices(&[domain, &canonical])).map_err(Into::into)
}

fn chunk_hash<T: Serialize>(
    chunk_index: u32,
    collection: &str,
    start_index: u32,
    items: &[T],
) -> Result<Hash> {
    #[derive(Serialize)]
    struct ChunkView<'a, T> {
        chunk_index: u32,
        collection: &'a str,
        start_index: u32,
        items: &'a [T],
    }
    domain_hash(
        MLS_GOVERNANCE_CHUNK_DOMAIN,
        &ChunkView {
            chunk_index,
            collection,
            start_index,
            items,
        },
    )
}

fn is_sha256_digest(digest: &Hash) -> bool {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn digest_raw(digest: &Hash) -> Result<[u8; 32]> {
    if !is_sha256_digest(digest) {
        return schema("MLS governance proof commitment must use sha256");
    }
    let bytes = hex::decode(&digest.as_str()[7..])
        .map_err(|error| Error::Protocol(format!("invalid sha256 digest: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Protocol("sha256 digest must contain 32 bytes".to_owned()))
}

fn merkle_leaf(digest: &Hash) -> Result<[u8; 32]> {
    let raw = digest_raw(digest)?;
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(raw);
    Ok(hasher.finalize().into())
}

fn merkle_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    if value.is_power_of_two() {
        value / 2
    } else {
        1usize << (usize::BITS - value.leading_zeros() - 1)
    }
}

fn merkle_root_raw(digests: &[Hash]) -> Result<[u8; 32]> {
    match digests {
        [] => schema("MLS governance proof Merkle tree must not be empty"),
        [digest] => merkle_leaf(digest),
        _ => {
            let split = largest_power_of_two_less_than(digests.len());
            Ok(merkle_node(
                merkle_root_raw(&digests[..split])?,
                merkle_root_raw(&digests[split..])?,
            ))
        }
    }
}

fn merkle_root_hash(digests: &[Hash]) -> Result<Hash> {
    Hash::new(format!("sha256:{}", hex::encode(merkle_root_raw(digests)?))).map_err(Into::into)
}

fn merkle_proof(digests: &[Hash], index: usize) -> Result<Vec<Hash>> {
    if index >= digests.len() {
        return bounds("MLS governance proof Merkle index is out of range");
    }
    fn visit(digests: &[Hash], index: usize, proof: &mut Vec<Hash>) -> Result<()> {
        if digests.len() == 1 {
            return Ok(());
        }
        let split = largest_power_of_two_less_than(digests.len());
        if index < split {
            visit(&digests[..split], index, proof)?;
            proof.push(Hash::new(format!(
                "sha256:{}",
                hex::encode(merkle_root_raw(&digests[split..])?)
            ))?);
        } else {
            visit(&digests[split..], index - split, proof)?;
            proof.push(Hash::new(format!(
                "sha256:{}",
                hex::encode(merkle_root_raw(&digests[..split])?)
            ))?);
        }
        Ok(())
    }
    let mut proof = Vec::new();
    visit(digests, index, &mut proof)?;
    if proof.len() > 10 {
        return bounds("MLS governance proof chunk_proof exceeds 10 siblings");
    }
    Ok(proof)
}

fn split_items<T: Clone + Serialize>(
    items: &[T],
    max_items: usize,
) -> Result<Vec<(usize, Vec<T>)>> {
    let mut result = Vec::new();
    let mut start = 0usize;
    while start < items.len() {
        let mut end = start;
        let mut bytes = 0usize;
        while end < items.len() && end - start < max_items {
            let item_len = canonical::canonical_json_bytes(&items[end])?.len();
            if item_len > MLS_GOVERNANCE_MAX_CHUNK_ITEM_BYTES {
                return bounds("one MLS governance proof item cannot fit in a bounded response");
            }
            if end > start && bytes + item_len > MLS_GOVERNANCE_MAX_CHUNK_ITEM_BYTES {
                break;
            }
            bytes += item_len;
            end += 1;
        }
        result.push((start, items[start..end].to_vec()));
        start = end;
    }
    Ok(result)
}

fn item_bytes<T: Serialize>(items: &[T]) -> Result<u64> {
    items.iter().try_fold(0u64, |total, item| {
        let len = canonical::canonical_json_bytes(item)?.len() as u64;
        total
            .checked_add(len)
            .ok_or_else(|| Error::Protocol("MLS governance proof byte count overflow".to_owned()))
    })
}

fn materialized_total_item_bytes(bundle: &MaterializedMlsGovernanceProofBundle) -> Result<u64> {
    [
        item_bytes(&bundle.seal_path)?,
        item_bytes(&bundle.covered_event_digests)?,
        item_bytes(&bundle.control_state)?,
        item_bytes(&bundle.frontier_events)?,
    ]
    .into_iter()
    .try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| Error::Protocol("MLS governance proof byte count overflow".to_owned()))
    })
}

fn validate_materialized_identity(
    request: &MlsGovernanceProofRequest,
    bundle: &MaterializedMlsGovernanceProofBundle,
) -> Result<()> {
    if bundle.bundle_version != MLS_GOVERNANCE_PROOF_BUNDLE_VERSION
        || bundle.materialization_profile != MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE
    {
        return schema("unsupported MLS governance proof bundle header");
    }
    if bundle.realm_id != request.realm_id
        || bundle.effective_scope != request.effective_scope
        || bundle.reducer_profile != request.reducer_profile
        || bundle.trusted_anchor_seal_id != request.trusted_anchor_seal_id
    {
        return state_mismatch("materialized proof does not match the proof request identity");
    }
    Ok(())
}

fn validate_collection_totals(bundle: &MaterializedMlsGovernanceProofBundle) -> Result<()> {
    if bundle.seal_path.is_empty()
        || bundle.seal_path.len() > MLS_GOVERNANCE_MAX_SEAL_PATH_ITEMS
        || bundle.covered_event_digests.len() > MLS_GOVERNANCE_MAX_COVERED_EVENT_DIGESTS
        || bundle.control_state.len() > MLS_GOVERNANCE_MAX_CONTROL_STATE_ITEMS
        || bundle.frontier_events.is_empty()
        || bundle.frontier_events.len() > MLS_GOVERNANCE_MAX_FRONTIER_EVENTS
    {
        return bounds("MLS governance proof collection total exceeds schema bounds");
    }
    Ok(())
}

fn validate_manifest(manifest: &MlsGovernanceProofChunkManifest) -> Result<()> {
    if manifest.manifest_version != MLS_GOVERNANCE_PROOF_MANIFEST_VERSION
        || !(2..=MLS_GOVERNANCE_MAX_CHUNKS as u32).contains(&manifest.chunk_count)
        || manifest.max_response_bytes != MLS_GOVERNANCE_MAX_RESPONSE_BYTES as u32
        || manifest.max_total_item_bytes != MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES as u32
        || manifest.max_items_per_chunk != MlsGovernanceProofChunkItemLimits::default()
        || manifest.total_item_bytes == 0
        || manifest.total_item_bytes > MLS_GOVERNANCE_MAX_TOTAL_ITEM_BYTES as u64
        || !is_sha256_digest(&manifest.chunks_root)
    {
        return bounds("MLS governance proof manifest constants or bounds are invalid");
    }
    let totals = &manifest.collection_totals;
    if totals.seal_path == 0
        || totals.seal_path as usize > MLS_GOVERNANCE_MAX_SEAL_PATH_ITEMS
        || totals.covered_event_digests as usize > MLS_GOVERNANCE_MAX_COVERED_EVENT_DIGESTS
        || totals.control_state as usize > MLS_GOVERNANCE_MAX_CONTROL_STATE_ITEMS
        || totals.frontier_events == 0
        || totals.frontier_events as usize > MLS_GOVERNANCE_MAX_FRONTIER_EVENTS
    {
        return bounds("MLS governance proof manifest collection totals are invalid");
    }
    Ok(())
}

fn same_bundle_header(
    first: &MlsGovernanceProofBundle,
    candidate: &MlsGovernanceProofBundle,
) -> bool {
    first.bundle_version == candidate.bundle_version
        && first.proof_request_digest == candidate.proof_request_digest
        && first.bundle_digest == candidate.bundle_digest
        && first.materialization_profile == candidate.materialization_profile
        && first.realm_id == candidate.realm_id
        && first.effective_scope == candidate.effective_scope
        && first.reducer_profile == candidate.reducer_profile
        && first.governance_binding == candidate.governance_binding
        && first.trusted_anchor_seal_id == candidate.trusted_anchor_seal_id
        && first.accepted_seal_id == candidate.accepted_seal_id
        && first.chunk_manifest == candidate.chunk_manifest
}

fn validate_chunk_range<T>(
    collection: usize,
    last_collection: &mut usize,
    start_index: u32,
    current_len: usize,
    items: &[T],
    max_items: usize,
) -> Result<()> {
    if collection < *last_collection {
        return schema("MLS governance proof collection chunks are out of order");
    }
    *last_collection = collection;
    if start_index as usize != current_len {
        return incomplete("MLS governance proof collection range is not contiguous");
    }
    if items.is_empty() || items.len() > max_items {
        return bounds("MLS governance proof chunk item count is invalid");
    }
    Ok(())
}

fn schema<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!("{message} (schema_violation)")))
}

fn state_mismatch<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!("{message} (state_mismatch)")))
}

fn stale<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!(
        "{message} (mls_governance_binding_stale)"
    )))
}

fn bounds<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!(
        "{message} (mls_governance_proof_bounds_exceeded)"
    )))
}

fn incomplete<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!(
        "{message} (mls_governance_proof_incomplete)"
    )))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_state::{CellState, compute_state_root, control_event_set_root};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::{
        Effect, EventRequirements, Hlc, LatticeOp, LatticeOpType, MoveSignature, Proof, SealKind,
    };

    struct Fixture {
        bundle: MaterializedMlsGovernanceProofBundle,
        binding: MlsGovernanceBindingPayload,
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a").unwrap()
    }

    fn event_id() -> EventId {
        EventId::new("ak:event:0196419b-0000-7000-8000-000000000002").unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn cell(component: &str, subject: &str) -> CellRef {
        CellRef::new(format!("ak:cell:{component}:{subject}")).unwrap()
    }

    fn control_state() -> Vec<MlsGovernanceControlStateLeaf> {
        let mut leaves = vec![
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.member.state.v1", "did.web.alice.example"),
                state: MlsGovernanceControlStateValue {
                    value: json!({"state": "joined"}),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.realm.policy_components.v1", realm().as_str()),
                state: MlsGovernanceControlStateValue {
                    value: json!({"media_service_decrypts": true}),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell(
                    "ak.component.realm.plaintext_visible_services.v1",
                    realm().as_str(),
                ),
                state: MlsGovernanceControlStateValue {
                    value: json!({
                        "services": [{
                            "service_id": "did:webvh:z6mkfixture:media.example",
                            "data_classes": ["media_plaintext"],
                            "visibility": "realm",
                            "purposes": ["video transcoding"]
                        }]
                    }),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.capability.grant.v1", "ak.grant.fixture"),
                state: MlsGovernanceControlStateValue {
                    value: json!({"active": true}),
                },
            },
        ];
        leaves.sort_by(|left, right| left.cell.as_str().cmp(right.cell.as_str()));
        leaves
    }

    fn state_map(leaves: &[MlsGovernanceControlStateLeaf]) -> BTreeMap<CellRef, CellState> {
        leaves
            .iter()
            .map(|leaf| {
                (
                    leaf.cell.clone(),
                    CellState::Value(leaf.state.value.clone()),
                )
            })
            .collect()
    }

    fn frontier_event(scope: EffectiveScope) -> Event {
        let mut event = Event {
            event_id: event_id(),
            kind: "ak.member.state".into(),
            realm_id: realm(),
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            actor_seq: 1,
            created_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap(),
            hlc: Hlc::new("01980b44cc00-0000-aabbccdd").unwrap(),
            prev_refs: Vec::new(),
            effective_scope: Some(scope),
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: vec![Effect {
                cell: cell("ak.component.member.state.v1", "did.web.alice.example"),
                op: LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!({"state": "joined"})),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            }],
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            payload: BTreeMap::new(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        };
        let digest = Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:alice.example#device-key".to_owned(),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        });
        event
    }

    fn seal(
        state_root: Hash,
        covered_event_digests: Vec<MoveId>,
        control_event_set_root: Hash,
    ) -> Seal {
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            realm_id: realm(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root,
            state_root,
            completeness_root: hash(0xcc),
            notary_seq: 1,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests,
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:notary.example#key-1".to_owned(),
                payload_digest: hash(0),
                created_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }),
            sealed_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 1).unwrap(),
            hlc: Hlc::new("01980b44cc01-0000-aabbccdd").unwrap(),
            kind: SealKind::Compaction,
        };
        let payload_digest = Hash::new(canonical::sha256_digest(
            seal.canonical_bytes_for_id().unwrap(),
        ))
        .unwrap();
        if let NotarySig::Single(signature) = &mut seal.notary_signature {
            signature.payload_digest = payload_digest;
        }
        seal.id = seal.derive_id().unwrap();
        seal
    }

    fn fixture() -> Fixture {
        let effective_scope = EffectiveScope::Realm { realm_id: realm() };
        let frontier_event = frontier_event(effective_scope.clone());
        let frontier_digest = MoveId::new(frontier_event.event_digest().unwrap()).unwrap();
        let covered_event_digests = vec![frontier_digest.clone()];
        let covered = BTreeSet::from([frontier_digest]);
        let control_state = control_state();
        let states = state_map(&control_state);
        let policy_root = derive_mls_policy_root(&states).unwrap();
        let capability_root = derive_mls_capability_root(&states).unwrap();
        let discussion_metadata_digest =
            derive_mls_discussion_metadata_digest(&control_state).unwrap();
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            policy_root,
            capability_root,
            discussion_metadata_digest,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let seal = seal(
            compute_state_root(&states).unwrap(),
            covered_event_digests.clone(),
            control_event_set_root(&covered).unwrap(),
        );
        let seal_id = seal.id.clone();
        Fixture {
            bundle: MaterializedMlsGovernanceProofBundle {
                bundle_version: MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
                proof_request_digest: hash(0),
                bundle_digest: hash(0),
                materialization_profile: MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE.to_owned(),
                realm_id: realm(),
                effective_scope,
                reducer_profile: "ak.reducer.v1".to_owned(),
                governance_binding: binding.clone(),
                trusted_anchor_seal_id: seal_id.clone(),
                accepted_seal_id: seal_id,
                seal_path: vec![seal],
                covered_event_digests: covered_event_digests
                    .into_iter()
                    .map(|digest| Hash::new(digest.as_str().to_owned()).unwrap())
                    .collect(),
                control_state,
                frontier_events: vec![frontier_event],
            },
            binding,
        }
    }

    fn verify(fixture: &Fixture) -> Result<VerifiedMlsGovernanceProof> {
        verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
        )
    }

    fn proof_request(fixture: &Fixture) -> MlsGovernanceProofRequest {
        MlsGovernanceProofRequest {
            realm_id: fixture.bundle.realm_id.clone(),
            effective_scope: fixture.bundle.effective_scope.clone(),
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 0,
            next_epoch: 1,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: fixture.bundle.reducer_profile.clone(),
            trusted_anchor_seal_id: fixture.bundle.trusted_anchor_seal_id.clone(),
            chunk_index: 0,
            expected_bundle_digest: None,
        }
    }

    #[test]
    fn complete_bundle_verifies() {
        let fixture = fixture();
        let verified = verify(&fixture).unwrap();
        assert_eq!(verified.accepted_seal_id, fixture.bundle.accepted_seal_id);
        assert_eq!(verified.membership_frontier, vec![event_id()]);
    }

    #[test]
    fn chunked_bundle_round_trips_before_verification() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();
        assert!(chunks.len() >= 2);
        let assembled = assemble_mls_governance_proof_chunks(&request, &chunks).unwrap();
        assert_eq!(assembled.seal_path, fixture.bundle.seal_path);
        assert_eq!(assembled.control_state, fixture.bundle.control_state);
        verify_mls_governance_proof_bundle(
            &assembled,
            &fixture.binding,
            &request.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
    }

    #[test]
    fn incomplete_duplicate_and_out_of_order_chunks_fail_closed() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();

        let mut missing = chunks.clone();
        missing.pop();
        assert!(
            assemble_mls_governance_proof_chunks(&request, &missing)
                .unwrap_err()
                .to_string()
                .contains("mls_governance_proof_incomplete")
        );

        let mut duplicate = chunks.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(assemble_mls_governance_proof_chunks(&request, &duplicate).is_err());

        let mut out_of_order = chunks;
        out_of_order.swap(0, 1);
        assert!(
            assemble_mls_governance_proof_chunks(&request, &out_of_order)
                .unwrap_err()
                .to_string()
                .contains("chunk_index order")
        );
    }

    #[test]
    fn tampered_and_mixed_chunks_fail_closed() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();

        let mut tampered = chunks.clone();
        tampered[0].chunk = match tampered[0].chunk.clone() {
            MlsGovernanceProofChunk::SealPath {
                chunk_index,
                start_index,
                mut items,
                chunk_digest,
                chunk_proof,
            } => {
                items[0].notary_seq += 1;
                MlsGovernanceProofChunk::SealPath {
                    chunk_index,
                    start_index,
                    items,
                    chunk_digest,
                    chunk_proof,
                }
            }
            _ => panic!("first chunk must be seal_path"),
        };
        assert!(
            assemble_mls_governance_proof_chunks(&request, &tampered)
                .unwrap_err()
                .to_string()
                .contains("chunk_digest mismatch")
        );

        let mut mixed = chunks;
        mixed[1].accepted_seal_id =
            SealId::new(format!("ak:seal:{}", hash(0xfe).as_str())).unwrap();
        assert!(
            assemble_mls_governance_proof_chunks(&request, &mixed)
                .unwrap_err()
                .to_string()
                .contains("mix different bundles")
        );
    }

    #[test]
    fn rejected_seal_signature_is_propagated() {
        let fixture = fixture();
        let error = verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| {
                Err(Error::Protocol(
                    "fixture Seal signature rejected".to_owned(),
                ))
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixture Seal signature rejected")
        );
    }

    #[test]
    fn rejected_frontier_event_signature_is_propagated() {
        let fixture = fixture();
        let error = verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| {
                Err(Error::Protocol(
                    "fixture frontier Event signature rejected".to_owned(),
                ))
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixture frontier Event signature rejected")
        );
    }

    #[test]
    fn seal_signature_payload_digest_tampering_is_rejected() {
        let mut fixture = fixture();
        let NotarySig::Single(signature) = &mut fixture.bundle.seal_path[0].notary_signature else {
            panic!("fixture must use a single notary signature");
        };
        signature.payload_digest = hash(0xef);
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn proof_request_rejects_epoch_skip() {
        let request = MlsGovernanceProofRequest {
            realm_id: realm(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 3,
            next_epoch: 5,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
            trusted_anchor_seal_id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            chunk_index: 0,
            expected_bundle_digest: None,
        };
        let error = request.validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains(crate::ErrorCode::SCHEMA_VIOLATION)
        );
    }

    #[test]
    fn proof_request_accepts_genesis_epoch() {
        let request = MlsGovernanceProofRequest {
            realm_id: realm(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 0,
            next_epoch: 0,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
            trusted_anchor_seal_id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            chunk_index: 0,
            expected_bundle_digest: None,
        };
        request.validate().unwrap();
    }

    #[test]
    fn bundle_epoch_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.governance_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            1,
            2,
            vec![event_id()],
            fixture.binding.policy_root().clone(),
            fixture.binding.capability_root().unwrap().clone(),
            fixture
                .binding
                .discussion_metadata_digest()
                .unwrap()
                .clone(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn bundle_scope_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.effective_scope = EffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014b").unwrap(),
        };
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn bundle_reducer_profile_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.reducer_profile = "ak.reducer.tampered.v1".to_owned();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn omitted_control_leaf_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.control_state.remove(0);
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn incomplete_covered_manifest_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.covered_event_digests.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn missing_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn cross_scope_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events[0].effective_scope = None;
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(crate::ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn discussion_metadata_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            fixture.binding.policy_root().clone(),
            fixture.binding.capability_root().unwrap().clone(),
            hash(0xee),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.bundle.governance_binding = bad_binding.clone();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(crate::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn policy_root_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            hash(0xed),
            fixture.binding.capability_root().unwrap().clone(),
            fixture
                .binding
                .discussion_metadata_digest()
                .unwrap()
                .clone(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.bundle.governance_binding = bad_binding.clone();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(crate::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn capability_root_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            fixture.binding.policy_root().clone(),
            hash(0xec),
            fixture
                .binding
                .discussion_metadata_digest()
                .unwrap()
                .clone(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.bundle.governance_binding = bad_binding.clone();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(crate::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }
}
