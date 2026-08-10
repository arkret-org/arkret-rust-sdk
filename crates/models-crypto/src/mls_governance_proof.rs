//! Complete-materialization proof for full-profile MLS governance bindings.
//!
//! A selective Merkle proof only shows that disclosed leaves exist; it cannot
//! prove that a server omitted no policy or capability leaf. The v1 proof
//! therefore materializes the complete covered digest set and every non-bottom
//! control cell committed by the accepted Seal.
//!
//! This module owns the proof request / bundle / chunk data shapes and the
//! chunk build / assemble commitment machinery. Verification and control-state
//! root derivation are owned by `arkret-state::mls_governance_proof`.

use arkret_wire::base64url::base64url_decode;
use arkret_wire::event_envelope::{Event, ScopeRef};
use arkret_wire::{
    CellRef, DidCoreId, Error, Hash, NonEmptyString, ProfileId, RealmId, Result, SchemaId, Seal,
    SealId, canonical,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

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

/// One current or pending RFC 9420 leaf as seen by the verifier.
///
/// This is deliberately not carried by the proof bundle. The verifier obtains
/// it from its local MLS group state so the proof service cannot choose the
/// key-holder set used to validate a governance binding.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsSecurityFrontierLeaf {
    pub leaf_index: u32,
    pub principal_id: DidCoreId,
    pub credential_ref: NonEmptyString,
}

const MLS_GOVERNANCE_REQUEST_DOMAIN: &[u8] = b"arkret-mls-governance-proof-request-v1\n";
const MLS_GOVERNANCE_BUNDLE_DOMAIN: &[u8] = b"arkret-mls-governance-proof-bundle-v1\n";
const MLS_GOVERNANCE_CHUNK_DOMAIN: &[u8] = b"arkret-mls-governance-proof-chunk-v1\n";
// Leaves enough headroom for the repeated response header and JSON delimiters.
const MLS_GOVERNANCE_MAX_CHUNK_ITEM_BYTES: usize = 3_500_000;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofRequestBodyBody {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
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

impl MlsGovernanceProofRequestBodyBody {
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
        if self.binding_profile != ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1 {
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
            effective_scope: &'a ScopeRef,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofCollectionTotals {
    pub seal_path: u32,
    pub covered_event_digests: u32,
    pub control_state: u32,
    pub frontier_events: u32,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "collection", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsGovernanceProofChunk {
    SealPath {
        chunk_index: u32,
        start_index: u32,
        #[cfg_attr(
            feature = "openapi",
            salvo(schema(value_type = Vec<serde_json::Value>))
        )]
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
        #[cfg_attr(
            feature = "openapi",
            salvo(schema(value_type = Vec<serde_json::Value>))
        )]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofBundle {
    pub bundle_version: u8,
    pub proof_request_digest: Hash,
    pub bundle_digest: Hash,
    pub materialization_profile: String,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub reducer_profile: String,
    pub trusted_anchor_seal_id: SealId,
    pub accepted_seal_id: SealId,
    pub chunk_manifest: MlsGovernanceProofChunkManifest,
    pub chunk: MlsGovernanceProofChunk,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaterializedMlsGovernanceProofBundle {
    pub bundle_version: u8,
    pub proof_request_digest: Hash,
    pub bundle_digest: Hash,
    pub materialization_profile: String,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub reducer_profile: String,
    pub trusted_anchor_seal_id: SealId,
    pub accepted_seal_id: SealId,
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub seal_path: Vec<Seal>,
    pub covered_event_digests: Vec<Hash>,
    pub control_state: Vec<MlsGovernanceControlStateLeaf>,
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub frontier_events: Vec<Event>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceControlStateLeaf {
    pub cell: CellRef,
    pub state: MlsGovernanceControlStateValue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceControlStateValue {
    pub value: Value,
}

impl MlsGovernanceProofBundle {
    pub const SCHEMA: &'static str = SchemaId::MLS_GOVERNANCE_PROOF_BUNDLE_V1;
    pub fn recompute_bundle_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct DigestView<'a> {
            bundle_version: u8,
            proof_request_digest: &'a Hash,
            materialization_profile: &'a str,
            realm_id: &'a RealmId,
            effective_scope: &'a ScopeRef,
            reducer_profile: &'a str,
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
    request: &MlsGovernanceProofRequestBodyBody,
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
    let chunks_root = merkle_tree_root(&chunk_digests)?;
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
    request: &MlsGovernanceProofRequestBodyBody,
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
    if merkle_tree_root(&digests)? != first.chunk_manifest.chunks_root {
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
        trusted_anchor_seal_id: first.trusted_anchor_seal_id.clone(),
        accepted_seal_id: first.accepted_seal_id.clone(),
        seal_path,
        covered_event_digests,
        control_state,
        frontier_events,
    })
}

pub fn is_mls_membership_frontier_component(component: &str) -> bool {
    matches!(
        component,
        arkret_wire::CellFamilyId::MEMBER_STATE_V1
            | arkret_wire::CellFamilyId::REALM_CREATE_V1
            | arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1
            | arkret_wire::CellFamilyId::ACCOUNT_STATUS_V1
            | arkret_wire::CellFamilyId::DEVICE_AUTHORIZATION_V1
            | arkret_wire::CellFamilyId::DEVICE_LIST_UPDATE_V1
            | arkret_wire::CellFamilyId::REALM_TOMBSTONE_V1
            | arkret_wire::CellFamilyId::REALM_DESTROY_V1
    )
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

fn merkle_tree_root(digests: &[Hash]) -> Result<Hash> {
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
    request: &MlsGovernanceProofRequestBodyBody,
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
