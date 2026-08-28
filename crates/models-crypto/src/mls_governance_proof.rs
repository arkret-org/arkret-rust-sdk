//! Near-current stateless MLS group-security-frontier proof DTOs.
//!
//! Bulk and historical replay use the standard Event, Seal, and governance
//! dependency resolve surfaces. This module deliberately has no chunk,
//! package, materialized-bundle, cursor, or continuation carrier.

use std::collections::BTreeSet;

use arkret_wire::base64url::{base64url_decode, base64url_encode};
use arkret_wire::event_envelope::ScopeRef;
use arkret_wire::{
    Base64UrlString, CellRef, DidCoreId, EventId, Hash, NonEmptyString, Result, SealBasis, SealId,
    WireError,
};
use serde::{Deserialize, Serialize};

pub const MLS_GOVERNANCE_PROOF_MIN_BYTES: u32 = 65_536;
pub const MLS_GOVERNANCE_PROOF_MAX_BYTES: u32 = 1_048_576;
pub const MLS_GOVERNANCE_PROOF_MAX_REQUEST_BYTES: usize = 8_388_608;
pub const MLS_GOVERNANCE_PROOF_MAX_LEAVES: usize = 65_536;
pub const MLS_GOVERNANCE_PROOF_MAX_SIBLINGS: usize = 64;
const MLS_GOVERNANCE_PAGE_DIGEST_DOMAIN: &[u8] = b"ak.mls-governance-proof-page-v1";

/// One current or pending RFC 9420 leaf supplied by the local MLS state.
/// It is verifier input and never part of the proof response.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsSecurityFrontierLeaf {
    pub leaf_index: u32,
    pub principal_id: DidCoreId,
    pub credential_ref: NonEmptyString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsGovernanceProofProfile {
    #[serde(rename = "group_security_frontier")]
    GroupSecurityFrontier,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsGovernanceFrontierPurpose {
    #[serde(rename = "group_binding")]
    GroupBinding,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsGovernanceBindingProfile {
    #[serde(rename = "ak.security_frontier.v1")]
    AkSecurityFrontierV1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofRequestBody {
    pub profile: MlsGovernanceProofProfile,
    pub effective_scope: ScopeRef,
    pub mls_group_id: Base64UrlString,
    pub local_mls_leaves: Vec<MlsSecurityFrontierLeaf>,
    pub proof_base_basis: SealBasis,
    pub proof_target_basis: SealBasis,
    pub byte_limit: u32,
    pub frontier_purpose: MlsGovernanceFrontierPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_group_state_ref: Option<EventId>,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub binding_profile: MlsGovernanceBindingProfile,
}

impl MlsGovernanceProofRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.proof_base_basis.validate_protocol_bounds()?;
        self.proof_target_basis.validate_protocol_bounds()?;
        if !(MLS_GOVERNANCE_PROOF_MIN_BYTES..=MLS_GOVERNANCE_PROOF_MAX_BYTES)
            .contains(&self.byte_limit)
        {
            return schema("MLS governance proof byte_limit is outside 64 KiB..=1 MiB");
        }
        if matches!(
            self.effective_scope,
            ScopeRef::RealmGenesis | ScopeRef::Sidecar { .. }
        ) {
            return schema("MLS governance proof effective_scope must be Realm or Circle");
        }
        if self.effective_scope.canonical_mls_group_id()? != self.mls_group_id.as_str() {
            return state("MLS governance proof group does not match effective_scope");
        }
        if self.local_mls_leaves.is_empty()
            || self.local_mls_leaves.len() > MLS_GOVERNANCE_PROOF_MAX_LEAVES
        {
            return schema("MLS governance proof local_mls_leaves is outside 1..=65536");
        }
        let mut previous_leaf_index = None;
        let mut credential_refs = BTreeSet::new();
        for leaf in &self.local_mls_leaves {
            if leaf.credential_ref.as_str().chars().count() > 2_048 {
                return schema(
                    "MLS governance proof local_mls_leaves credential_ref exceeds 2048 characters",
                );
            }
            if previous_leaf_index.is_some_and(|previous| previous >= leaf.leaf_index) {
                return schema(
                    "MLS governance proof local_mls_leaves must use strictly increasing leaf_index order",
                );
            }
            previous_leaf_index = Some(leaf.leaf_index);
            if !credential_refs.insert(leaf.credential_ref.as_str()) {
                return schema("MLS governance proof local_mls_leaves repeats credential_ref");
            }
        }
        let genesis = self.previous_epoch == 0 && self.next_epoch == 0;
        let successor = self.previous_epoch.checked_add(1) == Some(self.next_epoch);
        if !genesis && !successor {
            return schema("MLS governance proof epochs are not genesis or one-step successor");
        }
        if genesis != self.base_group_state_ref.is_none() {
            return schema(
                "MLS governance proof genesis forbids base_group_state_ref and successor requires it",
            );
        }
        if arkret_canonical::canonical_json_bytes(self)?.len()
            > MLS_GOVERNANCE_PROOF_MAX_REQUEST_BYTES
        {
            return bounds("MLS governance proof request exceeds 8 MiB");
        }
        Ok(())
    }

    pub fn query_digest(&self) -> Result<Hash> {
        self.validate()?;
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        Ok(Hash::new(
            arkret_canonical::canonical::sha256_digest_from_slices(&[
                b"ak.mls-governance-proof-query-v1",
                &[0],
                &bytes,
            ]),
        )?)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsGovernanceMerkleProofKind {
    StateMembership,
    ControlEventMembership,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsGovernanceMerkleRootField {
    StateRoot,
    ControlEventSetRoot,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceMerkleMembershipWitness {
    pub proof_kind: MlsGovernanceMerkleProofKind,
    pub root_seal_ref: SealId,
    pub root_field: MlsGovernanceMerkleRootField,
    pub root_digest: Hash,
    pub leaf_canonical_preimage_b64u: Base64UrlString,
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<Hash>,
}

impl MlsGovernanceMerkleMembershipWitness {
    pub fn validate(&self) -> Result<()> {
        let paired = matches!(
            (self.proof_kind, self.root_field),
            (
                MlsGovernanceMerkleProofKind::StateMembership,
                MlsGovernanceMerkleRootField::StateRoot
            ) | (
                MlsGovernanceMerkleProofKind::ControlEventMembership,
                MlsGovernanceMerkleRootField::ControlEventSetRoot
            )
        );
        if !paired || self.leaf_count == 0 || self.leaf_index >= self.leaf_count {
            return schema("invalid MLS governance Merkle witness coordinates");
        }
        let preimage =
            base64url_decode(self.leaf_canonical_preimage_b64u.as_str()).map_err(|error| {
                WireError::Protocol(format!("invalid Merkle leaf preimage: {error}"))
            })?;
        if preimage.is_empty()
            || base64url_encode(&preimage) != self.leaf_canonical_preimage_b64u.as_str()
            || self.siblings.len() > MLS_GOVERNANCE_PROOF_MAX_SIBLINGS
            || self.siblings.len() != audit_path_len(self.leaf_index, self.leaf_count)
        {
            return schema("invalid MLS governance Merkle witness shape");
        }
        let suite = digest_suite(&self.root_digest)?;
        if digest_suite(&self.leaf_digest)? != suite
            || self
                .siblings
                .iter()
                .any(|digest| digest_suite(digest).ok() != Some(suite))
        {
            return schema("MLS governance Merkle witness mixes digest suites");
        }
        let mut leaf_input = Vec::with_capacity(preimage.len() + 1);
        leaf_input.push(0);
        leaf_input.extend_from_slice(&preimage);
        let expected = Hash::new(arkret_canonical::canonical::digest(suite, &leaf_input))?;
        if expected != self.leaf_digest {
            return state("MLS governance Merkle leaf digest mismatch");
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierCellEntry {
    pub cell_id: CellRef,
    pub value_digest: Hash,
    pub provenance_event_refs: Vec<EventId>,
    pub inclusion_witness: MlsGovernanceMerkleMembershipWitness,
}

impl MlsGovernanceFrontierCellEntry {
    pub fn validate(&self, state_root: &Hash) -> Result<()> {
        if self.provenance_event_refs.is_empty()
            || !is_sorted_unique(&self.provenance_event_refs)
            || self.inclusion_witness.proof_kind != MlsGovernanceMerkleProofKind::StateMembership
            || &self.inclusion_witness.root_digest != state_root
        {
            return schema("invalid MLS governance frontier cell entry");
        }
        self.inclusion_witness.validate()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceSealDescriptor {
    pub seal_ref: SealId,
    pub seal_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceSealPredecessorEdge {
    pub seal_ref: SealId,
    pub predecessor_seal_ref: SealId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceTypedProofMaterial {
    pub seal_descriptors: Vec<MlsGovernanceSealDescriptor>,
    pub event_ids: Vec<EventId>,
    pub seal_predecessor_edges: Vec<MlsGovernanceSealPredecessorEdge>,
}

impl MlsGovernanceTypedProofMaterial {
    pub fn validate(&self) -> Result<()> {
        if self.seal_descriptors.is_empty()
            || !is_sorted_unique(&self.seal_descriptors)
            || !is_sorted_unique_or_empty(&self.seal_predecessor_edges)
            || !is_sorted_unique_or_empty(&self.event_ids)
        {
            return schema("MLS governance proof descriptors are not canonical sets");
        }
        let seals = self
            .seal_descriptors
            .iter()
            .map(|descriptor| &descriptor.seal_ref)
            .collect::<BTreeSet<_>>();
        if self.seal_predecessor_edges.iter().any(|edge| {
            !seals.contains(&edge.seal_ref) || !seals.contains(&edge.predecessor_seal_ref)
        }) {
            return state("MLS governance predecessor edge names an undescribed Seal");
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsGovernanceFrontierBoundarySide {
    Left,
    Right,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierBoundary {
    pub side: MlsGovernanceFrontierBoundarySide,
    pub state_edge: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<MlsGovernanceFrontierCellEntry>,
}

impl MlsGovernanceFrontierBoundary {
    fn validate(
        &self,
        expected_side: MlsGovernanceFrontierBoundarySide,
        state_root: &Hash,
    ) -> Result<()> {
        if self.side != expected_side || self.state_edge == self.entry.is_some() {
            return schema("invalid MLS governance frontier boundary");
        }
        if let Some(entry) = &self.entry {
            entry.validate(state_root)?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierRangeWitness {
    pub cell_family: String,
    pub subject_prefix: String,
    pub leaf_count: u64,
    pub start_index: u64,
    pub end_index_exclusive: u64,
    pub included_entry_indices: Vec<u64>,
    pub left_boundary: MlsGovernanceFrontierBoundary,
    pub right_boundary: MlsGovernanceFrontierBoundary,
}

impl MlsGovernanceFrontierRangeWitness {
    fn validate(&self, state_root: &Hash) -> Result<()> {
        if !is_cell_family(&self.cell_family)
            || self.start_index > self.end_index_exclusive
            || self.end_index_exclusive > self.leaf_count
            || self.included_entry_indices
                != (self.start_index..self.end_index_exclusive).collect::<Vec<_>>()
        {
            return schema("invalid MLS governance frontier range witness");
        }
        self.left_boundary
            .validate(MlsGovernanceFrontierBoundarySide::Left, state_root)?;
        self.right_boundary
            .validate(MlsGovernanceFrontierBoundarySide::Right, state_root)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierProjection {
    pub frontier_registry_digest: Hash,
    pub frontier_branch_projections: Vec<MlsGovernanceFrontierBranchProjection>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierBranchProjection {
    pub target_seal_ref: SealId,
    pub state_root: Hash,
    pub frontier_cell_entries: Vec<MlsGovernanceFrontierCellEntry>,
    pub range_witnesses: Vec<MlsGovernanceFrontierRangeWitness>,
}

impl MlsGovernanceFrontierProjection {
    pub fn validate(&self) -> Result<()> {
        if self.branches.is_empty()
            || self
                .branches
                .windows(2)
                .any(|pair| pair[0].target_seal_ref >= pair[1].target_seal_ref)
        {
            return schema("MLS governance frontier branches are not canonical");
        }
        for branch in &self.branches {
            branch.validate()?;
        }
        Ok(())
    }
}

impl MlsGovernanceFrontierBranchProjection {
    pub fn validate(&self) -> Result<()> {
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].cell_id.as_str() >= pair[1].cell_id.as_str())
            || self.range_witnesses.windows(2).any(|pair| {
                (
                    pair[0].cell_family.as_str(),
                    pair[0].subject_prefix.as_str(),
                ) >= (
                    pair[1].cell_family.as_str(),
                    pair[1].subject_prefix.as_str(),
                )
            })
        {
            return schema("MLS governance frontier projection is not canonical");
        }
        for entry in &self.entries {
            entry.validate(&self.state_root)?;
            if entry.inclusion_witness.root_seal_ref != self.target_seal_ref {
                return state("MLS governance branch entry names a different target Seal");
            }
        }
        for witness in &self.range_witnesses {
            witness.validate(&self.state_root)?;
            for entry in witness
                .left_boundary
                .entry
                .iter()
                .chain(witness.right_boundary.entry.iter())
            {
                if entry.inclusion_witness.root_seal_ref != self.target_seal_ref {
                    return state("MLS governance branch boundary names a different target Seal");
                }
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofBundle {
    pub query_digest: Hash,
    pub frontier_projection: MlsGovernanceFrontierProjection,
    pub proof_material: MlsGovernanceTypedProofMaterial,
    pub page_digest: Hash,
}

impl MlsGovernanceProofBundle {
    pub fn validate_for_request(&self, request: &MlsGovernanceProofRequestBody) -> Result<()> {
        request.validate()?;
        if self.query_digest != request.query_digest()? {
            return state("MLS governance proof response binds a different query");
        }
        self.frontier_projection.validate()?;
        self.proof_material.validate()?;
        let branch_seals = self
            .frontier_projection
            .branches
            .iter()
            .map(|branch| &branch.target_seal_ref)
            .collect::<BTreeSet<_>>();
        let target_seals = request
            .proof_target_basis
            .leaves
            .iter()
            .collect::<BTreeSet<_>>();
        if branch_seals != target_seals
            || self.frontier_projection.branches.len() != request.proof_target_basis.leaves.len()
        {
            return state(
                "MLS governance frontier branches are not every-and-only the target basis",
            );
        }

        let described_seals = self
            .proof_material
            .seal_descriptors
            .iter()
            .map(|descriptor| &descriptor.seal_ref)
            .collect::<BTreeSet<_>>();
        if request
            .proof_base_basis
            .leaves
            .iter()
            .chain(&request.proof_target_basis.leaves)
            .any(|seal| !described_seals.contains(seal))
        {
            return state("MLS governance proof omits a query basis Seal descriptor");
        }

        let described_events = self
            .proof_material
            .event_ids
            .iter()
            .collect::<BTreeSet<_>>();
        for entry in self.all_entries() {
            if !described_seals.contains(&entry.inclusion_witness.root_seal_ref)
                || entry
                    .provenance_event_refs
                    .iter()
                    .any(|event| !described_events.contains(event))
            {
                return state("MLS governance frontier entry omits required proof descriptors");
            }
        }

        if self.page_digest != self.recompute_page_digest()? {
            return state("MLS governance proof page_digest mismatch");
        }
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        if bytes.len() > request.byte_limit as usize
            || bytes.len() > MLS_GOVERNANCE_PROOF_MAX_BYTES as usize
        {
            return bounds("MLS governance proof response exceeds its exact byte ceiling");
        }
        Ok(())
    }

    pub fn recompute_page_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct PageBody<'a> {
            frontier_projection: &'a MlsGovernanceFrontierProjection,
            proof_material: &'a MlsGovernanceTypedProofMaterial,
        }
        let body = arkret_canonical::canonical_json_bytes(&PageBody {
            frontier_projection: &self.frontier_projection,
            proof_material: &self.proof_material,
        })?;
        Ok(Hash::new(
            arkret_canonical::canonical::sha256_digest_from_slices(&[
                MLS_GOVERNANCE_PAGE_DIGEST_DOMAIN,
                &[0],
                self.query_digest.as_str().as_bytes(),
                &[0],
                &body,
            ]),
        )?)
    }

    pub fn all_entries(&self) -> impl Iterator<Item = &MlsGovernanceFrontierCellEntry> {
        self.frontier_projection.branches.iter().flat_map(|branch| {
            branch
                .entries
                .iter()
                .chain(branch.range_witnesses.iter().flat_map(|witness| {
                    witness
                        .left_boundary
                        .entry
                        .iter()
                        .chain(witness.right_boundary.entry.iter())
                }))
        })
    }
}

fn audit_path_len(mut index: u64, mut size: u64) -> usize {
    let mut length = 0;
    while size > 1 {
        if index % 2 == 1 || index + 1 < size {
            length += 1;
        }
        index /= 2;
        size = size.div_ceil(2);
    }
    length
}

fn digest_suite(digest: &Hash) -> Result<arkret_canonical::canonical::DigestSuite> {
    let (suite, _) = digest
        .as_ref()
        .split_once(':')
        .ok_or_else(|| WireError::Protocol("digest has no suite prefix".to_owned()))?;
    arkret_canonical::canonical::digest_suite(suite)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

fn is_cell_family(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("ak.component.")
        .and_then(|value| value.strip_suffix(".v1"))
    else {
        return false;
    };
    !body.is_empty()
        && body.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
}

fn is_sorted_unique<T: Ord>(items: &[T]) -> bool {
    !items.is_empty() && items.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_sorted_unique_or_empty<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn schema<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(format!("{message} (schema_violation)")))
}

fn state<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(format!("{message} (state_mismatch)")))
}

fn bounds<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(format!(
        "{message} (mls_governance_proof_bounds_exceeded)"
    )))
}
