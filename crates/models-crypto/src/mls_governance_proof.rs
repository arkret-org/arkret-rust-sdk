//! Near-current stateless MLS group-security-frontier proof DTOs.
//!
//! Bulk and historical replay use the standard Event, Seal, and governance
//! dependency resolve surfaces. This module deliberately has no chunk,
//! package, materialized-bundle, cursor, or continuation carrier.

use std::collections::BTreeSet;

use arkret_wire::base64url::{base64url_decode, base64url_encode};
use arkret_wire::event_envelope::ScopeRef;
use arkret_wire::{
    Base64UrlString, CellRef, ContentScheme, DurabilityPolicy, EventId, Hash, Result, SealBasis,
    SealId, WireError,
};
use serde::{Deserialize, Serialize};

pub const MLS_GOVERNANCE_PROOF_MIN_BYTES: u32 = 65_536;
pub use arkret_wire::constants::MLS_GOVERNANCE_PROOF_MAX_BYTES;
pub const MLS_GOVERNANCE_PROOF_MAX_REQUEST_BYTES: usize = 8_388_608;
pub use arkret_wire::mls_transition::MLS_FRONTIER_MAX_LEAVES as MLS_GOVERNANCE_PROOF_MAX_LEAVES;
pub const MLS_GOVERNANCE_PROOF_MAX_SIBLINGS: usize = 64;
const MLS_GOVERNANCE_PAGE_DIGEST_DOMAIN: &[u8] = b"ak.mls-governance-proof-page-v1";

pub use arkret_wire::mls_transition::MlsSecurityFrontierLeaf;

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

/// Immutable group binding proposed only by the unique pre-Genesis 0 -> 0
/// governance query. It is query input, not accepted authority.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedMlsGroupGenesisBinding {
    pub content_scheme: ContentScheme,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability_policy: Option<DurabilityPolicy>,
}

impl ProposedMlsGroupGenesisBinding {
    pub fn validate(&self) -> Result<()> {
        match (self.content_scheme, self.durability_policy) {
            (ContentScheme::MlsRfc9420, None)
            | (
                ContentScheme::MlsExporterAeadV1,
                Some(DurabilityPolicy::None | DurabilityPolicy::OrganizationRecoveryKey),
            ) => Ok(()),
            _ => schema(
                "proposed MLS group genesis binding content scheme and durability policy mismatch",
            ),
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_group_genesis_binding: Option<ProposedMlsGroupGenesisBinding>,
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
        validate_group_binding_query(
            &self.effective_scope,
            &self.mls_group_id,
            &self.local_mls_leaves,
            self.base_group_state_ref.as_ref(),
            self.proposed_group_genesis_binding.as_ref(),
            self.previous_epoch,
            self.next_epoch,
        )?;
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

pub(crate) fn validate_group_binding_query(
    effective_scope: &ScopeRef,
    mls_group_id: &Base64UrlString,
    local_mls_leaves: &[MlsSecurityFrontierLeaf],
    base_group_state_ref: Option<&EventId>,
    proposed_group_genesis_binding: Option<&ProposedMlsGroupGenesisBinding>,
    previous_epoch: u64,
    next_epoch: u64,
) -> Result<()> {
    if matches!(
        effective_scope,
        ScopeRef::RealmGenesis | ScopeRef::Sidecar { .. }
    ) {
        return schema("MLS governance proof effective_scope must be Realm or Circle");
    }
    if effective_scope.canonical_mls_group_id()? != mls_group_id.as_str() {
        return state("MLS governance proof group does not match effective_scope");
    }
    arkret_wire::mls_transition::validate_mls_frontier_leaves(local_mls_leaves)?;
    let genesis = previous_epoch == 0 && next_epoch == 0;
    let successor = previous_epoch.checked_add(1) == Some(next_epoch);
    if !genesis && !successor {
        return schema("MLS governance proof epochs are not genesis or one-step successor");
    }
    if genesis != base_group_state_ref.is_none() {
        return schema(
            "MLS governance proof genesis forbids base_group_state_ref and successor requires it",
        );
    }
    if !genesis && proposed_group_genesis_binding.is_some() {
        return schema("MLS governance successor query forbids proposed_group_genesis_binding");
    }
    if let Some(proposal) = proposed_group_genesis_binding {
        proposal.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AccountId, ActorId, DidCoreId, NonEmptyString, RealmId};

    use super::*;

    fn genesis_request(proposal: ProposedMlsGroupGenesisBinding) -> MlsGovernanceProofRequestBody {
        let realm_id =
            RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
        let effective_scope = ScopeRef::Realm { realm_id };
        MlsGovernanceProofRequestBody {
            profile: MlsGovernanceProofProfile::GroupSecurityFrontier,
            mls_group_id: Base64UrlString::new(
                effective_scope.canonical_mls_group_id().unwrap(),
            )
            .unwrap(),
            effective_scope,
            local_mls_leaves: vec![MlsSecurityFrontierLeaf {
                leaf_index: 0,
                actor_id: ActorId::account(AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                )),
                credential_ref: NonEmptyString::new("device-1").unwrap(),
            }],
            proof_base_basis: SealBasis {
                leaves: vec![SealId::new(
                    "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap()],
            },
            proof_target_basis: SealBasis {
                leaves: vec![SealId::new(
                    "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap()],
            },
            byte_limit: MLS_GOVERNANCE_PROOF_MAX_BYTES,
            frontier_purpose: MlsGovernanceFrontierPurpose::GroupBinding,
            base_group_state_ref: None,
            proposed_group_genesis_binding: Some(proposal),
            previous_epoch: 0,
            next_epoch: 0,
            binding_profile: MlsGovernanceBindingProfile::AkSecurityFrontierV1,
        }
    }

    #[test]
    fn genesis_binding_proposals_validate_all_registered_combinations() {
        for proposal in [
            ProposedMlsGroupGenesisBinding {
                content_scheme: ContentScheme::MlsRfc9420,
                durability_policy: None,
            },
            ProposedMlsGroupGenesisBinding {
                content_scheme: ContentScheme::MlsExporterAeadV1,
                durability_policy: Some(DurabilityPolicy::None),
            },
            ProposedMlsGroupGenesisBinding {
                content_scheme: ContentScheme::MlsExporterAeadV1,
                durability_policy: Some(DurabilityPolicy::OrganizationRecoveryKey),
            },
        ] {
            genesis_request(proposal).validate().unwrap();
        }
    }

    #[test]
    fn genesis_binding_proposal_is_part_of_query_digest_and_successor_forbids_it() {
        let rfc9420 = genesis_request(ProposedMlsGroupGenesisBinding {
            content_scheme: ContentScheme::MlsRfc9420,
            durability_policy: None,
        });
        let exporter = genesis_request(ProposedMlsGroupGenesisBinding {
            content_scheme: ContentScheme::MlsExporterAeadV1,
            durability_policy: Some(DurabilityPolicy::None),
        });
        assert_ne!(
            rfc9420.query_digest().unwrap(),
            exporter.query_digest().unwrap()
        );

        let mut successor = exporter;
        successor.previous_epoch = 1;
        successor.next_epoch = 2;
        successor.base_group_state_ref =
            Some(EventId::new("ak:event:AbnHJt4q4qY18zqvLiy3Emmqy7weTAuApx42RmRgPr2h").unwrap());
        assert!(successor.validate().is_err());
    }

    #[test]
    fn genesis_binding_proposal_rejects_mismatched_scheme_and_durability() {
        let invalid = genesis_request(ProposedMlsGroupGenesisBinding {
            content_scheme: ContentScheme::MlsRfc9420,
            durability_policy: Some(DurabilityPolicy::None),
        });
        assert!(invalid.validate().is_err());
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
#[serde(untagged, deny_unknown_fields)]
pub enum MlsGovernanceFrontierProjection {
    Merkle {
        frontier_registry_digest: Hash,
        branches: Vec<MlsGovernanceFrontierBranchProjection>,
    },
    Conclusions {
        frontier_registry_digest: Hash,
        conclusion_set: arkret_wire::SealConclusionSet,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierBranchProjection {
    pub target_seal_ref: SealId,
    pub state_root: Hash,
    pub cells: Vec<MlsGovernanceFrontierCellEntry>,
    pub range_witnesses: Vec<MlsGovernanceFrontierRangeWitness>,
}

impl MlsGovernanceFrontierProjection {
    pub fn frontier_registry_digest(&self) -> &Hash {
        match self {
            Self::Merkle {
                frontier_registry_digest,
                ..
            }
            | Self::Conclusions {
                frontier_registry_digest,
                ..
            } => frontier_registry_digest,
        }
    }

    pub fn branches(&self) -> &[MlsGovernanceFrontierBranchProjection] {
        match self {
            Self::Merkle { branches, .. } => branches,
            Self::Conclusions { .. } => &[],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Self::Conclusions { conclusion_set, .. } = self {
            return conclusion_set.validate_structural();
        }
        if self.branches().is_empty()
            || self
                .branches()
                .windows(2)
                .any(|pair| pair[0].target_seal_ref >= pair[1].target_seal_ref)
        {
            return schema("MLS governance frontier branches are not canonical");
        }
        for branch in self.branches() {
            branch.validate()?;
        }
        Ok(())
    }
}

impl MlsGovernanceFrontierBranchProjection {
    pub fn validate(&self) -> Result<()> {
        if self
            .cells
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
        for entry in &self.cells {
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
        let branch_seals = match &self.frontier_projection {
            MlsGovernanceFrontierProjection::Merkle { branches, .. } => branches
                .iter()
                .map(|branch| &branch.target_seal_ref)
                .collect::<BTreeSet<_>>(),
            MlsGovernanceFrontierProjection::Conclusions { conclusion_set, .. } => conclusion_set
                .conclusions
                .iter()
                .map(|certificate| &certificate.statement.target_seal_ref)
                .collect::<BTreeSet<_>>(),
        };
        let target_seals = request
            .proof_target_basis
            .leaves
            .iter()
            .collect::<BTreeSet<_>>();
        if branch_seals != target_seals {
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
        self.frontier_projection
            .branches()
            .iter()
            .flat_map(|branch| {
                branch
                    .cells
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
