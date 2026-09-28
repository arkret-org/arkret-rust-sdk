//! RFC 9420 validation for externally supplied public epoch state.
use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::base64url_encode;
use arkret_models_collaboration::events_payloads::mls_proposal_admission::MlsProposalSenderClass;
use arkret_wire::{ActorId, Base64UrlString};
use openmls::prelude::{
    GroupId, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    ProcessedMessageContent, ProposalStore, ProtocolMessage, PublicGroup, RatchetTreeIn, Sender,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::identity::decode_leaf_credential;
use crate::{MlsError as Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsPublicEndpointLeaf {
    pub leaf_index: u32,
    pub actor_id: ActorId,
    pub signature_key: Base64UrlString,
}

/// One Proposal actually consumed by a verified signed Commit. The ordinal
/// counts every RFC 9420 Proposal kind in the Commit's original wire order.
/// These fields are Station-private transition facts, not a roster wire DTO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsVerifiedConsumedProposal {
    pub ordinal: u64,
    pub proposal_ref: Vec<u8>,
    pub proposal_type: u16,
    pub proposal_wire: Vec<u8>,
    pub sender_leaf: MlsPublicEndpointLeaf,
    pub target_before: Option<MlsPublicEndpointLeaf>,
    pub target_after: Option<MlsPublicEndpointLeaf>,
}

/// Validate an MLSMessage carrying GroupInfo together with the exact external
/// ratchet tree, then return occupied leaves with their real tree indices.
///
/// `PublicGroup::from_external` verifies the GroupInfo signature, ratchet-tree
/// node semantics, tree hash, MLS version, leaf-node validity, and uniqueness
/// constraints. No leaves or tree bytes are accepted from a service assertion;
/// callers obtain these two byte strings only from the typed standard
/// group-state-material operation after its content-address checks pass.
pub fn validate_public_group_state(
    group_info_bytes: &[u8],
    ratchet_tree_bytes: &[u8],
    expected_mls_group_id: &str,
    expected_epoch: u64,
) -> Result<Vec<MlsPublicEndpointLeaf>> {
    validate_public_group_state_inner(
        group_info_bytes,
        ratchet_tree_bytes,
        expected_mls_group_id,
        expected_epoch,
    )
}

fn validate_public_group_state_inner(
    group_info_bytes: &[u8],
    ratchet_tree_bytes: &[u8],
    expected_mls_group_id: &str,
    expected_epoch: u64,
) -> Result<Vec<MlsPublicEndpointLeaf>> {
    MlsPublicGroupTracker::from_external(
        group_info_bytes,
        ratchet_tree_bytes,
        expected_mls_group_id,
        expected_epoch,
    )?
    .leaves()
}

fn build_public_tracker(
    group_info_bytes: &[u8],
    ratchet_tree_bytes: &[u8],
    expected_mls_group_id: &str,
    expected_epoch: u64,
) -> Result<MlsPublicGroupTracker> {
    let message = MlsMessageIn::tls_deserialize_exact(group_info_bytes).map_err(mls_error)?;
    let MlsMessageBodyIn::GroupInfo(group_info) = message.extract() else {
        return Err(Error::Protocol(
            "MLS group_info bytes do not contain an RFC 9420 GroupInfo message".to_owned(),
        ));
    };
    if base64url_encode(group_info.group_id().as_slice()) != expected_mls_group_id {
        return Err(Error::Protocol(
            "MLS GroupInfo group_id does not match accepted genesis".to_owned(),
        ));
    }
    if group_info.epoch().as_u64() != expected_epoch {
        return Err(Error::Protocol(
            "MLS GroupInfo epoch does not match accepted genesis".to_owned(),
        ));
    }

    let ratchet_tree =
        RatchetTreeIn::tls_deserialize_exact(ratchet_tree_bytes).map_err(mls_error)?;
    let provider = OpenMlsRustCrypto::default();
    let (public_group, _) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        ratchet_tree,
        group_info,
        ProposalStore::new(),
    )
    .map_err(mls_error)?;
    Ok(MlsPublicGroupTracker {
        provider,
        public_group,
    })
}

fn public_leaves(public_group: &PublicGroup) -> Result<Vec<MlsPublicEndpointLeaf>> {
    let mut leaves = public_group
        .members()
        .map(|member| {
            let actor_id = decode_leaf_credential(member.credential.serialized_content())?;
            Ok(MlsPublicEndpointLeaf {
                leaf_index: member.index.u32(),
                actor_id,
                signature_key: Base64UrlString::new(base64url_encode(
                    member.signature_key.as_slice(),
                ))
                .map_err(|error| Error::Protocol(error.to_owned()))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    leaves.sort_by_key(|leaf| leaf.leaf_index);
    if leaves.is_empty() {
        return Err(Error::Protocol(
            "MLS public group state contains no occupied leaves".to_owned(),
        ));
    }
    Ok(leaves)
}

fn mls_error(error: impl std::fmt::Debug) -> Error {
    Error::Protocol(format!(
        "MLS public group-state validation failed: {error:?}"
    ))
}

/// Public-only RFC 9420 observer. It holds no membership, epoch or path secrets.
/// It checks public signatures/structure/tree/transcripts; secret-dependent
/// membership and confirmation MAC verification remains a member obligation.
/// This type is not an alternate Arkret wire carrier.
pub struct MlsPublicGroupTracker {
    provider: OpenMlsRustCrypto,
    public_group: PublicGroup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsPublicHandshakeTransition {
    Proposal {
        proposal_ref: Vec<u8>,
        /// RFC 9420 ProposalType code, obtained from the signed message.
        proposal_type: u16,
        /// RFC 9420 sender class of the signed message.
        ///
        /// A `None` `sender_leaf` says only that there is no member leaf; it is
        /// neither an authorization nor a refusal. This field is the one that
        /// carries the admission decision, through
        /// [`arkret_models_collaboration::events_payloads::mls_proposal_admission::admit_inline_mls_proposal`].
        sender_class: MlsProposalSenderClass,
        /// Member signer at the exact base. None denotes a non-member sender;
        /// applications must authorize that separate class explicitly.
        sender_leaf: Option<MlsPublicEndpointLeaf>,
        add_key_package_bytes: Option<Vec<u8>>,
        remove_leaf_index: Option<u32>,
    },
    Commit {
        /// RFC 9420 sender class of the signed Commit. A `new_member_commit`
        /// sender is an external Commit, which v1 does not admit.
        sender_class: MlsProposalSenderClass,
        sender_leaf: Option<MlsPublicEndpointLeaf>,
        previous_epoch: u64,
        epoch: u64,
        /// Includes every inline Proposal actually consumed by the Commit.
        consumed_proposal_refs: Vec<Vec<u8>>,
        /// Exact verified inline Proposal bodies, wire ordinals, senders and
        /// pre/post leaf targets. A referenced Proposal is rejected in v1.
        consumed_proposals: Vec<MlsVerifiedConsumedProposal>,
        referenced_proposal_refs: Vec<Vec<u8>>,
        removed_leaf_indices: Vec<u32>,
        /// A remove followed by an add at the same index occurs in both lists.
        added_leaves: Vec<MlsPublicEndpointLeaf>,
        /// Staged Add identity for each installed leaf. External commits have
        /// no Add proposal; inline Add refs are not in referenced_proposal_refs.
        added_leaf_proposal_refs: Vec<(u32, Vec<u8>)>,
        updated_leaf_indices: Vec<u32>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicTrackerSnapshot {
    group_id: String,
    epoch: u64,
    storage_entries: BTreeMap<String, String>,
}

impl MlsPublicGroupTracker {
    pub fn from_external(
        group_info: &[u8],
        tree: &[u8],
        group_id: &str,
        epoch: u64,
    ) -> Result<Self> {
        let tracker = build_public_tracker(group_info, tree, group_id, epoch)?;
        tracker.ensure_supported_group_context_extensions()?;
        Ok(tracker)
    }
    pub fn group_id(&self) -> String {
        base64url_encode(self.public_group.group_id().as_slice())
    }
    /// Registry canonical name of the public GroupContext cipher suite.
    pub fn ciphersuite_name(&self) -> String {
        format!("{:?}", self.public_group.ciphersuite())
    }

    pub fn epoch(&self) -> u64 {
        self.public_group.group_context().epoch().as_u64()
    }
    /// Registered canonical id of the public GroupContext cipher suite
    /// (`mls-ciphersuite-registry.json`); a suite without a registered row
    /// fails closed.
    pub fn ciphersuite_canonical_id(&self) -> Result<&'static str> {
        if self.public_group.ciphersuite() == crate::ARKRET_MLS_CIPHERSUITE {
            Ok(crate::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID)
        } else {
            Err(Error::Protocol(
                "MLS public group uses a ciphersuite with no registered canonical_id".to_owned(),
            ))
        }
    }
    pub fn leaves(&self) -> Result<Vec<MlsPublicEndpointLeaf>> {
        public_leaves(&self.public_group)
    }
    pub fn ratchet_tree_bytes(&self) -> Result<Vec<u8>> {
        self.public_group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(mls_error)
    }
    /// The fixed `0xF1C0` governance binding of the current public
    /// GroupContext (encryption-and-audit.md §2.5.1). Genesis carries the
    /// `0 -> 0` binding; every accepted Commit replaces it with its own next
    /// epoch binding. A context without the extension is not a governed group.
    pub fn governance_binding(&self) -> Result<arkret_models_crypto::MlsGovernanceBindingPayload> {
        crate::group::decode_group_context_governance_binding(self.public_group.group_context())
    }
    /// Local persistence only. The caller binds this to its accepted base and
    /// commits snapshot + provenance atomically; this is not network evidence.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&PublicTrackerSnapshot {
            group_id: self.group_id(),
            epoch: self.epoch(),
            storage_entries: crate::group::snapshot_provider_storage(&self.provider)?,
        })?)
    }
    /// Restore only snapshots previously emitted by this public-only tracker.
    /// Do not accept arbitrary remote OpenMLS storage as an authenticated base.
    pub fn restore(bytes: &[u8], expected_group_id: &str, expected_epoch: u64) -> Result<Self> {
        let snapshot: PublicTrackerSnapshot = serde_json::from_slice(bytes)?;
        if snapshot.group_id != expected_group_id || snapshot.epoch != expected_epoch {
            return Err(Error::Protocol(
                "public tracker snapshot base mismatch".into(),
            ));
        }
        let provider = OpenMlsRustCrypto::default();
        crate::group::restore_provider_storage(&provider, &snapshot.storage_entries)?;
        let group_id = GroupId::from_slice(&arkret_canonical::base64url_decode(expected_group_id)?);
        let public_group = PublicGroup::load(provider.storage(), &group_id)
            .map_err(mls_error)?
            .ok_or_else(|| Error::Protocol("public tracker snapshot is incomplete".into()))?;
        if public_group.group_id() != &group_id
            || public_group.group_context().epoch().as_u64() != expected_epoch
        {
            return Err(Error::Protocol(
                "public tracker stored epoch mismatch".into(),
            ));
        }
        let tracker = Self {
            provider,
            public_group,
        };
        tracker.leaves()?;
        Ok(tracker)
    }
    /// Verify and install one public Proposal/Commit. Failure leaves the
    /// original state and queued proposals untouched.
    pub fn process_public_handshake(
        &mut self,
        bytes: &[u8],
    ) -> Result<MlsPublicHandshakeTransition> {
        let mut candidate = Self::restore(&self.export_state()?, &self.group_id(), self.epoch())?;
        let transition = candidate.process_inner(bytes)?;
        candidate.ensure_supported_group_context_extensions()?;
        *self = candidate;
        Ok(transition)
    }

    fn ensure_supported_group_context_extensions(&self) -> Result<()> {
        if self
            .public_group
            .group_context()
            .extensions()
            .external_senders()
            .is_some()
        {
            return Err(Error::UnsupportedFeature(
                "v1 forbids the external_senders GroupContext extension".to_owned(),
            ));
        }
        Ok(())
    }
    fn process_inner(&mut self, bytes: &[u8]) -> Result<MlsPublicHandshakeTransition> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(mls_error)?;
        if message.tls_serialize_detached().map_err(mls_error)? != bytes {
            return Err(Error::Protocol(
                "public MLSMessage does not round-trip to its exact signed wire".into(),
            ));
        }
        let MlsMessageBodyIn::PublicMessage(message) = message.extract() else {
            return Err(Error::Protocol(
                "public MLS tracker requires PublicMessage Proposal/Commit".into(),
            ));
        };
        let previous_epoch = self.epoch();
        let previous_leaves = self
            .leaves()?
            .into_iter()
            .map(|leaf| (leaf.leaf_index, leaf))
            .collect::<BTreeMap<_, _>>();
        let processed = self
            .public_group
            .process_message(
                self.provider.crypto(),
                ProtocolMessage::PublicMessage(Box::new(message)),
            )
            .map_err(mls_error)?;
        let sender = processed.sender().clone();
        let sender_class = match &sender {
            Sender::Member(_) => MlsProposalSenderClass::Member,
            Sender::External(_) => MlsProposalSenderClass::External,
            Sender::NewMemberProposal => MlsProposalSenderClass::NewMemberProposal,
            Sender::NewMemberCommit => MlsProposalSenderClass::NewMemberCommit,
        };
        let sender_leaf = match &sender {
            Sender::Member(index) => Some(
                previous_leaves
                    .get(&index.u32())
                    .ok_or_else(|| {
                        Error::Protocol("public handshake sender leaf is absent".into())
                    })?
                    .clone(),
            ),
            _ => None,
        };
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                let proposal_ref = proposal
                    .proposal_reference_ref()
                    .tls_serialize_detached()
                    .map_err(mls_error)?;
                let proposal_type = u16::from(proposal.proposal().proposal_type());
                let add_key_package_bytes = match proposal.proposal() {
                    openmls::prelude::Proposal::Add(add) => Some(
                        add.key_package()
                            .tls_serialize_detached()
                            .map_err(mls_error)?,
                    ),
                    _ => None,
                };
                let remove_leaf_index = match proposal.proposal() {
                    openmls::prelude::Proposal::Remove(remove) => Some(remove.removed().u32()),
                    _ => None,
                };
                self.public_group
                    .add_proposal(self.provider.storage(), *proposal)
                    .map_err(mls_error)?;
                Ok(MlsPublicHandshakeTransition::Proposal {
                    proposal_ref,
                    proposal_type,
                    sender_class,
                    sender_leaf,
                    add_key_package_bytes,
                    remove_leaf_index,
                })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // OpenMLS StagedCommit::queued_proposals preserves the original
                // Commit.proposals[] order. The parsed MLSMessage above must
                // round-trip to the exact signed input before we use that
                // verified queue as the historical ordinal/body source.
                let mut consumed_proposals = Vec::new();
                for (ordinal, proposal) in staged.queued_proposals().enumerate() {
                    if proposal.proposal_or_ref_type()
                        == openmls::prelude::ProposalOrRefType::Reference
                    {
                        return Err(Error::UnsupportedFeature(
                            "v1 Commit cannot consume a referenced Proposal".to_owned(),
                        ));
                    }
                    let Sender::Member(sender_index) = proposal.sender() else {
                        return Err(Error::UnsupportedFeature(
                            "v1 Commit Proposal sender must be a member".to_owned(),
                        ));
                    };
                    let sender_leaf = previous_leaves
                        .get(&sender_index.u32())
                        .ok_or_else(|| {
                            Error::Protocol("consumed Proposal sender leaf is absent".into())
                        })?
                        .clone();
                    let target_before = match proposal.proposal() {
                        openmls::prelude::Proposal::Add(_)
                        | openmls::prelude::Proposal::PreSharedKey(_)
                        | openmls::prelude::Proposal::GroupContextExtensions(_) => None,
                        openmls::prelude::Proposal::Remove(remove) => Some(
                            previous_leaves
                                .get(&remove.removed().u32())
                                .ok_or_else(|| {
                                    Error::Protocol("removed Proposal target leaf is absent".into())
                                })?
                                .clone(),
                        ),
                        openmls::prelude::Proposal::Update(_) => Some(sender_leaf.clone()),
                        _ => {
                            return Err(Error::UnsupportedFeature(
                                "v1 Commit contains an unsupported Proposal kind".to_owned(),
                            ));
                        }
                    };
                    consumed_proposals.push(MlsVerifiedConsumedProposal {
                        ordinal: u64::try_from(ordinal).map_err(mls_error)?,
                        proposal_ref: proposal
                            .proposal_reference_ref()
                            .tls_serialize_detached()
                            .map_err(mls_error)?,
                        proposal_type: u16::from(proposal.proposal().proposal_type()),
                        proposal_wire: proposal
                            .proposal()
                            .tls_serialize_detached()
                            .map_err(mls_error)?,
                        sender_leaf,
                        target_before,
                        target_after: None,
                    });
                }
                let mut removed = staged
                    .remove_proposals()
                    .map(|p| p.remove_proposal().removed().u32())
                    .collect::<Vec<_>>();
                removed.sort();
                removed.dedup();
                let mut updated = staged
                    .update_proposals()
                    .filter_map(|p| {
                        if let Sender::Member(index) = p.sender() {
                            Some(index.u32())
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeSet<_>>();
                if staged.update_path_leaf_node().is_some() {
                    if let Sender::Member(index) = sender {
                        updated.insert(index.u32());
                    }
                }
                let mut additions = staged
                    .queued_proposals()
                    .filter_map(|proposal| match proposal.proposal() {
                        openmls::prelude::Proposal::Add(add) => Some((add, proposal)),
                        _ => None,
                    })
                    .map(|(add, proposal)| {
                        Ok((
                            add.key_package()
                                .leaf_node()
                                .tls_serialize_detached()
                                .map_err(mls_error)?,
                            Some(
                                proposal
                                    .proposal_reference_ref()
                                    .tls_serialize_detached()
                                    .map_err(mls_error)?,
                            ),
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                if matches!(sender, Sender::NewMemberCommit) {
                    let path = staged.update_path_leaf_node().ok_or_else(|| {
                        Error::Protocol("external commit omitted its public leaf".into())
                    })?;
                    additions.push((path.tls_serialize_detached().map_err(mls_error)?, None));
                }
                let referenced_proposal_refs = staged
                    .queued_proposals()
                    .filter(|p| {
                        p.proposal_or_ref_type() == openmls::prelude::ProposalOrRefType::Reference
                    })
                    .map(|p| {
                        p.proposal_reference_ref()
                            .tls_serialize_detached()
                            .map_err(mls_error)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let consumed_proposal_refs = staged
                    .queued_proposals()
                    .map(|p| {
                        p.proposal_reference_ref()
                            .tls_serialize_detached()
                            .map_err(mls_error)
                    })
                    .collect::<Result<Vec<_>>>()?;
                self.public_group
                    .merge_commit(self.provider.storage(), *staged)
                    .map_err(mls_error)?;
                if self.epoch()
                    != previous_epoch
                        .checked_add(1)
                        .ok_or_else(|| Error::Protocol("MLS epoch overflow".into()))?
                {
                    return Err(Error::Protocol(
                        "public commit did not advance one epoch".into(),
                    ));
                }
                let mut added_leaves = Vec::new();
                let mut added_leaf_proposal_refs = Vec::new();
                for leaf in self.leaves()? {
                    if !removed.contains(&leaf.leaf_index)
                        && previous_leaves
                            .get(&leaf.leaf_index)
                            .is_some_and(|previous| {
                                previous.actor_id != leaf.actor_id
                                    || previous.signature_key != leaf.signature_key
                            })
                    {
                        return Err(Error::Protocol(
                            "MLS credential or signature-key replacement requires Remove+Add"
                                .into(),
                        ));
                    }
                    let node = self
                        .public_group
                        .leaf(LeafNodeIndex::new(leaf.leaf_index))
                        .ok_or_else(|| Error::Protocol("public leaf disappeared".into()))?;
                    let node_bytes = node.tls_serialize_detached().map_err(mls_error)?;
                    let matches = additions
                        .iter()
                        .filter(|(bytes, _)| bytes == &node_bytes)
                        .collect::<Vec<_>>();
                    if matches.len() > 1 {
                        return Err(Error::Protocol(
                            "multiple staged Adds match one public leaf".into(),
                        ));
                    }
                    if let Some((_, proposal_ref)) = matches.first() {
                        if let Some(proposal_ref) = proposal_ref {
                            added_leaf_proposal_refs.push((leaf.leaf_index, proposal_ref.clone()));
                        }
                        updated.remove(&leaf.leaf_index);
                        added_leaves.push(leaf);
                    }
                }
                if added_leaves.len() != additions.len() {
                    return Err(Error::Protocol(
                        "staged Add proposals do not match installed public leaves".into(),
                    ));
                }
                for proposal in &mut consumed_proposals {
                    match proposal.proposal_type {
                        1 => {
                            let matches = added_leaf_proposal_refs
                                .iter()
                                .filter(|(_, reference)| reference == &proposal.proposal_ref)
                                .collect::<Vec<_>>();
                            if matches.len() != 1 {
                                return Err(Error::Protocol(
                                    "consumed Add has no unique installed leaf".into(),
                                ));
                            }
                            proposal.target_after = Some(
                                added_leaves
                                    .iter()
                                    .find(|leaf| leaf.leaf_index == matches[0].0)
                                    .ok_or_else(|| {
                                        Error::Protocol("installed Add leaf disappeared".into())
                                    })?
                                    .clone(),
                            );
                        }
                        2 => {
                            let before = proposal.target_before.as_ref().ok_or_else(|| {
                                Error::Protocol("Update has no prior target leaf".into())
                            })?;
                            proposal.target_after = Some(
                                self.leaves()?
                                    .into_iter()
                                    .find(|leaf| leaf.leaf_index == before.leaf_index)
                                    .ok_or_else(|| {
                                        Error::Protocol("updated target leaf disappeared".into())
                                    })?,
                            );
                        }
                        _ => {}
                    }
                }
                for index in &removed {
                    updated.remove(index);
                }
                Ok(MlsPublicHandshakeTransition::Commit {
                    sender_class,
                    sender_leaf,
                    previous_epoch,
                    epoch: self.epoch(),
                    consumed_proposal_refs,
                    consumed_proposals,
                    referenced_proposal_refs,
                    removed_leaf_indices: removed,
                    added_leaves,
                    added_leaf_proposal_refs,
                    updated_leaf_indices: updated.into_iter().collect(),
                })
            }
            _ => Err(Error::Protocol(
                "public MLS tracker rejects non-handshake content".into(),
            )),
        }
    }
}
