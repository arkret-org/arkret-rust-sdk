use arkret_wire::{
    Base64UrlString, ControlProposalAck, DeviceId, DidCoreId, DidFullId, Event, EventId, Hash,
    IdempotencyKey, PrincipalAuthorityKey, ProtocolOpaqueId, ProtocolOperationId,
    ProtocolSignature, ReservationHandle,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::peer_contact::{ContactIntroductionEvidence, PeerContactAddress};
use crate::string_marker;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum StandardHolderBinding {
    HumanDevice {
        device_binding: ProtocolOpaqueId,
    },
    AgentRuntime {
        agent_id: DidCoreId,
        device_id: DeviceId,
        agent_key_authorization_ref: EventId,
        verification_method: arkret_wire::DidUrl,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactPeer {
    Human {
        principal_id: DidCoreId,
    },
    Agent {
        agent_id: DidCoreId,
        controller_id: DidCoreId,
    },
}

impl ContactPeer {
    /// Normalize a Contact participant to the actor role used by pair ordering
    /// and Contact receipts. Human principals are actors in this protocol
    /// context; this explicit conversion prevents a generic cross-role `From`.
    pub fn contact_actor_id(&self) -> DidCoreId {
        match self {
            Self::Human { principal_id } => DidCoreId::new(principal_id.as_str())
                .expect("validated principal core is a valid actor core"),
            Self::Agent { agent_id, .. } => agent_id.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactScope {
    Invite,
    DirectMessage,
    VoiceCall,
    VideoCall,
    Presence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RequestAcceptanceReceiptCore {
    pub holder: ContactPeer,
    pub peer: ContactPeer,
    pub slot_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_predecessor: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_contact_round_id: Option<Hash>,
    pub request_event_ref: EventId,
    pub request_digest: Hash,
    pub source_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: DidCoreId,
}

impl RequestAcceptanceReceiptCore {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.slot_version == 0
            || (self.slot_version == 1) == self.slot_predecessor.is_some()
            || self.holder.contact_actor_id() == self.peer.contact_actor_id()
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid Contact request acceptance receipt core".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RequestAcceptanceReceipt {
    pub core: RequestAcceptanceReceiptCore,
    pub receipt_digest: Hash,
    pub signature: ProtocolSignature,
}

impl RequestAcceptanceReceipt {
    /// Digest of the closed receipt core covered by `signature`.
    pub fn computed_core_digest(&self) -> arkret_wire::Result<Hash> {
        let mut bytes = b"ak.contact.request_acceptance_core.v1\n".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&self.core)?);
        Hash::new(arkret_canonical::sha256_digest(bytes)).map_err(Into::into)
    }

    /// RFC 8785/JCS digest of the complete signed receipt used by Contact round
    /// payloads and receipt-to-Event bindings.
    pub fn computed_receipt_digest(&self) -> arkret_wire::Result<Hash> {
        Hash::new(arkret_canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    /// Validate the closed core and its non-recursive digest layer. Historical
    /// issuer-key and signature verification remains a separate cryptographic
    /// step because it needs the issuer DID document at `accepted_at`.
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        self.core.validate()?;
        if self.computed_core_digest()? != self.receipt_digest {
            return Err(arkret_wire::WireError::Protocol(
                "Contact request acceptance receipt core digest mismatch".to_owned(),
            ));
        }
        let signer = self
            .signature
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol(
                    "Contact request acceptance receipt signer is not a DID URL".to_owned(),
                )
            })?;
        let signer = DidFullId::new(signer)
            .and_then(|full_id| arkret_wire::project_full_id_to_core_id(&full_id))?;
        if signer != self.core.issuer {
            return Err(arkret_wire::WireError::Protocol(
                "Contact request acceptance receipt signer is not its issuer".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exact issuer-local successor cursor copied from an accepted Contact list
/// projection into the next scope-update or tombstone prepare request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactNextPrepareInput {
    pub contact_round_id: Hash,
    /// Version carried by the *next* Event, so it starts at two.
    pub version: u64,
    /// Current accepted lineage head, used as the next Event predecessor.
    pub predecessor_event_ref: EventId,
}

impl ContactNextPrepareInput {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if self.version < 2 {
            return Err(arkret_wire::WireError::Protocol(
                "Contact next_prepare_input.version must be at least 2".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactCurrentProof {
    pub contact_round_id: Hash,
    pub issuer: DidCoreId,
    pub terminal: bool,
    pub head_event_ref: EventId,
    pub head_digest: Hash,
    pub accepted_frontier: Vec<EventId>,
    pub complete_through: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fresh_until: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

impl ContactCurrentProof {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        canonical_signing_bytes_without_signature(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRoundRequestRef {
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactRound {
    Normal {
        sorted_pair_members: [DidCoreId; 2],
        request_event_ref: EventId,
        request_acceptance_receipt_digest: Hash,
    },
    Glare {
        sorted_pair_members: [DidCoreId; 2],
        requests: [ContactRoundRequestRef; 2],
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NormalResponseAcceptanceReceipt {
    pub contact_round_id: Hash,
    pub request_receipt: RequestAcceptanceReceipt,
    pub response_event_ref: EventId,
    pub response_digest: Hash,
    pub outgoing_slot_absence_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: DidCoreId,
    pub signature: ProtocolSignature,
}

impl NormalResponseAcceptanceReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        canonical_signing_bytes_without_signature(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RejectAcceptanceReceipt {
    pub request_receipt: RequestAcceptanceReceipt,
    pub reject_event_ref: EventId,
    pub reject_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: DidCoreId,
    pub signature: ProtocolSignature,
}

impl RejectAcceptanceReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        canonical_signing_bytes_without_signature(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactLineage {
    pub contact_round_id: Hash,
    pub issuer: ContactPeer,
    pub peer: ContactPeer,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_event_ref: Option<EventId>,
    pub event_ref: EventId,
    pub granted_to_peer_scopes: Vec<ContactScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactCommitRequestBody {
    pub phase: ContactCommitPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub reservation_handle: ReservationHandle,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub signed_event: Event,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proposal_ack: Option<ControlProposalAck>,
}

string_marker!(ContactCommitPhase, Commit, "commit");
string_marker!(ContactPreparePhase, Prepare, "prepare");
string_marker!(ContactAcceptAction, Accept, "accept");
string_marker!(ContactRejectAction, Reject, "reject");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
    pub granted_to_peer_scopes: Vec<ContactScope>,
    pub introduction_evidence: ContactIntroductionEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_contact_round_id: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_evidence: Option<ContactContinuityEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactOperationRequestBody {
    Prepare(ContactPrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactScopeUpdatePrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
    pub contact_round_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub granted_to_peer_scopes: Vec<ContactScope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactScopeUpdateRequestBody {
    Prepare(ContactScopeUpdatePrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRoundEvidenceBundle {
    pub contact_round_id: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_contact_round_id: Option<Hash>,
    pub contact_round: ContactRound,
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_response_receipt: Option<NormalResponseAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glare_concurrency_attestations: Option<[GlareConcurrencyAttestation; 2]>,
    pub current_proofs: Vec<ContactCurrentProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_checkpoint: Option<BilateralContinuityCheckpoint>,
}

pub const BILATERAL_CONTINUITY_CHECKPOINT_DOMAIN: &[u8] =
    b"ak.bilateral-continuity.checkpoint.v1\n";
pub const BILATERAL_CONTINUITY_ACCUMULATOR_DOMAIN: &[u8] =
    b"ak.bilateral-continuity.accumulator.v1\n";
pub const CONTACT_CONTINUITY_CONTEXT: &str = "ak.contact.round.continuity.v1";

/// Mutually signed commitment to a contiguous bilateral Contact lineage
/// prefix. The current v1 schema closes `root_basis` to one uncheckpointed
/// Contact round bundle; a future domain-neutral carrier must register its
/// own typed branch instead of reopening this field as arbitrary JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BilateralContinuityCheckpointCore {
    pub context: String,
    pub participants: [PrincipalAuthorityKey; 2],
    #[serde(deserialize_with = "deserialize_uncheckpointed_root_basis")]
    pub root_basis: Box<ContactRoundEvidenceBundle>,
    pub root_basis_digest: Hash,
    /// Contact round id at the compacted-prefix boundary. The first omitted
    /// tail edge points to this value; bundle content digests remain confined
    /// to `prefix_accumulator_root`.
    pub covered_through_contact_round_id: Hash,
    pub prefix_accumulator_root: Hash,
    pub covered_prefix_count: u64,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_digest: Option<Hash>,
}

fn deserialize_uncheckpointed_root_basis<'de, D>(
    deserializer: D,
) -> Result<Box<ContactRoundEvidenceBundle>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.get("continuity_checkpoint").is_some() {
        return Err(serde::de::Error::custom(
            "checkpoint root_basis must be an uncheckpointed Contact round bundle",
        ));
    }
    serde_json::from_value(value)
        .map(Box::new)
        .map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BilateralContinuityCheckpointSignature {
    pub signer: PrincipalAuthorityKey,
    pub signature: ProtocolSignature,
}

/// One-sided proposal carried to the other participant's Principal Server.
/// It is not portable continuity evidence until the counterparty has verified
/// the exact core, appended its signature and durably committed the completed
/// checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BilateralContinuityCheckpointProposal {
    pub core: BilateralContinuityCheckpointCore,
    pub checkpoint_digest: Hash,
    pub proposer_signature: BilateralContinuityCheckpointSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BilateralContinuityCheckpoint {
    pub core: BilateralContinuityCheckpointCore,
    pub checkpoint_digest: Hash,
    pub signatures: [BilateralContinuityCheckpointSignature; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactContinuityEvidence {
    pub checkpoint: BilateralContinuityCheckpoint,
    pub uncompressed_tail: Vec<ContactRoundEvidenceBundle>,
}

/// Holder-authorized request to compact the oldest contiguous terminal prefix
/// of one durable Contact lineage. The service chooses the exact boundary
/// deterministically from its accepted history; callers never submit a core.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactContinuityCheckpointRequestBody {
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactContinuityCheckpointStatus {
    Pending,
    Committed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactContinuityCheckpointOutcome {
    pub status: ContactContinuityCheckpointStatus,
    pub checkpoint_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_evidence: Option<ContactContinuityEvidence>,
}

impl BilateralContinuityCheckpoint {
    pub fn signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        bilateral_checkpoint_signing_bytes(&self.core)
    }

    pub fn recompute_digest(&self) -> arkret_wire::Result<Hash> {
        bilateral_checkpoint_digest(&self.core)
    }

    pub fn validate_contact_shape(&self) -> arkret_wire::Result<ContactRoundEvidenceBundle> {
        if self.core.context != CONTACT_CONTINUITY_CONTEXT
            || self.core.covered_prefix_count == 0
            || self.core.sequence == 0
            || (self.core.sequence == 1) == self.core.previous_checkpoint_digest.is_some()
            || self.core.participants[0] >= self.core.participants[1]
            || self.signatures[0].signer >= self.signatures[1].signer
            || self.signatures[0].signer != self.core.participants[0]
            || self.signatures[1].signer != self.core.participants[1]
            || self.recompute_digest()? != self.checkpoint_digest
        {
            return Err(arkret_wire::WireError::Protocol(
                "continuity_invalid: bilateral checkpoint shape or digest mismatch".to_owned(),
            ));
        }
        let root = self.core.root_basis.as_ref().clone();
        let root_digest = Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&root).map_err(|error| {
                arkret_wire::WireError::Protocol(format!(
                    "continuity_invalid: root basis canonicalization failed: {error}"
                ))
            })?,
        ))?;
        if root.previous_terminal_contact_round_id.is_some()
            || root.continuity_checkpoint.is_some()
            || root_digest != self.core.root_basis_digest
        {
            return Err(arkret_wire::WireError::Protocol(
                "continuity_invalid: checkpoint root basis mismatch".to_owned(),
            ));
        }
        Ok(root)
    }
}

impl BilateralContinuityCheckpointProposal {
    pub fn signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        bilateral_checkpoint_signing_bytes(&self.core)
    }

    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if self.core.context != CONTACT_CONTINUITY_CONTEXT
            || self.core.covered_prefix_count == 0
            || self.core.sequence == 0
            || (self.core.sequence == 1) == self.core.previous_checkpoint_digest.is_some()
            || self.core.participants[0] >= self.core.participants[1]
            || self.proposer_signature.signer != self.core.participants[0]
                && self.proposer_signature.signer != self.core.participants[1]
            || bilateral_checkpoint_digest(&self.core)? != self.checkpoint_digest
        {
            return Err(arkret_wire::WireError::Protocol(
                "continuity_invalid: bilateral checkpoint proposal mismatch".to_owned(),
            ));
        }
        let root = self.core.root_basis.as_ref();
        let root_digest = Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(root).map_err(|error| {
                arkret_wire::WireError::Protocol(format!(
                    "continuity_invalid: root basis canonicalization failed: {error}"
                ))
            })?,
        ))?;
        if root.previous_terminal_contact_round_id.is_some()
            || root.continuity_checkpoint.is_some()
            || root_digest != self.core.root_basis_digest
        {
            return Err(arkret_wire::WireError::Protocol(
                "continuity_invalid: checkpoint proposal root basis mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

fn bilateral_checkpoint_signing_bytes(
    core: &BilateralContinuityCheckpointCore,
) -> arkret_canonical::Result<Vec<u8>> {
    let canonical = arkret_canonical::canonical_json_bytes(core)?;
    let mut material =
        Vec::with_capacity(BILATERAL_CONTINUITY_CHECKPOINT_DOMAIN.len() + canonical.len());
    material.extend_from_slice(BILATERAL_CONTINUITY_CHECKPOINT_DOMAIN);
    material.extend_from_slice(&canonical);
    Ok(material)
}

pub fn bilateral_checkpoint_digest(
    core: &BilateralContinuityCheckpointCore,
) -> arkret_wire::Result<Hash> {
    let material = bilateral_checkpoint_signing_bytes(core)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    Ok(Hash::new(arkret_canonical::sha256_digest(material))?)
}

#[cfg(test)]
mod bilateral_checkpoint_shape_tests {
    use super::*;

    #[test]
    fn root_basis_rejects_nested_checkpoint_before_recursive_decode() {
        let mut deserializer =
            serde_json::Deserializer::from_str(r#"{"continuity_checkpoint":{}}"#);
        let error = deserialize_uncheckpointed_root_basis(&mut deserializer).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must be an uncheckpointed Contact round")
        );
    }
}

pub fn bilateral_prefix_accumulator(
    previous: Option<&Hash>,
    covered_basis_digests: &[Hash],
) -> arkret_wire::Result<Hash> {
    if covered_basis_digests.is_empty() {
        return Err(arkret_wire::WireError::Protocol(
            "continuity_invalid: accumulator extension is empty".to_owned(),
        ));
    }
    #[derive(Serialize)]
    struct Material<'a> {
        previous: Option<&'a Hash>,
        covered_basis_digests: &'a [Hash],
    }
    let canonical = arkret_canonical::canonical_json_bytes(&Material {
        previous,
        covered_basis_digests,
    })
    .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    let mut material =
        Vec::with_capacity(BILATERAL_CONTINUITY_ACCUMULATOR_DOMAIN.len() + canonical.len());
    material.extend_from_slice(BILATERAL_CONTINUITY_ACCUMULATOR_DOMAIN);
    material.extend_from_slice(&canonical);
    Ok(Hash::new(arkret_canonical::sha256_digest(material))?)
}

pub fn validate_recontact_continuity(
    current: &ContactRoundEvidenceBundle,
    predecessors: &[ContactRoundEvidenceBundle],
) -> arkret_wire::Result<()> {
    if predecessors.len() > 64 {
        return Err(arkret_wire::WireError::Protocol(
            "Contact round continuity exceeds 64 predecessors".to_owned(),
        ));
    }
    let mut expected = current.previous_terminal_contact_round_id.as_ref();
    if current
        .request_receipts
        .iter()
        .any(|receipt| receipt.core.previous_terminal_contact_round_id.as_ref() != expected)
    {
        return Err(arkret_wire::WireError::Protocol(
            "current Contact request receipt continuity pointer mismatch".to_owned(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(current.contact_round_id.clone());
    for predecessor in predecessors {
        if expected != Some(&predecessor.contact_round_id)
            || predecessor.current_proofs.len() != 2
            || predecessor.current_proofs.iter().any(|proof| {
                !proof.terminal || proof.contact_round_id != predecessor.contact_round_id
            })
            || !seen.insert(predecessor.contact_round_id.clone())
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid Contact terminal contact_round continuity edge".to_owned(),
            ));
        }
        if predecessor.request_receipts.iter().any(|receipt| {
            receipt.core.previous_terminal_contact_round_id
                != predecessor.previous_terminal_contact_round_id
        }) {
            return Err(arkret_wire::WireError::Protocol(
                "predecessor Contact request receipt continuity pointer mismatch".to_owned(),
            ));
        }
        if predecessor
            .continuity_checkpoint
            .as_ref()
            .is_some_and(|checkpoint| {
                current
                    .continuity_checkpoint
                    .as_ref()
                    .is_some_and(|current| {
                        current.checkpoint_digest != checkpoint.checkpoint_digest
                    })
            })
        {
            return Err(arkret_wire::WireError::Protocol(
                "continuity_invalid: tail checkpoint binding changed".to_owned(),
            ));
        }
        expected = predecessor.previous_terminal_contact_round_id.as_ref();
    }
    if let Some(checkpoint) = &current.continuity_checkpoint {
        let root = checkpoint.validate_contact_shape()?;
        let current_pair = contact_round_participants(&current.contact_round);
        let root_pair = contact_round_participants(&root.contact_round);
        let checkpoint_pair = [
            checkpoint.core.participants[0].principal_id.clone(),
            checkpoint.core.participants[1].principal_id.clone(),
        ];
        if current_pair != root_pair
            || root_pair != checkpoint_pair
            || expected != Some(&checkpoint.core.covered_through_contact_round_id)
        {
            return Err(arkret_wire::WireError::Protocol(
                "continuity_invalid: checkpoint pair, root or tail terminator mismatch".to_owned(),
            ));
        }
    } else if expected.is_some()
        || (current.previous_terminal_contact_round_id.is_some() && predecessors.is_empty())
    {
        return Err(arkret_wire::WireError::Protocol(
            "continuity_evidence_unavailable: Contact continuity does not reach its root"
                .to_owned(),
        ));
    }
    Ok(())
}

fn contact_round_participants(round: &ContactRound) -> [DidCoreId; 2] {
    match round {
        ContactRound::Normal {
            sorted_pair_members,
            ..
        }
        | ContactRound::Glare {
            sorted_pair_members,
            ..
        } => sorted_pair_members.clone(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactAcceptPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub request_receipt: RequestAcceptanceReceipt,
    pub action: ContactAcceptAction,
    pub granted_to_peer_scopes: Vec<ContactScope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactAcceptRequestBody {
    Prepare(ContactAcceptPrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRejectPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub request_receipt: RequestAcceptanceReceipt,
    pub action: ContactRejectAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactRejectRequestBody {
    Prepare(ContactRejectPrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactTombstonePrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
    pub contact_round_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub block_peer: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactTombstoneRequestBody {
    Prepare(ContactTombstonePrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

string_marker!(
    ContactScopeUpdateSchema,
    V1,
    "ak.schema.contact_scope_update.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactScopeUpdatePayload {
    pub schema: ContactScopeUpdateSchema,
    pub peer: ContactPeer,
    pub contact_round_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub granted_to_peer_scopes: Vec<ContactScope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactOperationRejectReason {
    ContactIdempotencyConflict,
    ContactRoundConflict,
    ContactLineageConflict,
    ContactTerminal,
    ContactScopeStale,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactPreparedEventDraft {
    pub event_id: EventId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub kind: arkret_wire::EventKind,
    pub unsigned_event_bytes: Base64UrlString,
    pub event_digest: Hash,
}

impl ContactPreparedEventDraft {
    /// Reconstruct the prepared Event and prove it carries its own identity.
    ///
    /// The result is an [`AuthoredEvent`]: authoring finished on the preparing
    /// side, so the holder's only remaining job is to sign it. Nothing here may
    /// re-derive the id — that would silently accept a draft the preparer never
    /// committed to.
    pub fn unsigned_event(&self) -> arkret_wire::Result<arkret_wire::AuthoredEvent> {
        let bytes =
            arkret_canonical::base64url_decode(self.unsigned_event_bytes.as_str().as_bytes())?;
        let digest_suite = self.event_digest.digest_suite().map_err(|error| {
            arkret_wire::WireError::Protocol(format!(
                "prepared Contact Event digest is invalid: {error}"
            ))
        })?;
        let event = Event::from_digest_payload_bytes(&bytes, digest_suite)?;
        if event.event_id != self.event_id
            || event.kind != self.kind
            || Hash::new(event.event_digest_with_digest_suite(digest_suite)?)? != self.event_digest
        {
            return Err(arkret_wire::WireError::Protocol(
                "prepared Contact Event metadata does not match unsigned_event_bytes".to_owned(),
            ));
        }
        event.validate_for_authoring_structural()?;
        arkret_wire::AuthoredEvent::from_verified_with_digest_suite(event, digest_suite)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactResultKind {
    Request,
    Response,
    Reject,
    ScopeUpdate,
    Tombstone,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactPreparedOutcome {
    Request {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Response {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Reject {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    ScopeUpdate {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Tombstone {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactAcceptedOutcome {
    Request {
        operation_id: ProtocolOperationId,
        request_acceptance_receipt: RequestAcceptanceReceipt,
    },
    Response {
        operation_id: ProtocolOperationId,
        normal_response_acceptance_receipt: NormalResponseAcceptanceReceipt,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
    },
    Reject {
        operation_id: ProtocolOperationId,
        reject_acceptance_receipt: RejectAcceptanceReceipt,
    },
    ScopeUpdate {
        operation_id: ProtocolOperationId,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
    },
    Tombstone {
        operation_id: ProtocolOperationId,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactFailedOutcome {
    pub result_kind: ContactResultKind,
    pub operation_id: ProtocolOperationId,
    pub reason: ContactOperationRejectReason,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ContactOperationOutcome {
    Prepared {
        #[serde(flatten)]
        outcome: ContactPreparedOutcome,
    },
    Accepted {
        #[serde(flatten)]
        outcome: ContactAcceptedOutcome,
    },
    Failed {
        #[serde(flatten)]
        outcome: ContactFailedOutcome,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[allow(clippy::large_enum_variant)]
pub enum PeerContactSubmitRequestBody {
    Request {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        request_receipt: RequestAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
        introduction_evidence: ContactIntroductionEvidence,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
    Response {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        response_receipt: NormalResponseAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
    Reject {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        reject_receipt: RejectAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    ScopeUpdate {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    Tombstone {
        idempotency_key: IdempotencyKey,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    ProofRefresh {
        idempotency_key: IdempotencyKey,
        prior_mirror_receipt: PeerContactMirrorReceipt,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    GlareFinalize {
        idempotency_key: IdempotencyKey,
        contact_round_id: Hash,
        contact_round: ContactRound,
        request_receipts: [RequestAcceptanceReceipt; 2],
        remote_mirror_receipt: PeerContactMirrorReceipt,
        glare_concurrency_attestation: GlareConcurrencyAttestation,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    ContinuityCheckpoint {
        idempotency_key: IdempotencyKey,
        proposal: BilateralContinuityCheckpointProposal,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct GlareConcurrencyAttestation {
    pub issuer: DidCoreId,
    pub peer: DidCoreId,
    pub request_receipt_digests: [Hash; 2],
    pub observed_frontier: Vec<EventId>,
    pub complete_through: u64,
    pub unconsumed_slot_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

impl GlareConcurrencyAttestation {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        canonical_signing_bytes_without_signature(self)
    }
}

string_marker!(
    PeerContactMirrorReceiptDomain,
    V1,
    "ak.peer_contact.mirror_receipt.v1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactOutcome {
    Accepted,
    Duplicate,
    Deferred,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactMirrorReceipt {
    pub domain: PeerContactMirrorReceiptDomain,
    pub request_digest: Hash,
    pub signed_event_ref: EventId,
    pub signed_event_digest: Hash,
    pub outcome: PeerContactOutcome,
    pub recipient_service_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer: DidCoreId,
    pub signature: ProtocolSignature,
}

impl PeerContactMirrorReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        canonical_signing_bytes_without_signature(self)
    }
}

fn canonical_signing_bytes_without_signature(
    value: &impl Serialize,
) -> arkret_canonical::Result<Vec<u8>> {
    let mut unsigned = serde_json::to_value(value)?;
    let object = unsigned.as_object_mut().ok_or_else(|| {
        arkret_canonical::CanonicalError::Protocol(
            "signed Contact evidence must serialize as an object".to_owned(),
        )
    })?;
    object.remove("signature");
    arkret_canonical::canonical_json_bytes(&unsigned)
}

string_marker!(
    PeerContactControlReceiptDomain,
    V1,
    "ak.peer_contact.control_receipt.v1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactControlKind {
    ProofRefresh,
    GlareFinalize,
    ContinuityCheckpoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactControlReceipt {
    pub domain: PeerContactControlReceiptDomain,
    pub request_kind: PeerContactControlKind,
    pub request_digest: Hash,
    pub outcome: PeerContactOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<Hash>,
    pub recipient_service_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer: DidCoreId,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactEventSubmitOutcome {
    pub result_kind: ContactResultKind,
    pub status: PeerContactOutcome,
    pub mirror_receipt: PeerContactMirrorReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_proof: Option<ContactCurrentProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum PeerContactControlSubmitOutcome {
    ProofRefresh {
        status: PeerContactOutcome,
        control_receipt: PeerContactControlReceipt,
        current_proof: ContactCurrentProof,
    },
    GlareFinalize {
        status: PeerContactOutcome,
        control_receipt: PeerContactControlReceipt,
        glare_concurrency_attestation: GlareConcurrencyAttestation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
    ContinuityCheckpoint {
        status: PeerContactOutcome,
        control_receipt: PeerContactControlReceipt,
        checkpoint: BilateralContinuityCheckpoint,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactControlDeferredOutcome {
    pub status: PeerContactOutcome,
    pub request_kind: PeerContactControlKind,
    pub control_receipt: PeerContactControlReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[allow(clippy::large_enum_variant)]
pub enum PeerContactSubmitOutcome {
    Event(PeerContactEventSubmitOutcome),
    Control(PeerContactControlSubmitOutcome),
    ControlDeferred(PeerContactControlDeferredOutcome),
}

impl PeerContactSubmitOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let valid = match self {
            Self::Event(outcome) => outcome.status == outcome.mirror_receipt.outcome,
            Self::Control(_) => true,
            Self::ControlDeferred(outcome) => {
                outcome.status == PeerContactOutcome::Deferred
                    && outcome.control_receipt.outcome == PeerContactOutcome::Deferred
            }
        };
        if valid {
            Ok(())
        } else {
            Err(arkret_wire::WireError::Protocol(
                "peer Contact status does not match mirror receipt outcome".to_owned(),
            ))
        }
    }
}
