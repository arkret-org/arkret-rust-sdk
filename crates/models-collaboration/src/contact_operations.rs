use arkret_wire::{
    Base64UrlString, ControlProposalAck, DeviceId, Did, Event, EventId, Hash, IdempotencyKey,
    ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature, ReservationHandle,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::peer_contact::{ContactIntroductionEvidence, PeerContactAddress};
use crate::string_marker;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum StandardHolderBinding {
    HumanDevice {
        device_binding: ProtocolOpaqueId,
    },
    AgentRuntime {
        agent_id: Did,
        device_id: DeviceId,
        agent_key_authorization_ref: EventId,
        verification_method: arkret_wire::DidUrl,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactPeer {
    Human { principal_id: Did },
    Agent { agent_id: Did, controller_id: Did },
}

impl ContactPeer {
    pub fn subject_id(&self) -> &Did {
        match self {
            Self::Human { principal_id } => principal_id,
            Self::Agent { agent_id, .. } => agent_id,
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

pub type ContactScopes = Vec<ContactScope>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RequestAcceptanceReceiptCore {
    pub holder: ContactPeer,
    pub peer: ContactPeer,
    pub slot_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_predecessor: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_basis_id: Option<Hash>,
    pub request_event_ref: EventId,
    pub request_digest: Hash,
    pub source_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: Did,
}

impl RequestAcceptanceReceiptCore {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.slot_version == 0
            || (self.slot_version == 1) == self.slot_predecessor.is_some()
            || self.holder.subject_id() == self.peer.subject_id()
        {
            return Err(arkret_wire::Error::Protocol(
                "invalid Contact request acceptance receipt core".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RequestAcceptanceReceipt {
    pub core: RequestAcceptanceReceiptCore,
    pub receipt_digest: Hash,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactCurrentProof {
    pub basis_id: Hash,
    pub issuer: Did,
    pub terminal: bool,
    pub head_event_ref: EventId,
    pub head_digest: Hash,
    pub accepted_frontier: Vec<EventId>,
    pub complete_through: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fresh_until: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactBasisRequestRef {
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactBasis {
    Normal {
        sorted_pair_members: [Did; 2],
        request_event_ref: EventId,
        request_acceptance_receipt_digest: Hash,
    },
    Glare {
        sorted_pair_members: [Did; 2],
        requests: [ContactBasisRequestRef; 2],
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NormalResponseAcceptanceReceipt {
    pub basis_id: Hash,
    pub request_receipt: RequestAcceptanceReceipt,
    pub response_event_ref: EventId,
    pub response_digest: Hash,
    pub no_outgoing_slot_proof: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RejectAcceptanceReceipt {
    pub request_receipt: RequestAcceptanceReceipt,
    pub reject_event_ref: EventId,
    pub reject_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactLineage {
    pub basis_id: Hash,
    pub issuer: ContactPeer,
    pub peer: ContactPeer,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_event_ref: Option<EventId>,
    pub event_ref: EventId,
    pub granted_to_peer_scopes: ContactScopes,
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
    pub granted_to_peer_scopes: ContactScopes,
    pub introduction_evidence: ContactIntroductionEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_basis_id: Option<Hash>,
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
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub granted_to_peer_scopes: ContactScopes,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactBasisEvidenceBundle {
    pub basis_id: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_terminal_basis_id: Option<Hash>,
    pub basis: ContactBasis,
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_response_receipt: Option<NormalResponseAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glare_concurrency_attestations: Option<[GlareConcurrencyAttestation; 2]>,
    pub current_proofs: Vec<ContactCurrentProof>,
}

pub fn validate_recontact_continuity(
    current: &ContactBasisEvidenceBundle,
    predecessors: &[ContactBasisEvidenceBundle],
) -> arkret_wire::Result<()> {
    if predecessors.len() > 64 {
        return Err(arkret_wire::Error::Protocol(
            "Contact basis continuity exceeds 64 predecessors".to_owned(),
        ));
    }
    let mut expected = current.previous_terminal_basis_id.as_ref();
    if current
        .request_receipts
        .iter()
        .any(|receipt| receipt.core.previous_terminal_basis_id.as_ref() != expected)
    {
        return Err(arkret_wire::Error::Protocol(
            "current Contact request receipt continuity pointer mismatch".to_owned(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(current.basis_id.clone());
    for predecessor in predecessors {
        if expected != Some(&predecessor.basis_id)
            || predecessor.current_proofs.len() != 2
            || predecessor
                .current_proofs
                .iter()
                .any(|proof| !proof.terminal || proof.basis_id != predecessor.basis_id)
            || !seen.insert(predecessor.basis_id.clone())
        {
            return Err(arkret_wire::Error::Protocol(
                "invalid Contact terminal basis continuity edge".to_owned(),
            ));
        }
        if predecessor.request_receipts.iter().any(|receipt| {
            receipt.core.previous_terminal_basis_id != predecessor.previous_terminal_basis_id
        }) {
            return Err(arkret_wire::Error::Protocol(
                "predecessor Contact request receipt continuity pointer mismatch".to_owned(),
            ));
        }
        expected = predecessor.previous_terminal_basis_id.as_ref();
    }
    if expected.is_some()
        || (current.previous_terminal_basis_id.is_some() && predecessors.is_empty())
    {
        return Err(arkret_wire::Error::Protocol(
            "Contact basis continuity does not terminate at one root".to_owned(),
        ));
    }
    Ok(())
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
    pub granted_to_peer_scopes: ContactScopes,
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
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
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
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub granted_to_peer_scopes: ContactScopes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactOperationRejectReason {
    ContactIdempotencyConflict,
    ContactBasisConflict,
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
    pub fn unsigned_event(&self) -> arkret_wire::Result<Event> {
        let bytes =
            arkret_canonical::base64url_decode(self.unsigned_event_bytes.as_str().as_bytes())?;
        let event = Event::from_digest_payload_bytes(&bytes)?;
        if event.event_id != self.event_id
            || event.kind != self.kind
            || Hash::new(event.event_digest()?)? != self.event_digest
        {
            return Err(arkret_wire::Error::Protocol(
                "prepared Contact Event metadata does not match unsigned_event_bytes".to_owned(),
            ));
        }
        event.validate_for_authoring_structural()?;
        Ok(event)
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
        basis_id: Hash,
        basis: ContactBasis,
        request_receipts: [RequestAcceptanceReceipt; 2],
        remote_mirror_receipt: PeerContactMirrorReceipt,
        glare_concurrency_attestation: GlareConcurrencyAttestation,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct GlareConcurrencyAttestation {
    pub issuer: Did,
    pub peer: Did,
    pub request_receipt_digests: [Hash; 2],
    pub observed_frontier: Vec<EventId>,
    pub complete_through: u64,
    pub unconsumed_slot_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

string_marker!(
    PeerContactMirrorReceiptDomain,
    V1,
    "ak.peer-contact.mirror-receipt.v1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactDisposition {
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
    pub disposition: PeerContactDisposition,
    pub recipient_service_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

string_marker!(
    PeerContactControlReceiptDomain,
    V1,
    "ak.peer-contact.control-receipt.v1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactControlKind {
    ProofRefresh,
    GlareFinalize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactControlReceipt {
    pub domain: PeerContactControlReceiptDomain,
    pub request_kind: PeerContactControlKind,
    pub request_digest: Hash,
    pub disposition: PeerContactDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<Hash>,
    pub recipient_service_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactEventSubmitOutcome {
    pub result_kind: ContactResultKind,
    pub status: PeerContactDisposition,
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
        status: PeerContactDisposition,
        control_receipt: PeerContactControlReceipt,
        current_proof: ContactCurrentProof,
    },
    GlareFinalize {
        status: PeerContactDisposition,
        control_receipt: PeerContactControlReceipt,
        glare_concurrency_attestation: GlareConcurrencyAttestation,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PeerContactControlDeferredOutcome {
    pub status: PeerContactDisposition,
    pub request_kind: PeerContactControlKind,
    pub control_receipt: PeerContactControlReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PeerContactSubmitOutcome {
    Event(PeerContactEventSubmitOutcome),
    Control(PeerContactControlSubmitOutcome),
    ControlDeferred(PeerContactControlDeferredOutcome),
}

impl PeerContactSubmitOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let valid = match self {
            Self::Event(outcome) => outcome.status == outcome.mirror_receipt.disposition,
            Self::Control(_) => true,
            Self::ControlDeferred(outcome) => {
                outcome.status == PeerContactDisposition::Deferred
                    && outcome.control_receipt.disposition == PeerContactDisposition::Deferred
            }
        };
        if valid {
            Ok(())
        } else {
            Err(arkret_wire::Error::Protocol(
                "peer Contact status does not match mirror receipt disposition".to_owned(),
            ))
        }
    }
}
