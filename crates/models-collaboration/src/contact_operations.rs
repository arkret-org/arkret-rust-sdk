use arkret_wire::{
    Base64UrlString, ControlProposalAck, DeviceId, DidCoreId, DidFullId, Event, EventId, Hash,
    IdempotencyKey, ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature, ReservationHandle,
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

pub type ContactScopes = Vec<ContactScope>;

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
            return Err(arkret_wire::Error::Protocol(
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
        let mut bytes = b"ak.contact.request-acceptance-core.v1\n".to_vec();
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
            return Err(arkret_wire::Error::Protocol(
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
                arkret_wire::Error::Protocol(
                    "Contact request acceptance receipt signer is not a DID URL".to_owned(),
                )
            })?;
        let signer = DidFullId::new(signer)
            .and_then(|full_id| arkret_wire::project_full_id_to_core_id(&full_id))?;
        if signer != self.core.issuer {
            return Err(arkret_wire::Error::Protocol(
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
            return Err(arkret_wire::Error::Protocol(
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRoundRequestRef {
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub no_outgoing_slot_proof: Hash,
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
    pub previous_terminal_contact_round_id: Option<Hash>,
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
}

pub fn validate_recontact_continuity(
    current: &ContactRoundEvidenceBundle,
    predecessors: &[ContactRoundEvidenceBundle],
) -> arkret_wire::Result<()> {
    if predecessors.len() > 64 {
        return Err(arkret_wire::Error::Protocol(
            "Contact round continuity exceeds 64 predecessors".to_owned(),
        ));
    }
    let mut expected = current.previous_terminal_contact_round_id.as_ref();
    if current
        .request_receipts
        .iter()
        .any(|receipt| receipt.core.previous_terminal_contact_round_id.as_ref() != expected)
    {
        return Err(arkret_wire::Error::Protocol(
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
            return Err(arkret_wire::Error::Protocol(
                "invalid Contact terminal contact_round continuity edge".to_owned(),
            ));
        }
        if predecessor.request_receipts.iter().any(|receipt| {
            receipt.core.previous_terminal_contact_round_id
                != predecessor.previous_terminal_contact_round_id
        }) {
            return Err(arkret_wire::Error::Protocol(
                "predecessor Contact request receipt continuity pointer mismatch".to_owned(),
            ));
        }
        expected = predecessor.previous_terminal_contact_round_id.as_ref();
    }
    if expected.is_some()
        || (current.previous_terminal_contact_round_id.is_some() && predecessors.is_empty())
    {
        return Err(arkret_wire::Error::Protocol(
            "Contact round continuity does not terminate at one root".to_owned(),
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
    pub granted_to_peer_scopes: ContactScopes,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
