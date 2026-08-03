use arkret_wire::{Base64UrlString, DeviceId, Did, Event, EventId, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature, string_marker};
use crate::governance::peer_contact::{ContactIntroductionEvidence, PeerContactAddress};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum BootstrapMode {
    Founding,
    SiblingPairing,
}

string_marker!(
    DeviceBootstrapCredentialKind,
    DeviceBootstrap,
    "device_bootstrap"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum FoundingAllowedOperation {
    #[serde(rename = "ak.gate.account.command.enroll_device")]
    EnrollDevice,
    #[serde(rename = "ak.gate.account.command.cancel_device_bootstrap")]
    CancelDeviceBootstrap,
    #[serde(rename = "ak.self.events.command.submit")]
    EventsSubmit,
    #[serde(rename = "ak.self.events.query.resolve")]
    EventsResolve,
}

/// The schema defines this as a positional tuple, not as an arbitrary set of
/// four operation identifiers.  A zero-sized value keeps callers from ever
/// constructing a reordered credential while its custom wire form preserves
/// the required JSON array.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct FoundingAllowedOperations;

impl Serialize for FoundingAllowedOperations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        [
            FoundingAllowedOperation::EnrollDevice,
            FoundingAllowedOperation::CancelDeviceBootstrap,
            FoundingAllowedOperation::EventsSubmit,
            FoundingAllowedOperation::EventsResolve,
        ]
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FoundingAllowedOperations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let operations = <[FoundingAllowedOperation; 4]>::deserialize(deserializer)?;
        let expected = [
            FoundingAllowedOperation::EnrollDevice,
            FoundingAllowedOperation::CancelDeviceBootstrap,
            FoundingAllowedOperation::EventsSubmit,
            FoundingAllowedOperation::EventsResolve,
        ];
        if operations != expected {
            return Err(serde::de::Error::custom(
                "founding allowed_operation_ids must match the fixed operation tuple",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SiblingAllowedOperation {
    #[serde(rename = "ak.gate.account.command.cancel_device_bootstrap")]
    CancelDeviceBootstrap,
    #[serde(rename = "ak.self.device_messages.command.send")]
    DeviceMessagesSend,
    #[serde(rename = "ak.self.device_messages.query.list")]
    DeviceMessagesList,
    #[serde(rename = "ak.self.device_messages.command.ack")]
    DeviceMessagesAck,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SiblingAllowedOperations;

impl Serialize for SiblingAllowedOperations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        [
            SiblingAllowedOperation::CancelDeviceBootstrap,
            SiblingAllowedOperation::DeviceMessagesSend,
            SiblingAllowedOperation::DeviceMessagesList,
            SiblingAllowedOperation::DeviceMessagesAck,
        ]
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SiblingAllowedOperations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let operations = <[SiblingAllowedOperation; 4]>::deserialize(deserializer)?;
        let expected = [
            SiblingAllowedOperation::CancelDeviceBootstrap,
            SiblingAllowedOperation::DeviceMessagesSend,
            SiblingAllowedOperation::DeviceMessagesList,
            SiblingAllowedOperation::DeviceMessagesAck,
        ];
        if operations != expected {
            return Err(serde::de::Error::custom(
                "sibling allowed_operation_ids must match the fixed operation tuple",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceBootstrapCredential {
    Founding {
        credential_kind: DeviceBootstrapCredentialKind,
        principal_id: Did,
        device_id: DeviceId,
        device_key_digest: Hash,
        transaction_id: ProtocolOpaqueId,
        holder_jkt: Hash,
        canonical_request_digest: Hash,
        founding_batch_digest: Hash,
        founding_event_ids: Vec<EventId>,
        allowed_operation_ids: FoundingAllowedOperations,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        credential_expires_at: DateTime<Utc>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        bootstrap_transaction_expires_at: DateTime<Utc>,
    },
    SiblingPairing {
        credential_kind: DeviceBootstrapCredentialKind,
        principal_id: Did,
        device_id: DeviceId,
        device_key_digest: Hash,
        transaction_id: ProtocolOpaqueId,
        holder_jkt: Hash,
        canonical_request_digest: Hash,
        source_device_id: DeviceId,
        target_device_id: DeviceId,
        verification_content_kinds: Vec<String>,
        allowed_operation_ids: SiblingAllowedOperations,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        credential_expires_at: DateTime<Utc>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        bootstrap_transaction_expires_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CancelDeviceBootstrapRequestBody {
    pub transaction_id: ProtocolOpaqueId,
    pub mode: BootstrapMode,
    pub canonical_request_digest: Hash,
    pub idempotency_key: ProtocolOpaqueId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum BootstrapRetryableError {
    TemporarilyUnavailable,
    ProofRefreshRequired,
    DependencyPending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CancelDeviceBootstrapOutcome {
    Cancelled {
        transaction_id: ProtocolOpaqueId,
        outcome_digest: Hash,
    },
    Expired {
        transaction_id: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expired_at: DateTime<Utc>,
        outcome_digest: Hash,
    },
    Pending {
        transaction_id: ProtocolOpaqueId,
        retryable_error: BootstrapRetryableError,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
        outcome_digest: Hash,
    },
}

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
    pub idempotency_key: ProtocolOpaqueId,
    pub reservation_handle: ProtocolOpaqueId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub signed_event: Event,
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
    pub idempotency_key: ProtocolOpaqueId,
    pub peer: ContactPeer,
    pub granted_to_peer_scopes: ContactScopes,
    pub introduction_evidence: ContactIntroductionEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    pub idempotency_key: ProtocolOpaqueId,
    pub peer: ContactPeer,
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
    pub granted_to_peer_scopes: ContactScopes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactScopeUpdateRequestBody {
    Prepare(ContactScopeUpdatePrepareRequestBody),
    Commit(ContactCommitRequestBody),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactBasisEvidenceBundle {
    pub basis_id: Hash,
    pub basis: ContactBasis,
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_response_receipt: Option<NormalResponseAcceptanceReceipt>,
    pub current_proofs: Vec<ContactCurrentProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactAcceptPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub request_receipt: RequestAcceptanceReceipt,
    pub action: ContactAcceptAction,
    pub granted_to_peer_scopes: ContactScopes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    pub idempotency_key: ProtocolOpaqueId,
    pub request_receipt: RequestAcceptanceReceipt,
    pub action: ContactRejectAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    pub idempotency_key: ProtocolOpaqueId,
    pub peer: ContactPeer,
    pub basis_id: Hash,
    pub version: u64,
    pub predecessor_event_ref: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
        let bytes = arkret_canonical::base64url_decode(
            self.unsigned_event_bytes.as_str().as_bytes(),
        )?;
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
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Response {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Reject {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    ScopeUpdate {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
    Tombstone {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: ContactPreparedEventDraft,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
        idempotency_key: ProtocolOpaqueId,
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
        idempotency_key: ProtocolOpaqueId,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        response_receipt: NormalResponseAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_proof: Option<ContactCurrentProof>,
    },
    Reject {
        idempotency_key: ProtocolOpaqueId,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        reject_receipt: RejectAcceptanceReceipt,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    ScopeUpdate {
        idempotency_key: ProtocolOpaqueId,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    Tombstone {
        idempotency_key: ProtocolOpaqueId,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        signed_event: Event,
        lineage: ContactLineage,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    ProofRefresh {
        idempotency_key: ProtocolOpaqueId,
        prior_mirror_receipt: PeerContactMirrorReceipt,
        current_proof: ContactCurrentProof,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        contact_address: PeerContactAddress,
    },
    GlareFinalize {
        idempotency_key: ProtocolOpaqueId,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn bootstrap_operation_tuples_reject_reordering() {
        let founding = json!([
            "ak.gate.account.command.enroll_device",
            "ak.gate.account.command.cancel_device_bootstrap",
            "ak.self.events.command.submit",
            "ak.self.events.query.resolve"
        ]);
        serde_json::from_value::<FoundingAllowedOperations>(founding.clone()).unwrap();
        let mut reordered = founding.as_array().unwrap().clone();
        reordered.swap(0, 1);
        assert!(serde_json::from_value::<FoundingAllowedOperations>(json!(reordered)).is_err());

        let sibling = json!([
            "ak.gate.account.command.cancel_device_bootstrap",
            "ak.self.device_messages.command.send",
            "ak.self.device_messages.query.list",
            "ak.self.device_messages.command.ack"
        ]);
        serde_json::from_value::<SiblingAllowedOperations>(sibling.clone()).unwrap();
        let mut reordered = sibling.as_array().unwrap().clone();
        reordered.swap(2, 3);
        assert!(serde_json::from_value::<SiblingAllowedOperations>(json!(reordered)).is_err());
    }
}
