use arkret_wire::{
    AccountId, ActorId, BlobRef, Did, DidCoreId, Event, EventId, Hash, IdempotencyKey,
    ProtocolOperationId, ProtocolSignature, RealmId, ReservationHandle, StrandId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::peer_contact::{ContactIntroductionEvidence, PeerContactAddress};
use crate::prepared_event_draft::PreparedEventDraft;
use crate::string_marker;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactPeer {
    Human {
        account_id: AccountId,
    },
    Agent {
        actor_id: ActorId,
        controller_account_id: AccountId,
    },
}

impl ContactPeer {
    /// Normalize a Contact participant to the actor role used by pair ordering
    /// and Contact receipts. Human principals are actors in this protocol
    /// context; this explicit conversion prevents a generic cross-role `From`.
    pub fn contact_actor_id(&self) -> ActorId {
        match self {
            Self::Human { account_id } => ActorId::account(account_id.clone()),
            Self::Agent { actor_id, .. } => actor_id.clone(),
        }
    }

    /// Station that accepts private delivery for this participant.
    pub fn delivery_station_id(&self) -> &DidCoreId {
        match self {
            Self::Human { account_id } => &account_id.station_id,
            Self::Agent {
                controller_account_id,
                ..
            } => &controller_account_id.station_id,
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

/// The exact producer key authenticated by an enclosing Contact source
/// receipt or lineage. It has no reusable authorization or authority semantics.
///
/// `schemas/contact-operations.schema.json#/$defs/contact_producer_signer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactProducerSigner {
    Direct(ContactDirectProducerSigner),
    Delegated(ContactDelegatedProducerSigner),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactDirectProducerSigner {
    pub verification_method: arkret_wire::DidUrl,
    #[serde(deserialize_with = "deserialize_contact_producer_key")]
    pub public_key_b64u: arkret_wire::Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactDelegatedProducerSigner {
    pub verification_method: arkret_wire::DidUrl,
    #[serde(deserialize_with = "deserialize_contact_producer_key")]
    pub public_key_b64u: arkret_wire::Base64UrlString,
    pub delegated_actor_did: Did,
}
fn deserialize_contact_producer_key<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<arkret_wire::Base64UrlString, D::Error> {
    let value = arkret_wire::Base64UrlString::deserialize(deserializer)?;
    let bytes =
        arkret_canonical::base64url_decode(value.as_str()).map_err(serde::de::Error::custom)?;
    if bytes.len() != 32 || arkret_canonical::base64url_encode(&bytes) != value.as_str() {
        return Err(serde::de::Error::custom(
            "Contact producer key must be canonical Ed25519 raw32",
        ));
    }
    Ok(value)
}
impl ContactProducerSigner {
    pub fn direct(
        verification_method: arkret_wire::DidUrl,
        public_key_b64u: arkret_wire::Base64UrlString,
    ) -> arkret_wire::Result<Self> {
        let value = Self::Direct(ContactDirectProducerSigner {
            verification_method,
            public_key_b64u,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn delegated(
        verification_method: arkret_wire::DidUrl,
        public_key_b64u: arkret_wire::Base64UrlString,
        delegated_actor_did: Did,
    ) -> arkret_wire::Result<Self> {
        let value = Self::Delegated(ContactDelegatedProducerSigner {
            verification_method,
            public_key_b64u,
            delegated_actor_did,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn verification_method(&self) -> &arkret_wire::DidUrl {
        match self {
            Self::Direct(value) => &value.verification_method,
            Self::Delegated(value) => &value.verification_method,
        }
    }

    pub fn public_key_b64u(&self) -> &arkret_wire::Base64UrlString {
        match self {
            Self::Direct(value) => &value.public_key_b64u,
            Self::Delegated(value) => &value.public_key_b64u,
        }
    }

    pub fn delegated_actor_did(&self) -> Option<&Did> {
        match self {
            Self::Direct(_) => None,
            Self::Delegated(value) => Some(&value.delegated_actor_did),
        }
    }

    /// Check the standalone source object's holder constraint. The enclosing
    /// carrier must also check the original Event's executor and exact actor.
    pub fn validate_for_holder(&self, holder: &ContactPeer) -> arkret_wire::Result<()> {
        self.validate()?;
        if let Some(did) = self.delegated_actor_did() {
            if !matches!(holder, ContactPeer::Agent { .. })
                || arkret_wire::project_did_to_core_id(did)?
                    != *holder.contact_actor_id().signing_principal_id()
            {
                return Err(arkret_wire::WireError::Protocol(
                    "delegated Contact producer does not bind the Agent holder".into(),
                ));
            }
        }
        Ok(())
    }

    /// Structural binding only: source signatures and the independently
    /// authenticated Agent native identity are verified by the receiving gate.
    pub fn validate_for_event(
        &self,
        event: &Event,
        holder: &ContactPeer,
    ) -> arkret_wire::Result<()> {
        self.validate_for_holder(holder)?;
        if event.actor_id != holder.contact_actor_id()
            || event.actor_id.as_account_id().is_none()
            || event.executed_by.is_some() != self.delegated_actor_did().is_some()
        {
            return Err(arkret_wire::WireError::Protocol(
                "Contact producer branch differs from the exact Event actor/executor".into(),
            ));
        }
        if let ContactPeer::Agent {
            controller_account_id,
            ..
        } = holder
        {
            if event.actor_id.route_service_id() != &controller_account_id.station_id
                || event.executed_by.as_ref().is_some_and(|executor| {
                    executor != &ActorId::account(controller_account_id.clone())
                })
            {
                return Err(arkret_wire::WireError::Protocol(
                    "Contact executor differs from the complete Agent controller account".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn public_key_bytes(&self) -> arkret_wire::Result<[u8; 32]> {
        let bytes = arkret_canonical::base64url_decode(self.public_key_b64u().as_str())
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
        if arkret_canonical::base64url_encode(&bytes) != self.public_key_b64u().as_str() {
            return Err(arkret_wire::WireError::Protocol(
                "Contact producer key is not canonical unpadded base64url".into(),
            ));
        }
        bytes.try_into().map_err(|_| {
            arkret_wire::WireError::Protocol("Contact producer key must be Ed25519 raw32".into())
        })
    }
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.public_key_bytes().map(|_| ())
    }
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
    pub producer_signer: ContactProducerSigner,
    pub source_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
}

impl RequestAcceptanceReceiptCore {
    pub fn request_digest(&self) -> Hash {
        self.request_event_ref.event_digest()
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.producer_signer.validate_for_holder(&self.holder)?;
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

fn request_acceptance_core_digest(
    core: &RequestAcceptanceReceiptCore,
) -> arkret_wire::Result<Hash> {
    let mut bytes = b"ak.contact.request_acceptance_core.v1\n".to_vec();
    bytes.extend(arkret_canonical::canonical_json_bytes(core)?);
    Hash::new(arkret_canonical::sha256_digest(bytes)).map_err(Into::into)
}

#[derive(Serialize)]
struct UnsignedRequestAcceptanceReceipt {
    core: RequestAcceptanceReceiptCore,
    receipt_digest: Hash,
}

impl RequestAcceptanceReceipt {
    /// Build the exact unsigned transcript and request its real historical source
    /// signature once. The caller selects and authenticates that historical key;
    /// no incomplete signed object or placeholder signature is constructed.
    pub fn sign_with(
        core: RequestAcceptanceReceiptCore,
        sign: impl FnOnce(&[u8]) -> arkret_wire::Result<ProtocolSignature>,
    ) -> arkret_wire::Result<Self> {
        core.validate()?;
        let receipt_digest = request_acceptance_core_digest(&core)?;
        let unsigned = UnsignedRequestAcceptanceReceipt {
            core,
            receipt_digest,
        };
        let signature = sign(&arkret_canonical::canonical_json_bytes(&unsigned)?)?;
        Ok(Self {
            core: unsigned.core,
            receipt_digest: unsigned.receipt_digest,
            signature,
        })
    }

    /// Exact non-recursive transcript signed by the accepting source Station.
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&UnsignedRequestAcceptanceReceipt {
            core: self.core.clone(),
            receipt_digest: self.receipt_digest.clone(),
        })
    }

    /// Digest of the closed receipt core covered by `signature`.
    pub fn computed_core_digest(&self) -> arkret_wire::Result<Hash> {
        request_acceptance_core_digest(&self.core)
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
        let signer = Did::new(signer).and_then(|did| arkret_wire::project_did_to_core_id(&did))?;
        if signer != self.core.issuer_id {
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
    pub issuer_id: DidCoreId,
    pub peer: ContactPeer,
    pub terminal: bool,
    pub head_event_ref: EventId,
    pub accepted_commit_event_ids: Vec<EventId>,
    pub complete_through: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fresh_until: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

#[derive(Serialize)]
struct UnsignedContactCurrentProof {
    contact_round_id: Hash,
    issuer_id: DidCoreId,
    peer: ContactPeer,
    terminal: bool,
    head_event_ref: EventId,
    accepted_commit_event_ids: Vec<EventId>,
    complete_through: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    fresh_until: DateTime<Utc>,
}

impl ContactCurrentProof {
    /// Build the exact unsigned transcript and request its real historical source
    /// signature once. The caller selects and authenticates that historical key;
    /// no incomplete signed object or placeholder signature is constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with(
        contact_round_id: Hash,
        issuer_id: DidCoreId,
        peer: ContactPeer,
        terminal: bool,
        head_event_ref: EventId,
        accepted_commit_event_ids: Vec<EventId>,
        complete_through: u64,
        fresh_until: DateTime<Utc>,
        sign: impl FnOnce(&[u8]) -> arkret_wire::Result<ProtocolSignature>,
    ) -> arkret_wire::Result<Self> {
        let unsigned = UnsignedContactCurrentProof {
            contact_round_id,
            issuer_id,
            peer,
            terminal,
            head_event_ref,
            accepted_commit_event_ids,
            complete_through,
            fresh_until,
        };
        let signature = sign(&arkret_canonical::canonical_json_bytes(&unsigned)?)?;
        Ok(Self {
            contact_round_id: unsigned.contact_round_id,
            issuer_id: unsigned.issuer_id,
            peer: unsigned.peer,
            terminal: unsigned.terminal,
            head_event_ref: unsigned.head_event_ref,
            accepted_commit_event_ids: unsigned.accepted_commit_event_ids,
            complete_through: unsigned.complete_through,
            fresh_until: unsigned.fresh_until,
            signature,
        })
    }

    pub fn head_digest(&self) -> Hash {
        self.head_event_ref.event_digest()
    }

    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&UnsignedContactCurrentProof {
            contact_round_id: self.contact_round_id.clone(),
            issuer_id: self.issuer_id.clone(),
            peer: self.peer.clone(),
            terminal: self.terminal,
            head_event_ref: self.head_event_ref.clone(),
            accepted_commit_event_ids: self.accepted_commit_event_ids.clone(),
            complete_through: self.complete_through,
            fresh_until: self.fresh_until,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactRoundRequestRef {
    pub request_event_ref: EventId,
    pub request_acceptance_receipt_digest: Hash,
}

/// Compare complete EventId wire strings, never decoded digests or receipt hashes.
pub fn compare_contact_request_event_refs(left: &EventId, right: &EventId) -> std::cmp::Ordering {
    left.as_str().as_bytes().cmp(right.as_str().as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactRound {
    Normal {
        sorted_pair_member_ids: [ActorId; 2],
        request_event_ref: EventId,
        request_acceptance_receipt_digest: Hash,
    },
    Glare {
        sorted_pair_member_ids: [ActorId; 2],
        requests: [ContactRoundRequestRef; 2],
    },
}

impl ContactRound {
    /// Check the received core without changing its signed array order.
    pub fn validate_canonical_order(&self) -> arkret_wire::Result<()> {
        let participants = match self {
            Self::Normal {
                sorted_pair_member_ids,
                ..
            }
            | Self::Glare {
                sorted_pair_member_ids,
                ..
            } => sorted_pair_member_ids,
        };
        let first = arkret_canonical::canonical_json_bytes(&participants[0])?;
        let second = arkret_canonical::canonical_json_bytes(&participants[1])?;
        if first >= second {
            return Err(arkret_wire::WireError::Protocol(
                "Contact round participants must be distinct and strictly JCS-byte ordered"
                    .to_owned(),
            ));
        }
        if let Self::Glare { requests, .. } = self {
            if !compare_contact_request_event_refs(
                &requests[0].request_event_ref,
                &requests[1].request_event_ref,
            )
            .is_lt()
            {
                return Err(arkret_wire::WireError::Protocol(
                    "Contact glare request refs must be distinct and strictly wire-byte ordered"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Construct a local core from exact receipts. Signature/current-proof validation is separate.
    /// Receiving verifiers must validate their received core before comparing it to this result.
    pub fn glare_from_request_receipts(
        receipts: &[RequestAcceptanceReceipt; 2],
    ) -> arkret_wire::Result<Self> {
        let mut participants = [
            receipts[0].core.holder.contact_actor_id(),
            receipts[1].core.holder.contact_actor_id(),
        ];
        if receipts[0].core.peer.contact_actor_id() != participants[1]
            || receipts[1].core.peer.contact_actor_id() != participants[0]
            || participants[0] == participants[1]
        {
            return Err(arkret_wire::WireError::Protocol(
                "Contact glare receipts must cover the exact reverse pair".to_owned(),
            ));
        }
        if arkret_canonical::canonical_json_bytes(&participants[0])?
            > arkret_canonical::canonical_json_bytes(&participants[1])?
        {
            participants.swap(0, 1);
        }
        let mut requests = [
            ContactRoundRequestRef {
                request_event_ref: receipts[0].core.request_event_ref.clone(),
                request_acceptance_receipt_digest: Hash::new(arkret_canonical::canonical_sha256(
                    &receipts[0],
                )?)?,
            },
            ContactRoundRequestRef {
                request_event_ref: receipts[1].core.request_event_ref.clone(),
                request_acceptance_receipt_digest: Hash::new(arkret_canonical::canonical_sha256(
                    &receipts[1],
                )?)?,
            },
        ];
        requests.sort_by(|left, right| {
            compare_contact_request_event_refs(&left.request_event_ref, &right.request_event_ref)
        });
        let round = Self::Glare {
            sorted_pair_member_ids: participants,
            requests,
        };
        round.validate_canonical_order()?;
        Ok(round)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NormalResponseAcceptanceReceipt {
    pub contact_round_id: Hash,
    pub request_receipt: RequestAcceptanceReceipt,
    pub response_event_ref: EventId,
    pub producer_signer: ContactProducerSigner,
    pub outgoing_slot_absence_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub signature: ProtocolSignature,
}

#[derive(Serialize)]
struct UnsignedNormalResponseAcceptanceReceipt {
    contact_round_id: Hash,
    request_receipt: RequestAcceptanceReceipt,
    response_event_ref: EventId,
    producer_signer: ContactProducerSigner,
    outgoing_slot_absence_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    accepted_at: DateTime<Utc>,
    issuer_id: DidCoreId,
}

impl NormalResponseAcceptanceReceipt {
    /// Build the exact unsigned transcript and request its real historical source
    /// signature once. The caller selects and authenticates that historical key;
    /// no incomplete signed object or placeholder signature is constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with(
        contact_round_id: Hash,
        request_receipt: RequestAcceptanceReceipt,
        response_event_ref: EventId,
        producer_signer: ContactProducerSigner,
        outgoing_slot_absence_digest: Hash,
        accepted_at: DateTime<Utc>,
        issuer_id: DidCoreId,
        sign: impl FnOnce(&[u8]) -> arkret_wire::Result<ProtocolSignature>,
    ) -> arkret_wire::Result<Self> {
        producer_signer.validate_for_holder(&request_receipt.core.peer)?;
        let unsigned = UnsignedNormalResponseAcceptanceReceipt {
            contact_round_id,
            request_receipt,
            response_event_ref,
            producer_signer,
            outgoing_slot_absence_digest,
            accepted_at,
            issuer_id,
        };
        let signature = sign(&arkret_canonical::canonical_json_bytes(&unsigned)?)?;
        Ok(Self {
            contact_round_id: unsigned.contact_round_id,
            request_receipt: unsigned.request_receipt,
            response_event_ref: unsigned.response_event_ref,
            producer_signer: unsigned.producer_signer,
            outgoing_slot_absence_digest: unsigned.outgoing_slot_absence_digest,
            accepted_at: unsigned.accepted_at,
            issuer_id: unsigned.issuer_id,
            signature,
        })
    }

    pub fn response_digest(&self) -> Hash {
        self.response_event_ref.event_digest()
    }

    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&UnsignedNormalResponseAcceptanceReceipt {
            contact_round_id: self.contact_round_id.clone(),
            request_receipt: self.request_receipt.clone(),
            response_event_ref: self.response_event_ref.clone(),
            producer_signer: self.producer_signer.clone(),
            outgoing_slot_absence_digest: self.outgoing_slot_absence_digest.clone(),
            accepted_at: self.accepted_at,
            issuer_id: self.issuer_id.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum OutgoingRequestState {
    Absent,
}

/// Exact CAS observation covered by `outgoing_slot_absence_digest`.
///
/// `slot_predecessor` intentionally serializes as JSON null at genesis. No
/// field in this closed transcript is optional on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct OutgoingSlotAbsenceTranscript {
    pub sorted_pair_member_ids: [ActorId; 2],
    pub request_slot_owner: ActorId,
    pub contact_round_id: Hash,
    pub slot_predecessor: Option<Hash>,
    pub cas_sequence: u64,
    pub cas_revision: Vec<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub outgoing_request_state: OutgoingRequestState,
}

impl OutgoingSlotAbsenceTranscript {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        let pair_bytes = self
            .sorted_pair_member_ids
            .iter()
            .map(arkret_canonical::canonical_json_bytes)
            .collect::<arkret_canonical::Result<Vec<_>>>()?;
        if pair_bytes[0] >= pair_bytes[1]
            || !self
                .sorted_pair_member_ids
                .contains(&self.request_slot_owner)
            || self.cas_sequence == 0
            || self.cas_revision.is_empty()
            || !self.cas_revision.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid Contact outgoing-slot-absence transcript".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        self.validate_shape()?;
        arkret_canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn digest(&self) -> arkret_wire::Result<Hash> {
        let mut bytes = b"ak.contact.no_outgoing_slot.v1\n".to_vec();
        bytes.extend(self.canonical_bytes()?);
        Hash::new(arkret_canonical::sha256_digest(bytes)).map_err(Into::into)
    }

    pub fn verify_digest(&self, expected: &Hash) -> arkret_wire::Result<()> {
        if &self.digest()? != expected {
            return Err(arkret_wire::WireError::Protocol(
                "Contact outgoing-slot-absence digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct RejectAcceptanceReceipt {
    pub request_receipt: RequestAcceptanceReceipt,
    pub reject_event_ref: EventId,
    pub producer_signer: ContactProducerSigner,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub signature: ProtocolSignature,
}

#[derive(Serialize)]
struct UnsignedRejectAcceptanceReceipt {
    request_receipt: RequestAcceptanceReceipt,
    reject_event_ref: EventId,
    producer_signer: ContactProducerSigner,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    accepted_at: DateTime<Utc>,
    issuer_id: DidCoreId,
}

impl RejectAcceptanceReceipt {
    /// Build the exact unsigned transcript and request its real historical source
    /// signature once. The caller selects and authenticates that historical key;
    /// no incomplete signed object or placeholder signature is constructed.
    pub fn sign_with(
        request_receipt: RequestAcceptanceReceipt,
        reject_event_ref: EventId,
        producer_signer: ContactProducerSigner,
        accepted_at: DateTime<Utc>,
        issuer_id: DidCoreId,
        sign: impl FnOnce(&[u8]) -> arkret_wire::Result<ProtocolSignature>,
    ) -> arkret_wire::Result<Self> {
        producer_signer.validate_for_holder(&request_receipt.core.peer)?;
        let unsigned = UnsignedRejectAcceptanceReceipt {
            request_receipt,
            reject_event_ref,
            producer_signer,
            accepted_at,
            issuer_id,
        };
        let signature = sign(&arkret_canonical::canonical_json_bytes(&unsigned)?)?;
        Ok(Self {
            request_receipt: unsigned.request_receipt,
            reject_event_ref: unsigned.reject_event_ref,
            producer_signer: unsigned.producer_signer,
            accepted_at: unsigned.accepted_at,
            issuer_id: unsigned.issuer_id,
            signature,
        })
    }

    pub fn reject_digest(&self) -> Hash {
        self.reject_event_ref.event_digest()
    }

    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&UnsignedRejectAcceptanceReceipt {
            request_receipt: self.request_receipt.clone(),
            reject_event_ref: self.reject_event_ref.clone(),
            producer_signer: self.producer_signer.clone(),
            accepted_at: self.accepted_at,
            issuer_id: self.issuer_id.clone(),
        })
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
    pub producer_signer: ContactProducerSigner,
    pub granted_to_peer_scopes: Vec<ContactScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
    pub signature: ProtocolSignature,
}

#[derive(Serialize)]
struct UnsignedContactLineage {
    contact_round_id: Hash,
    issuer: ContactPeer,
    peer: ContactPeer,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_event_ref: Option<EventId>,
    event_ref: EventId,
    producer_signer: ContactProducerSigner,
    granted_to_peer_scopes: Vec<ContactScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal: Option<bool>,
}

impl ContactLineage {
    /// Build the exact unsigned transcript and request its real historical source
    /// signature once. The caller selects and authenticates that historical key;
    /// no incomplete signed object or placeholder signature is constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with(
        contact_round_id: Hash,
        issuer: ContactPeer,
        peer: ContactPeer,
        version: u64,
        predecessor_event_ref: Option<EventId>,
        event_ref: EventId,
        producer_signer: ContactProducerSigner,
        granted_to_peer_scopes: Vec<ContactScope>,
        terminal: Option<bool>,
        sign: impl FnOnce(&[u8]) -> arkret_wire::Result<ProtocolSignature>,
    ) -> arkret_wire::Result<Self> {
        producer_signer.validate_for_holder(&issuer)?;
        let unsigned = UnsignedContactLineage {
            contact_round_id,
            issuer,
            peer,
            version,
            predecessor_event_ref,
            event_ref,
            producer_signer,
            granted_to_peer_scopes,
            terminal,
        };
        let signature = sign(&arkret_canonical::canonical_json_bytes(&unsigned)?)?;
        Ok(Self {
            contact_round_id: unsigned.contact_round_id,
            issuer: unsigned.issuer,
            peer: unsigned.peer,
            version: unsigned.version,
            predecessor_event_ref: unsigned.predecessor_event_ref,
            event_ref: unsigned.event_ref,
            producer_signer: unsigned.producer_signer,
            granted_to_peer_scopes: unsigned.granted_to_peer_scopes,
            terminal: unsigned.terminal,
            signature,
        })
    }

    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&UnsignedContactLineage {
            contact_round_id: self.contact_round_id.clone(),
            issuer: self.issuer.clone(),
            peer: self.peer.clone(),
            version: self.version,
            predecessor_event_ref: self.predecessor_event_ref.clone(),
            event_ref: self.event_ref.clone(),
            producer_signer: self.producer_signer.clone(),
            granted_to_peer_scopes: self.granted_to_peer_scopes.clone(),
            terminal: self.terminal,
        })
    }
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
    pub participants: [AccountId; 2],
    #[serde(deserialize_with = "deserialize_uncheckpointed_root_basis")]
    pub root_basis: Box<ContactRoundEvidenceBundle>,
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
    pub signer: AccountId,
    pub signature: ProtocolSignature,
}

/// One-sided proposal carried to the other participant's Station.
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
    pub uncompressed_tail_entries: Vec<ContactRoundEvidenceBundle>,
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
        if root.previous_terminal_contact_round_id.is_some() || root.continuity_checkpoint.is_some()
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
        if root.previous_terminal_contact_round_id.is_some() || root.continuity_checkpoint.is_some()
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

/// Derive the only v1 digest of a portable continuity root basis.
///
/// The digest is not a wire member: callers recompute `SHA-256(JCS(root_basis))`
/// from the closed root object whenever an accumulator input needs it.
pub fn bilateral_continuity_root_basis_digest(
    root_basis: &ContactRoundEvidenceBundle,
) -> arkret_wire::Result<Hash> {
    let canonical = arkret_canonical::canonical_json_bytes(root_basis)
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    Ok(Hash::new(arkret_canonical::sha256_digest(canonical))?)
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
    validate_contact_evidence_directions(current)?;
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
        validate_contact_evidence_directions(predecessor)?;
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
            ActorId::account(checkpoint.core.participants[0].clone()),
            ActorId::account(checkpoint.core.participants[1].clone()),
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

/// Validate participant direction independently from the service signer.
/// Same-Station pairs may legitimately have equal issuer IDs, so direction is
/// keyed exclusively by each signed peer/subject pair.
pub fn validate_contact_evidence_directions(
    bundle: &ContactRoundEvidenceBundle,
) -> arkret_wire::Result<()> {
    let pair = contact_round_participants(&bundle.contact_round);
    let mut proof_peers = std::collections::BTreeSet::new();
    for proof in &bundle.current_proofs {
        let peer = proof.peer.contact_actor_id();
        let subject = if peer == pair[0] {
            &pair[1]
        } else if peer == pair[1] {
            &pair[0]
        } else {
            return Err(arkret_wire::WireError::Protocol(
                "Contact current proof peer is outside the exact pair".to_owned(),
            ));
        };
        let Some(subject_account) = subject.as_account_id() else {
            return Err(arkret_wire::WireError::Protocol(
                "Contact proof subject has no account Station authority".to_owned(),
            ));
        };
        if proof.issuer_id != subject_account.station_id || !proof_peers.insert(peer) {
            return Err(arkret_wire::WireError::Protocol(
                "Contact current proofs do not cover distinct opposite directions".to_owned(),
            ));
        }
    }
    if bundle.current_proofs.len() == 2 && proof_peers != pair.clone().into_iter().collect() {
        return Err(arkret_wire::WireError::Protocol(
            "Contact current proofs do not cover the exact pair".to_owned(),
        ));
    }

    if let Some(attestations) = &bundle.glare_concurrency_attestations {
        let mut subjects = std::collections::BTreeSet::new();
        for attestation in attestations {
            let opposite = if attestation.subject_id == pair[0] {
                &pair[1]
            } else if attestation.subject_id == pair[1] {
                &pair[0]
            } else {
                return Err(arkret_wire::WireError::Protocol(
                    "Contact glare subject is outside the exact pair".to_owned(),
                ));
            };
            let Some(subject_account) = attestation.subject_id.as_account_id() else {
                return Err(arkret_wire::WireError::Protocol(
                    "Contact glare subject has no account Station authority".to_owned(),
                ));
            };
            if &attestation.peer_id != opposite
                || attestation.issuer_id != subject_account.station_id
                || !subjects.insert(attestation.subject_id.clone())
            {
                return Err(arkret_wire::WireError::Protocol(
                    "Contact glare attestations do not cover opposite directions".to_owned(),
                ));
            }
        }
        if subjects != pair.into_iter().collect() {
            return Err(arkret_wire::WireError::Protocol(
                "Contact glare attestations do not cover the exact pair".to_owned(),
            ));
        }
    }
    Ok(())
}

fn contact_round_participants(round: &ContactRound) -> [ActorId; 2] {
    match round {
        ContactRound::Normal {
            sorted_pair_member_ids,
            ..
        }
        | ContactRound::Glare {
            sorted_pair_member_ids,
            ..
        } => sorted_pair_member_ids.clone(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactAcceptPrepareRequestBody {
    pub phase: ContactPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub peer: ContactPeer,
    pub request_event_ref: EventId,
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
    pub peer: ContactPeer,
    pub request_event_ref: EventId,
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
        event_draft: PreparedEventDraft,
    },
    Response {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: PreparedEventDraft,
    },
    Reject {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: PreparedEventDraft,
    },
    ScopeUpdate {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: PreparedEventDraft,
    },
    Tombstone {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        event_draft: PreparedEventDraft,
    },
}

impl ContactPreparedOutcome {
    pub fn event_draft(&self) -> arkret_wire::Result<&PreparedEventDraft> {
        let (draft, expected_kind) = match self {
            Self::Request { event_draft, .. } => {
                (event_draft, arkret_wire::event_kind_str::CONTACT_REQUESTED)
            }
            Self::Response { event_draft, .. } => {
                (event_draft, arkret_wire::event_kind_str::CONTACT_ACCEPTED)
            }
            Self::Reject { event_draft, .. } => {
                (event_draft, arkret_wire::event_kind_str::CONTACT_REJECTED)
            }
            Self::ScopeUpdate { event_draft, .. } => (
                event_draft,
                arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE,
            ),
            Self::Tombstone { event_draft, .. } => {
                (event_draft, arkret_wire::event_kind_str::CONTACT_TOMBSTONE)
            }
        };
        draft.unsigned_event_for_kind(expected_kind)?;
        Ok(draft)
    }
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
    pub subject_id: ActorId,
    pub issuer_id: DidCoreId,
    pub peer_id: ActorId,
    pub request_receipt_digests: [Hash; 2],
    pub observed_commit_event_ids: Vec<EventId>,
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
    pub outcome: PeerContactOutcome,
    pub recipient_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub signature: ProtocolSignature,
}

impl PeerContactMirrorReceipt {
    pub fn signed_event_digest(&self) -> Hash {
        self.signed_event_ref.event_digest()
    }

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
    pub recipient_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
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

/// `contact-operations.schema.json#/$defs/contact_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContactState {
    PendingOutgoing,
    PendingIncoming,
    Accepted,
    Rejected,
    Expired,
    Tombstoned,
}

/// `contact-operations.schema.json#/$defs/direct_conversation_summary.state`.
///
/// Coordinates of a materialized Direct Conversation are immutable; this only
/// says whether the same conversation is currently sendable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationSummaryState {
    Found,
    Suspended,
}

/// `contact-operations.schema.json#/$defs/direct_conversation_summary`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationSummary {
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub binding_event_ref: EventId,
    pub state: DirectConversationSummaryState,
}

/// `contact-operations.schema.json#/$defs/contact_agent_projection`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactAgentProjection {
    pub actor_id: ActorId,
    pub controller_account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
}

/// `contact-operations.schema.json#/$defs/contact_list_row`.
///
/// The schema's conditional requirements (`next_prepare_input` exactly for
/// `accepted`, `request_event_ref` for `pending_incoming`, `request_message`
/// only there, `effective_scopes == bidirectional_scopes`) are enforced on
/// deserialization through `ContactListRowWire`, so a row that reaches a
/// caller has already been checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(try_from = "ContactListRowWire")]
pub struct ContactListRow {
    pub peer: ContactPeer,
    pub state: ContactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_prepare_input: Option<ContactNextPrepareInput>,
    pub granted_to_peer_scopes: Vec<ContactScope>,
    pub granted_by_peer_scopes: Vec<ContactScope>,
    pub bidirectional_scopes: Vec<ContactScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scopes: Option<Vec<ContactScope>>,
    /// Portable checkpoint plus the exact remaining tail. Present only after
    /// both participant Stations have committed the same checkpoint and the
    /// caller explicitly exports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_evidence: Option<ContactContinuityEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
    /// Active agents controlled by this contact that currently accept direct
    /// messages from the authenticated actor. Viewer-specific and fail-closed;
    /// clients must not infer it from public selector claims.
    #[serde(
        rename = "contact_agents",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub contact_agent_projections: Vec<ContactAgentProjection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactListRowWire {
    peer: ContactPeer,
    state: ContactState,
    #[serde(default)]
    request_event_ref: Option<EventId>,
    #[serde(default)]
    request_message: Option<String>,
    #[serde(default)]
    response_event_ref: Option<EventId>,
    #[serde(default)]
    tombstone_event_ref: Option<EventId>,
    #[serde(default)]
    next_prepare_input: Option<ContactNextPrepareInput>,
    granted_to_peer_scopes: Vec<ContactScope>,
    granted_by_peer_scopes: Vec<ContactScope>,
    bidirectional_scopes: Vec<ContactScope>,
    #[serde(default)]
    effective_scopes: Option<Vec<ContactScope>>,
    #[serde(default)]
    continuity_evidence: Option<ContactContinuityEvidence>,
    #[serde(default)]
    direct_conversation: Option<DirectConversationSummary>,
    #[serde(default)]
    contact_agents: Vec<ContactAgentProjection>,
}

impl TryFrom<ContactListRowWire> for ContactListRow {
    type Error = arkret_wire::WireError;

    fn try_from(wire: ContactListRowWire) -> arkret_wire::Result<Self> {
        let row = Self {
            peer: wire.peer,
            state: wire.state,
            request_event_ref: wire.request_event_ref,
            request_message: wire.request_message,
            response_event_ref: wire.response_event_ref,
            tombstone_event_ref: wire.tombstone_event_ref,
            next_prepare_input: wire.next_prepare_input,
            granted_to_peer_scopes: wire.granted_to_peer_scopes,
            granted_by_peer_scopes: wire.granted_by_peer_scopes,
            bidirectional_scopes: wire.bidirectional_scopes,
            effective_scopes: wire.effective_scopes,
            continuity_evidence: wire.continuity_evidence,
            direct_conversation: wire.direct_conversation,
            contact_agent_projections: wire.contact_agents,
        };
        row.validate_shape()?;
        Ok(row)
    }
}

impl ContactListRow {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if self.state == ContactState::PendingIncoming && self.request_event_ref.is_none() {
            return Err(arkret_wire::WireError::Protocol(
                "pending_incoming requires request_event_ref".to_owned(),
            ));
        }
        if let Some(message) = &self.request_message
            && (self.state != ContactState::PendingIncoming
                || !(1..=2000).contains(&message.chars().count()))
        {
            return Err(arkret_wire::WireError::Protocol(
                "request_message requires pending_incoming and 1..2000 characters".to_owned(),
            ));
        }
        if (self.state == ContactState::Accepted) != self.next_prepare_input.is_some() {
            return Err(arkret_wire::WireError::Protocol(
                "next_prepare_input must be present exactly for accepted Contact rows".to_owned(),
            ));
        }
        if let Some(input) = &self.next_prepare_input {
            input.validate_shape()?;
        }
        if self
            .effective_scopes
            .as_ref()
            .is_some_and(|scopes| scopes != &self.bidirectional_scopes)
        {
            return Err(arkret_wire::WireError::Protocol(
                "effective_scopes must equal bidirectional_scopes when present".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Viewer-specific current Contact rows.
/// `contact-operations.schema.json#/$defs/contact_list`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactList {
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<arkret_wire::Cursor>,
    pub has_more: bool,
}

#[cfg(test)]
mod contact_list_projection_tests {
    use serde_json::{Value, json};

    use super::*;

    const REALM: &str = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    const STRAND: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
    const BINDING_EVENT: &str = "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REQUEST_EVENT: &str = "ak:event:Abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const RESPONSE_EVENT: &str = "ak:event:Accccccccccccccccccccccccccccccccccccccccccc";
    const ROUND: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const AVATAR: &str =
        "ak:blob:sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn human_peer() -> Value {
        json!({
            "kind": "human",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkpeerprincipal",
                "station_id": "ak:did_core:webvh:z6mkpeerstation"
            }
        })
    }

    fn direct_conversation() -> Value {
        json!({
            "realm_id": REALM,
            "main_strand_id": STRAND,
            "binding_event_ref": BINDING_EVENT,
            "state": "found"
        })
    }

    /// The member order here is the schema `properties` order of
    /// `contact_list_row`; the round-trip assertion below therefore fails if a
    /// field is ever reordered or renamed in the Rust declaration.
    fn accepted_row() -> Value {
        json!({
            "peer": human_peer(),
            "state": "accepted",
            "request_event_ref": REQUEST_EVENT,
            "response_event_ref": RESPONSE_EVENT,
            "next_prepare_input": {
                "contact_round_id": ROUND,
                "version": 2,
                "predecessor_event_ref": RESPONSE_EVENT
            },
            "granted_to_peer_scopes": ["invite", "direct_message"],
            "granted_by_peer_scopes": ["direct_message"],
            "bidirectional_scopes": ["direct_message"],
            "effective_scopes": ["direct_message"],
            "direct_conversation": direct_conversation(),
            "contact_agents": [{
                "actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkagentprincipal",
                        "station_id": "ak:did_core:webvh:z6mkpeerstation"
                    }
                },
                "controller_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkpeerprincipal",
                    "station_id": "ak:did_core:webvh:z6mkpeerstation"
                },
                "display_name": "Scheduler",
                "agent_slug": "scheduler",
                "avatar_blob_ref": AVATAR,
                "direct_conversation": direct_conversation()
            }]
        })
    }

    #[test]
    fn accepted_row_round_trips_byte_for_byte() {
        let row: ContactListRow = serde_json::from_value(accepted_row()).unwrap();
        assert_eq!(row.state, ContactState::Accepted);
        assert_eq!(
            row.direct_conversation.as_ref().unwrap().state,
            DirectConversationSummaryState::Found
        );
        assert_eq!(row.contact_agent_projections.len(), 1);
        assert_eq!(serde_json::to_value(&row).unwrap(), accepted_row());
    }

    #[test]
    fn contact_list_carries_typed_rows() {
        let list: ContactList = serde_json::from_value(json!({
            "contacts": [accepted_row()],
            "has_more": false
        }))
        .unwrap();
        assert_eq!(list.contacts.len(), 1);
        assert!(!list.has_more);
        assert_eq!(list.contacts[0].state, ContactState::Accepted);
    }

    #[test]
    fn every_contact_state_is_the_schema_enum() {
        for (wire, expected) in [
            ("pending_outgoing", ContactState::PendingOutgoing),
            ("pending_incoming", ContactState::PendingIncoming),
            ("accepted", ContactState::Accepted),
            ("rejected", ContactState::Rejected),
            ("expired", ContactState::Expired),
            ("tombstoned", ContactState::Tombstoned),
        ] {
            let decoded: ContactState = serde_json::from_value(json!(wire)).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(serde_json::to_value(decoded).unwrap(), json!(wire));
        }
        assert!(serde_json::from_value::<ContactState>(json!("blocked")).is_err());
    }

    #[test]
    fn next_prepare_input_is_present_exactly_for_accepted() {
        let mut without = accepted_row();
        without
            .as_object_mut()
            .unwrap()
            .remove("next_prepare_input");
        assert!(serde_json::from_value::<ContactListRow>(without).is_err());

        let mut pending = accepted_row();
        let object = pending.as_object_mut().unwrap();
        object.insert("state".to_owned(), json!("pending_incoming"));
        object.remove("effective_scopes");
        assert!(serde_json::from_value::<ContactListRow>(pending.clone()).is_err());

        pending
            .as_object_mut()
            .unwrap()
            .remove("next_prepare_input");
        let row: ContactListRow = serde_json::from_value(pending).unwrap();
        assert_eq!(row.state, ContactState::PendingIncoming);
        assert!(row.next_prepare_input.is_none());
    }

    #[test]
    fn pending_incoming_requires_its_request_event_ref() {
        let mut pending = accepted_row();
        let object = pending.as_object_mut().unwrap();
        object.insert("state".to_owned(), json!("pending_incoming"));
        object.remove("next_prepare_input");
        object.remove("request_event_ref");
        assert!(serde_json::from_value::<ContactListRow>(pending).is_err());
    }

    #[test]
    fn request_message_belongs_only_to_pending_incoming() {
        let mut accepted = accepted_row();
        accepted
            .as_object_mut()
            .unwrap()
            .insert("request_message".to_owned(), json!("hello"));
        assert!(serde_json::from_value::<ContactListRow>(accepted).is_err());

        let mut pending = accepted_row();
        let object = pending.as_object_mut().unwrap();
        object.insert("state".to_owned(), json!("pending_incoming"));
        object.remove("next_prepare_input");
        object.insert("request_message".to_owned(), json!("hello"));
        let row: ContactListRow = serde_json::from_value(pending.clone()).unwrap();
        assert_eq!(row.request_message.as_deref(), Some("hello"));

        pending
            .as_object_mut()
            .unwrap()
            .insert("request_message".to_owned(), json!("x".repeat(2001)));
        assert!(serde_json::from_value::<ContactListRow>(pending).is_err());
    }

    #[test]
    fn effective_scopes_must_equal_bidirectional_scopes() {
        let mut row = accepted_row();
        row.as_object_mut()
            .unwrap()
            .insert("effective_scopes".to_owned(), json!(["invite"]));
        assert!(serde_json::from_value::<ContactListRow>(row).is_err());
    }

    #[test]
    fn rows_and_their_nested_projections_reject_unknown_members() {
        let mut row = accepted_row();
        row.as_object_mut()
            .unwrap()
            .insert("effective_scope".to_owned(), json!(["invite"]));
        assert!(serde_json::from_value::<ContactListRow>(row).is_err());

        let mut summary = direct_conversation();
        summary
            .as_object_mut()
            .unwrap()
            .insert("strand_id".to_owned(), json!(STRAND));
        assert!(serde_json::from_value::<DirectConversationSummary>(summary).is_err());

        let mut projection = accepted_row()["contact_agents"][0].clone();
        projection
            .as_object_mut()
            .unwrap()
            .insert("avatar".to_owned(), json!("x"));
        assert!(serde_json::from_value::<ContactAgentProjection>(projection).is_err());
    }

    #[test]
    fn direct_conversation_summary_state_is_closed() {
        for (wire, expected) in [
            ("found", DirectConversationSummaryState::Found),
            ("suspended", DirectConversationSummaryState::Suspended),
        ] {
            let mut summary = direct_conversation();
            summary
                .as_object_mut()
                .unwrap()
                .insert("state".to_owned(), json!(wire));
            let decoded: DirectConversationSummary = serde_json::from_value(summary).unwrap();
            assert_eq!(decoded.state, expected);
        }
        let mut summary = direct_conversation();
        summary
            .as_object_mut()
            .unwrap()
            .insert("state".to_owned(), json!("creating"));
        assert!(serde_json::from_value::<DirectConversationSummary>(summary).is_err());
    }

    #[test]
    fn a_stale_next_prepare_input_version_is_refused() {
        let mut row = accepted_row();
        row["next_prepare_input"]
            .as_object_mut()
            .unwrap()
            .insert("version".to_owned(), json!(1));
        assert!(serde_json::from_value::<ContactListRow>(row).is_err());
    }
}
