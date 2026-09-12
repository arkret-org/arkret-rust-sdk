use arkret_wire::{
    AccountId, ActorId, ControlProposalAck, Did, DidCoreId, Event, EventId, Hash, IdempotencyKey,
    ProtocolOperationId, ProtocolSignature, ReservationHandle,
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
/// receipt or lineage. It has no reusable authorization or notary semantics.
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
    pub accepted_frontier: Vec<EventId>,
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
    accepted_frontier: Vec<EventId>,
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
        accepted_frontier: Vec<EventId>,
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
            accepted_frontier,
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
            accepted_frontier: unsigned.accepted_frontier,
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
            accepted_frontier: self.accepted_frontier.clone(),
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
    pub cas_frontier: Vec<EventId>,
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
            || self.cas_frontier.is_empty()
            || !self.cas_frontier.windows(2).all(|pair| pair[0] < pair[1])
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

    #[test]
    fn checkpoint_core_rejects_retired_root_basis_digest_member() {
        let value = serde_json::json!({
            "root_basis_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let error = serde_json::from_value::<BilateralContinuityCheckpointCore>(value).unwrap_err();
        assert!(error.to_string().contains("root_basis_digest"));
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

#[cfg(test)]
mod event_digest_derivation_tests {
    use arkret_wire::{Base64UrlString, DidUrl};
    use chrono::{DateTime, Utc};

    use super::*;

    const EVENT_REF: &str = "ak:event:AWAIb405aEEenVBHYRG-ZfDs-f9_j3E67tWGI36uYxFJ";
    const EVENT_DIGEST: &str =
        "sha256:60086f8d3968411e9d50476111be65f0ecf9ff7f8f713aeed586237eae631149";

    fn hash(fill: char) -> Hash {
        Hash::new(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
    }

    fn timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-08T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn signature() -> ProtocolSignature {
        ProtocolSignature {
            verification_method: DidUrl::new("did:web:ps.example#key-1").unwrap(),
            created_at: timestamp(),
            jws: Base64UrlString::new("AA").unwrap(),
        }
    }

    fn account(principal: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        )
    }

    fn account_actor(principal: &str) -> ActorId {
        ActorId::account(account(principal))
    }

    fn producer_signer() -> ContactProducerSigner {
        ContactProducerSigner::Direct(ContactDirectProducerSigner {
            verification_method: DidUrl::new("did:web:holder.example#device").unwrap(),
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                [17; 32],
            ))
            .unwrap(),
        })
    }
    #[test]
    fn contact_producer_signer_rejects_noncanonical_or_non_ed25519_keys() {
        let valid = serde_json::to_value(producer_signer()).unwrap();
        let decoded: ContactProducerSigner = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(decoded.public_key_bytes().unwrap(), [17; 32]);
        for key in [
            arkret_canonical::base64url_encode([17; 31]),
            arkret_canonical::base64url_encode([17; 33]),
            format!("{}=", valid["public_key_b64u"].as_str().unwrap()),
        ] {
            let mut bad = valid.clone();
            bad["public_key_b64u"] = serde_json::Value::String(key);
            assert!(serde_json::from_value::<ContactProducerSigner>(bad).is_err());
        }
        let mut unknown = valid.clone();
        unknown["key_kind"] = serde_json::json!("ed25519");
        assert!(serde_json::from_value::<ContactProducerSigner>(unknown).is_err());
        let mut noncanonical = valid;
        let key = noncanonical["public_key_b64u"].as_str().unwrap();
        let mut bytes = key.as_bytes().to_vec();
        // A raw 32-byte key has two unused low bits in the final base64 symbol.
        *bytes.last_mut().unwrap() = b'F';
        noncanonical["public_key_b64u"] = serde_json::json!(String::from_utf8(bytes).unwrap());
        assert!(serde_json::from_value::<ContactProducerSigner>(noncanonical).is_err());
    }

    #[test]
    fn contact_producer_branches_preserve_signed_locator_and_reject_open_shapes() {
        let kat = contact_kat();
        for case in kat["delegated_actor_locator_kat"]["cases"]
            .as_array()
            .unwrap()
        {
            let receipt: RequestAcceptanceReceipt =
                serde_json::from_value(case["signed_request_receipt"].clone()).unwrap();
            receipt.validate_shape().unwrap();
            assert_eq!(
                String::from_utf8(receipt.canonical_signing_bytes().unwrap()).unwrap(),
                case["canonical_unsigned"].as_str().unwrap()
            );
            let producer = &receipt.core.producer_signer;
            let delegated = case["event_identity"].get("executed_by").is_some();
            assert_eq!(producer.delegated_actor_did().is_some(), delegated);
            assert_eq!(
                serde_json::to_value(&receipt).unwrap(),
                case["signed_request_receipt"]
            );
            if delegated {
                assert!(
                    producer
                        .validate_for_holder(&ContactPeer::Human {
                            account_id: receipt
                                .core
                                .holder
                                .contact_actor_id()
                                .as_account_id()
                                .unwrap()
                                .clone(),
                        })
                        .is_err()
                );
                let mut null_locator = serde_json::to_value(producer).unwrap();
                null_locator["delegated_actor_did"] = serde_json::Value::Null;
                assert!(serde_json::from_value::<ContactProducerSigner>(null_locator).is_err());
                let mut unknown = serde_json::to_value(producer).unwrap();
                unknown["actor_did"] = unknown["delegated_actor_did"].clone();
                assert!(serde_json::from_value::<ContactProducerSigner>(unknown).is_err());
            }
        }
    }

    fn contact_kat() -> serde_json::Value {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
            .expect("Contact vectors require the spec artifacts");
        serde_json::from_str(
            &std::fs::read_to_string(artifacts.join("fixtures/contact-round-kat.json")).unwrap(),
        )
        .unwrap()
    }
    fn request_receipt() -> RequestAcceptanceReceipt {
        RequestAcceptanceReceipt {
            core: RequestAcceptanceReceiptCore {
                holder: ContactPeer::Human {
                    account_id: account("ak:did_core:webvh:z6mkfixturealice"),
                },
                peer: ContactPeer::Human {
                    account_id: account("ak:did_core:webvh:z6mkfixturebob"),
                },
                slot_version: 1,
                slot_predecessor: None,
                previous_terminal_contact_round_id: None,
                request_event_ref: EventId::new(EVENT_REF).unwrap(),
                producer_signer: producer_signer(),
                source_checkpoint: hash('a'),
                accepted_at: timestamp(),
                issuer_id: DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            },
            receipt_digest: hash('b'),
            signature: signature(),
        }
    }

    #[test]
    fn contact_round_order_matches_normative_kat_and_rejects_noncanonical_input() {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().expect(
            "Contact round conformance requires ARKRET_SPEC_ARTIFACTS or the spec co-checkout",
        );
        let fixture: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(artifacts.join("fixtures/contact-round-kat.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(fixture["cases"].as_array().unwrap().len(), 3);
        for case in fixture["cases"].as_array().unwrap() {
            let round: ContactRound =
                serde_json::from_value(case["contact_round"].clone()).unwrap();
            assert_eq!(
                arkret_canonical::canonical_json_bytes(&round).unwrap(),
                case["canonical_contact_round"].as_str().unwrap().as_bytes()
            );
            assert_eq!(
                crate::direct_conversation_ops::contact_round_id(&round)
                    .unwrap()
                    .as_str(),
                case["expected_contact_round_id"].as_str().unwrap()
            );
        }
        let negatives = fixture["request_ordering"]["negative_cases"]
            .as_array()
            .unwrap();
        assert_eq!(negatives.len(), 3);
        for case in negatives {
            let round: ContactRound =
                serde_json::from_value(case["contact_round"].clone()).unwrap();
            let before = arkret_canonical::canonical_json_bytes(&round).unwrap();
            assert!(
                crate::direct_conversation_ops::contact_round_id(&round).is_err(),
                "{}",
                case["name"]
            );
            assert_eq!(
                before,
                arkret_canonical::canonical_json_bytes(&round).unwrap(),
                "validation must not normalize incoming bytes"
            );
        }
        let mut swapped: ContactRound =
            serde_json::from_value(fixture["cases"][0]["contact_round"].clone()).unwrap();
        let ContactRound::Normal {
            sorted_pair_member_ids,
            ..
        } = &mut swapped
        else {
            unreachable!()
        };
        sorted_pair_member_ids.swap(0, 1);
        assert!(crate::direct_conversation_ops::contact_round_id(&swapped).is_err());
    }

    #[test]
    fn contact_round_order_is_independent_of_receipt_arrival_order() {
        let mut first = request_receipt();
        first.core.request_event_ref =
            EventId::new("ak:event:AQ0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let mut second = request_receipt();
        second.core.holder = first.core.peer.clone();
        second.core.peer = first.core.holder.clone();
        second.core.request_event_ref =
            EventId::new("ak:event:AQYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let forward =
            ContactRound::glare_from_request_receipts(&[first.clone(), second.clone()]).unwrap();
        let reversed =
            ContactRound::glare_from_request_receipts(&[second.clone(), first.clone()]).unwrap();
        assert_eq!(forward, reversed);
        let ContactRound::Glare { requests, .. } = &forward else {
            unreachable!()
        };
        assert_eq!(requests[0].request_event_ref, first.core.request_event_ref);
        assert_eq!(
            requests[0].request_acceptance_receipt_digest.as_str(),
            arkret_canonical::canonical_sha256(&first).unwrap()
        );
        // Same ref with a different signed receipt is still a duplicate, not a tie to sort.
        second.core.request_event_ref = first.core.request_event_ref.clone();
        assert!(ContactRound::glare_from_request_receipts(&[first.clone(), second]).is_err());
        assert!(ContactRound::glare_from_request_receipts(&[first.clone(), first]).is_err());
    }

    #[test]
    fn all_contact_event_digests_are_derived_from_complete_event_ids() {
        let request = request_receipt();
        assert_eq!(request.core.request_digest().as_str(), EVENT_DIGEST);

        let proof = ContactCurrentProof {
            contact_round_id: hash('c'),
            issuer_id: DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            peer: ContactPeer::Human {
                account_id: account("ak:did_core:webvh:z6mkfixturebob"),
            },
            terminal: false,
            head_event_ref: EventId::new(EVENT_REF).unwrap(),
            accepted_frontier: vec![EventId::new(EVENT_REF).unwrap()],
            complete_through: 1,
            fresh_until: timestamp(),
            signature: signature(),
        };
        assert_eq!(proof.head_digest().as_str(), EVENT_DIGEST);

        let response = NormalResponseAcceptanceReceipt {
            contact_round_id: hash('d'),
            request_receipt: request.clone(),
            response_event_ref: EventId::new(EVENT_REF).unwrap(),
            producer_signer: producer_signer(),
            outgoing_slot_absence_digest: hash('e'),
            accepted_at: timestamp(),
            issuer_id: DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            signature: signature(),
        };
        assert_eq!(response.response_digest().as_str(), EVENT_DIGEST);

        let reject = RejectAcceptanceReceipt {
            request_receipt: request,
            reject_event_ref: EventId::new(EVENT_REF).unwrap(),
            producer_signer: producer_signer(),
            accepted_at: timestamp(),
            issuer_id: DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            signature: signature(),
        };
        assert_eq!(reject.reject_digest().as_str(), EVENT_DIGEST);

        let mirror = PeerContactMirrorReceipt {
            domain: PeerContactMirrorReceiptDomain::V1,
            request_digest: hash('f'),
            signed_event_ref: EventId::new(EVENT_REF).unwrap(),
            outcome: PeerContactOutcome::Accepted,
            recipient_id: DidCoreId::new("ak:did_core:web:peer.example").unwrap(),
            received_at: timestamp(),
            issuer_id: DidCoreId::new("ak:did_core:web:peer.example").unwrap(),
            signature: signature(),
        };
        assert_eq!(mirror.signed_event_digest().as_str(), EVENT_DIGEST);
    }

    #[test]
    fn contact_source_signing_builders_match_all_normative_unsigned_transcripts() {
        let fixture = contact_kat();
        for case in fixture["producer_signer_kat"]["cases"].as_array().unwrap() {
            let source_signature: ProtocolSignature =
                serde_json::from_value(case["signed_object"]["signature"].clone()).unwrap();
            let expected = case["canonical_unsigned"].as_str().unwrap().as_bytes();
            let sign = |bytes: &[u8]| {
                assert_eq!(bytes, expected, "{}", case["name"]);
                Ok(source_signature)
            };
            let actual = match case["schema_def"].as_str().unwrap() {
                "request_acceptance_receipt" => {
                    let value: RequestAcceptanceReceipt =
                        serde_json::from_value(case["signed_object"].clone()).unwrap();
                    let signed = RequestAcceptanceReceipt::sign_with(value.core, sign).unwrap();
                    assert_eq!(signed.canonical_signing_bytes().unwrap(), expected);
                    serde_json::to_value(signed).unwrap()
                }
                "normal_response_acceptance_receipt" => {
                    let v: NormalResponseAcceptanceReceipt =
                        serde_json::from_value(case["signed_object"].clone()).unwrap();
                    let signed = NormalResponseAcceptanceReceipt::sign_with(
                        v.contact_round_id,
                        v.request_receipt,
                        v.response_event_ref,
                        v.producer_signer,
                        v.outgoing_slot_absence_digest,
                        v.accepted_at,
                        v.issuer_id,
                        sign,
                    )
                    .unwrap();
                    assert_eq!(signed.canonical_signing_bytes().unwrap(), expected);
                    serde_json::to_value(signed).unwrap()
                }
                "reject_acceptance_receipt" => {
                    let v: RejectAcceptanceReceipt =
                        serde_json::from_value(case["signed_object"].clone()).unwrap();
                    let signed = RejectAcceptanceReceipt::sign_with(
                        v.request_receipt,
                        v.reject_event_ref,
                        v.producer_signer,
                        v.accepted_at,
                        v.issuer_id,
                        sign,
                    )
                    .unwrap();
                    assert_eq!(signed.canonical_signing_bytes().unwrap(), expected);
                    serde_json::to_value(signed).unwrap()
                }
                "contact_lineage" => {
                    let v: ContactLineage =
                        serde_json::from_value(case["signed_object"].clone()).unwrap();
                    let signed = ContactLineage::sign_with(
                        v.contact_round_id,
                        v.issuer,
                        v.peer,
                        v.version,
                        v.predecessor_event_ref,
                        v.event_ref,
                        v.producer_signer,
                        v.granted_to_peer_scopes,
                        v.terminal,
                        sign,
                    )
                    .unwrap();
                    assert_eq!(signed.canonical_signing_bytes().unwrap(), expected);
                    serde_json::to_value(signed).unwrap()
                }
                kind => panic!("unhandled normative source signing case: {kind}"),
            };
            assert_eq!(actual, case["signed_object"]);
        }
    }

    #[test]
    fn contact_signing_failure_never_constructs_a_placeholder_signed_object() {
        let error = RequestAcceptanceReceipt::sign_with(request_receipt().core, |_| {
            Err(arkret_wire::WireError::Protocol(
                "historical key unavailable".into(),
            ))
        })
        .unwrap_err();
        assert!(error.to_string().contains("historical key unavailable"));
        let current = ContactCurrentProof::sign_with(
            hash('c'),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            request_receipt().core.peer,
            false,
            EventId::new(EVENT_REF).unwrap(),
            vec![EventId::new(EVENT_REF).unwrap()],
            4,
            timestamp(),
            |_| {
                Err(arkret_wire::WireError::Protocol(
                    "current source key unavailable".into(),
                ))
            },
        );
        assert!(
            current
                .unwrap_err()
                .to_string()
                .contains("current source key unavailable")
        );
    }

    #[test]
    fn outgoing_slot_absence_transcript_matches_normative_kat() {
        let fixture = contact_kat();
        let case = &fixture["outgoing_slot_absence"]["case"];
        let transcript: OutgoingSlotAbsenceTranscript =
            serde_json::from_value(case["transcript"].clone()).unwrap();
        assert_eq!(
            transcript.digest().unwrap().as_str(),
            case["expected_digest"].as_str().unwrap()
        );

        let mut swapped = transcript.clone();
        swapped.sorted_pair_member_ids.swap(0, 1);
        assert!(swapped.validate_shape().is_err());
        let mut duplicate_direction = transcript;
        duplicate_direction.request_slot_owner =
            account_actor("ak:did_core:webvh:z6mkfixtureoutside");
        assert!(duplicate_direction.validate_shape().is_err());
    }
}
