//! Real producer/source signatures and exact bilateral Contact originals.
//!
//! These are protocol fixtures, not evidence that a live Station accepted them.
//! Reject is an alternative to Response, never a successor to an accepted round.

use anyhow::{Result, ensure};
use arkret_canonical::DigestSuite;
use arkret_event_draft::{EventSpec, TypedEventDraft};
use arkret_models_collaboration::contact_operations::*;
use arkret_models_collaboration::events_payloads::contact::*;
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event};
use arkret_wire::{AccountId, Base64UrlString, DidUrl, Event, EventId, Hash, RealmId, ScopeRef};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::service_identity::ServiceIdentityFixture;

pub struct ContactParticipant<'a> {
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub verification_method: DidUrl,
    pub signing_seed: [u8; 32],
    pub authority: &'a ServiceIdentityFixture,
}

impl ContactParticipant<'_> {
    pub fn peer(&self) -> ContactPeer {
        ContactPeer::Human {
            account_id: self.account_id.clone(),
        }
    }

    pub fn producer(&self) -> Result<ContactProducerSigner> {
        Ok(ContactProducerSigner::direct(
            self.verification_method.clone(),
            Base64UrlString::new(arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&self.signing_seed)
                    .verifying_key()
                    .to_bytes(),
            ))
            .map_err(anyhow::Error::msg)?,
        )?)
    }

    pub fn event<K: EventSpec>(&self, payload: K::Payload, at: DateTime<Utc>) -> Result<Event> {
        ensure!(
            self.account_id.station_id == self.authority.service_id,
            "Contact holder Station mismatch"
        );
        let did =
            arkret_wire::Did::new(self.verification_method.as_str().split('#').next().unwrap())?;
        ensure!(
            arkret_wire::project_did_to_core_id(&did)? == self.account_id.principal_id,
            "Contact producer DID mismatch"
        );
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            self.signing_seed,
            did,
            self.verification_method.clone(),
        );
        let mut authored = TypedEventDraft::<K>::new(
            ScopeRef::Realm {
                realm_id: self.realm_id.clone(),
            },
            self.peer().contact_actor_id(),
            payload,
        )?
        .author_with_digest_suite(at, DigestSuite::Sha256)?;
        sign_event(
            &mut authored,
            &signer,
            SignEventOptions::new().with_created_at(at),
        )?;
        Ok(authored.into_event())
    }

    fn address(&self) -> PeerContactAddress {
        PeerContactAddress::for_recipient(
            self.peer(),
            ServiceResolutionCarrier::Inline {
                inline: self.authority.resolution.clone(),
            },
        )
    }

    pub fn current(
        &self,
        peer: ContactPeer,
        round: Hash,
        head: EventId,
        version: u64,
        scope_instances: Vec<ContactScopeInstance>,
        at: DateTime<Utc>,
    ) -> Result<ContactCurrentProof> {
        Ok(ContactCurrentProof::sign_with(
            contact_trust_domain(),
            self.peer(),
            peer,
            Some(round.clone()),
            Some(round),
            self.authority.service_id.clone(),
            head,
            version,
            scope_instances,
            None,
            at,
            at + Duration::minutes(15),
            |bytes| self.authority.sign(bytes, at),
        )?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactCeremonyFixture {
    pub request: PeerContactSubmitRequestBody,
    pub response: PeerContactSubmitRequestBody,
    pub reject: PeerContactSubmitRequestBody,
    pub scope_update: PeerContactSubmitRequestBody,
    pub tombstone: PeerContactSubmitRequestBody,
    pub terminal_acknowledgement: ContactCurrentProof,
    pub response_lineage: ContactLineage,
    pub round: ContactRoundEvidenceBundle,
    pub outgoing_slot_absence: OutgoingSlotAbsenceTranscript,
}

impl ContactCeremonyFixture {
    /// A first normal round, one narrowing update, and a terminal successor.
    /// Each direction has its own holder key; each receipt uses that holder's Station.
    pub fn normal(
        requester: &ContactParticipant<'_>,
        responder: &ContactParticipant<'_>,
        at: DateTime<Utc>,
    ) -> Result<Self> {
        use arkret_wire::event_spec;
        ensure!(
            requester.peer() != responder.peer(),
            "Contact needs two participants"
        );
        let intro = ContactIntroductionEvidence::ExplicitAddress;
        let request = requester.event::<event_spec::ContactRequested>(
            ContactRequestedPayload {
                trust_domain_id: contact_trust_domain(),
                version: 1,
                predecessor_event_ref: None,
                peer: responder.peer(),
                granted_to_peer_scopes: vec![ContactScope::Invite, ContactScope::DirectMessage],
                introduction_evidence_digest: Hash::new(
                    arkret_canonical::domain_prefixed_canonical_sha256(
                        "ak.contact.introduction-evidence.v1",
                        &intro,
                    )?,
                )?,
                initial_contact_round_id: None,
                message: None,
            },
            at,
        )?;
        let receipt = RequestAcceptanceReceipt::sign_with(
            RequestAcceptanceReceiptCore {
                holder: requester.peer(),
                peer: responder.peer(),
                version: 1,
                predecessor_event_ref: None,
                trust_domain_id: contact_trust_domain(),
                initial_contact_round_id: None,
                request_event_ref: request.event_id.clone(),
                producer_signer: requester.producer()?,
                source_checkpoint: Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(
                    arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
                    &serde_json::json!({"event_ref":request.event_id,"event_digest":request.event_id.event_digest()}),
                )?)?,
                accepted_at: at,
                issuer_id: requester.authority.service_id.clone(),
            },
            |bytes| requester.authority.sign(bytes, at),
        )?;
        let mut pair = [
            requester.peer().contact_actor_id(),
            responder.peer().contact_actor_id(),
        ];
        pair.sort_by_cached_key(|actor| arkret_canonical::canonical_json_bytes(actor).unwrap());
        let core = ContactRound::Normal {
            sorted_pair_member_ids: pair.clone(),
            request_event_ref: request.event_id.clone(),
            request_acceptance_receipt_digest: receipt.computed_receipt_digest()?,
        };
        core.validate_canonical_order()?;
        let round_id = Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(
            "ak.contact.round.v1",
            &core,
        )?)?;
        let accepted = responder.event::<event_spec::ContactAccepted>(
            ContactAcceptedPayload {
                trust_domain_id: contact_trust_domain(),
                predecessor_event_ref: None,
                peer: requester.peer(),
                contact_round_id: round_id.clone(),
                version: 1,
                request_event_ref: request.event_id.clone(),
                request_acceptance_receipt_digest: receipt.computed_receipt_digest()?,
                initial_contact_round_id: None,
                granted_to_peer_scopes: vec![ContactScope::Invite, ContactScope::DirectMessage],
            },
            at,
        )?;
        let absence = OutgoingSlotAbsenceTranscript {
            sorted_pair_member_ids: pair,
            request_slot_owner: responder.peer().contact_actor_id(),
            contact_round_id: round_id.clone(),
            trust_domain_id: contact_trust_domain(),
            predecessor_event_ref: None,
            version: 1,
            request_event_ref: request.event_id.clone(),
            observed_at: at,
            outgoing_request_state: OutgoingRequestState::Absent,
        };
        let response_receipt = NormalResponseAcceptanceReceipt::sign_with(
            contact_trust_domain(),
            None,
            1,
            None,
            round_id.clone(),
            receipt.clone(),
            accepted.event_id.clone(),
            responder.producer()?,
            absence.digest()?,
            at,
            responder.authority.service_id.clone(),
            |bytes| responder.authority.sign(bytes, at),
        )?;
        let lineage = |event: &Event,
                       version,
                       predecessor,
                       scopes,
                       _terminal: Option<bool>|
         -> Result<ContactLineage> {
            Ok(ContactLineage::sign_with(
                contact_trust_domain(),
                if version == 1 {
                    None
                } else {
                    Some(round_id.clone())
                },
                Some(round_id.clone()),
                responder.peer(),
                requester.peer(),
                version,
                predecessor,
                event.event_id.clone(),
                responder.producer()?,
                scopes,
                at,
                |bytes| responder.authority.sign(bytes, at),
            )?)
        };
        let response_lineage = lineage(
            &accepted,
            1,
            None,
            vec![ContactScope::Invite, ContactScope::DirectMessage],
            None,
        )?;
        let initial_request = requester.current(
            responder.peer(),
            round_id.clone(),
            request.event_id.clone(),
            1,
            [ContactScope::Invite, ContactScope::DirectMessage]
                .into_iter()
                .map(|contact_scope| ContactScopeInstance {
                    contact_scope,
                    grant_event_ref: request.event_id.clone(),
                })
                .collect(),
            at,
        )?;
        let initial_response = responder.current(
            requester.peer(),
            round_id.clone(),
            accepted.event_id.clone(),
            1,
            [ContactScope::Invite, ContactScope::DirectMessage]
                .into_iter()
                .map(|contact_scope| ContactScopeInstance {
                    contact_scope,
                    grant_event_ref: accepted.event_id.clone(),
                })
                .collect(),
            at,
        )?;
        let reject = responder.event::<event_spec::ContactRejected>(
            ContactRejectedPayload {
                trust_domain_id: contact_trust_domain(),
                initial_contact_round_id: None,
                version: 1,
                predecessor_event_ref: None,
                peer: requester.peer(),
                request_event_ref: request.event_id.clone(),
                request_acceptance_receipt_digest: receipt.computed_receipt_digest()?,
                reason: None,
            },
            at,
        )?;
        let reject_receipt = RejectAcceptanceReceipt::sign_with(
            contact_trust_domain(),
            None,
            1,
            None,
            receipt.clone(),
            reject.event_id.clone(),
            responder.producer()?,
            at,
            responder.authority.service_id.clone(),
            |bytes| responder.authority.sign(bytes, at),
        )?;
        let update = responder.event::<event_spec::ContactScopeUpdate>(
            ContactScopeUpdatePayload {
                trust_domain_id: contact_trust_domain(),
                initial_contact_round_id: round_id.clone(),
                schema: ContactScopeUpdateSchema::V1,
                peer: requester.peer(),
                contact_round_id: round_id.clone(),
                version: 2,
                predecessor_event_ref: accepted.event_id.clone(),
                granted_to_peer_scopes: vec![ContactScope::DirectMessage],
            },
            at,
        )?;
        let updated = lineage(
            &update,
            2,
            Some(accepted.event_id.clone()),
            vec![ContactScope::DirectMessage],
            None,
        )?;
        let update_proof = responder.current(
            requester.peer(),
            round_id.clone(),
            update.event_id.clone(),
            2,
            vec![ContactScopeInstance {
                contact_scope: ContactScope::DirectMessage,
                grant_event_ref: accepted.event_id.clone(),
            }],
            at,
        )?;
        let terminal = responder.event::<event_spec::ContactTombstone>(
            ContactTombstonedPayload {
                trust_domain_id: contact_trust_domain(),
                initial_contact_round_id: round_id.clone(),
                peer: requester.peer(),
                contact_round_id: round_id.clone(),
                version: 3,
                predecessor_event_ref: update.event_id.clone(),
                reason: None,
            },
            at,
        )?;
        let terminated = lineage(
            &terminal,
            3,
            Some(update.event_id.clone()),
            vec![],
            Some(true),
        )?;
        let key = |value| arkret_wire::IdempotencyKey::new(value).map_err(anyhow::Error::msg);
        // Receipt of the peer's verified terminal fences this direction without
        // inventing a new holder Event or incrementing its directional version.
        let closure = ContactRoundClosure {
            contact_round_id: round_id.clone(),
            operation: ContactTombstoneEvidence {
                kind: ContactTombstoneEvidenceKind::Tombstone,
                signed_event: terminal.clone(),
                lineage: terminated.clone(),
            },
        };
        let terminal_acknowledgement = ContactCurrentProof::sign_with(
            contact_trust_domain(),
            requester.peer(),
            responder.peer(),
            Some(round_id.clone()),
            Some(round_id.clone()),
            requester.authority.service_id.clone(),
            request.event_id.clone(),
            1,
            vec![],
            Some(Box::new(closure.clone())),
            at,
            at + Duration::minutes(15),
            |bytes| requester.authority.sign(bytes, at),
        )?;
        let terminal_proof = ContactCurrentProof::sign_with(
            contact_trust_domain(),
            responder.peer(),
            requester.peer(),
            Some(round_id.clone()),
            Some(round_id.clone()),
            responder.authority.service_id.clone(),
            terminal.event_id.clone(),
            3,
            vec![],
            Some(Box::new(closure)),
            at,
            at + Duration::minutes(15),
            |bytes| responder.authority.sign(bytes, at),
        )?;
        let request_op = ContactOperationEvidence::Request {
            signed_event: request.clone(),
            request_receipt: receipt.clone(),
        };
        let response_op = ContactOperationEvidence::Response {
            signed_event: accepted.clone(),
            response_receipt: response_receipt.clone(),
        };
        let basis = ContactRoundBasis {
            contact_round_id: round_id.clone(),
            contact_round: core.clone(),
            request_receipts: vec![receipt.clone()],
            normal_response_receipt: Some(response_receipt.clone()),
            glare_concurrency_attestations: None,
        };
        Ok(Self {
            terminal_acknowledgement,
            round: ContactRoundEvidenceBundle {
                contact_round_id: round_id,
                initial_identity: ContactInitialIdentity {
                    trust_domain_id: contact_trust_domain(),
                    round: basis,
                    events: vec![request.clone(), accepted.clone()],
                },
                round_events: vec![request.clone(), accepted.clone()],
                current_operations: [request_op.clone(), response_op.clone()],
                scope_grants: vec![request_op, response_op],
                contact_round: core,
                request_receipts: vec![receipt.clone()],
                normal_response_receipt: Some(response_receipt.clone()),
                glare_concurrency_attestations: None,
                current_proofs: vec![initial_request, initial_response.clone()],
            },
            request: PeerContactSubmitRequestBody::Request {
                idempotency_key: key("fixture-request")?,
                signed_event: request,
                request_receipt: receipt,
                contact_address: responder.address(),
                introduction_evidence: intro,
                current_proof: None,
            },
            response: PeerContactSubmitRequestBody::Response {
                idempotency_key: key("fixture-response")?,
                signed_event: accepted,
                response_receipt,
                contact_address: requester.address(),
                current_proof: Some(initial_response),
            },
            reject: PeerContactSubmitRequestBody::Reject {
                idempotency_key: key("fixture-reject")?,
                signed_event: reject,
                reject_receipt,
                contact_address: requester.address(),
            },
            scope_update: PeerContactSubmitRequestBody::ScopeUpdate {
                idempotency_key: key("fixture-scope-update")?,
                signed_event: update,
                lineage: updated,
                current_proof: update_proof,
                contact_address: requester.address(),
            },
            tombstone: PeerContactSubmitRequestBody::Tombstone {
                idempotency_key: key("fixture-tombstone")?,
                signed_event: terminal,
                lineage: terminated,
                current_proof: terminal_proof,
                contact_address: requester.address(),
            },
            response_lineage,
            outgoing_slot_absence: absence,
        })
    }
}

/// Shared deterministic domain for synthetic Contact ceremonies.
pub fn contact_trust_domain() -> arkret_wire::TrustDomainId {
    arkret_wire::TrustDomainId::new("ak:trust_domain:contact.test").expect("fixture trust domain")
}
