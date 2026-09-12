//! Direct Conversation resolver and single-sided founding carriers.
//!
//! Mirrors `schemas/direct-conversation-operations.schema.json`.
//!
//! Creation is never carried here. A Direct Conversation Realm is created only by the founder
//! derived from the pair's root Contact round, through the `direct_conversation_genesis` (or
//! `direct_conversation_agent_genesis`) admission variant of `ak.realm.create`. This module only
//! carries the query-only resolver and the source-signed founding acceptance receipt.

#[cfg(test)]
use arkret_wire::Base64UrlString;
use arkret_wire::{
    ActorId, CbsProofBundle, CellRef, DidCoreId, Event, EventFederationSubmission, EventId,
    EventInitialSubmission, Hash, IdempotencyKey, PredicateOp, ProtocolSignature, RealmId,
    ScopeRef, StrandId, TrustDomainId, canonical,
};
pub use arkret_wire::{
    DidBindingEvidenceKind, DidBindingEvidenceReceipt, DidBindingMethodProof,
    DidBindingMethodProofKind, DidBindingWitness,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::contact_operations::{
    ContactPeer, ContactRoundEvidenceBundle, validate_contact_evidence_directions,
};
use crate::events_payloads::RealmCreatePayload;
use crate::events_payloads::event_wire::decode_payload_after_kind_validation;

pub const DIRECT_CONVERSATION_FOUNDING_UNIT_DOMAIN: &[u8] =
    b"ak.direct-conversation.founding-unit.v1\n";
pub const DIRECT_CONVERSATION_FOUNDING_RECEIPT_DOMAIN: &[u8] =
    b"ak.direct-conversation.founding-receipt.v1\n";
pub const CONTACT_ROUND_DOMAIN: &[u8] = b"ak.contact.round.v1\n";

/// Closed XOR evidence carried with both self and federation founding submissions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[allow(clippy::large_enum_variant)]
pub enum DirectConversationFoundingAuthorityEvidence {
    Human {
        contact_round_evidence: ContactRoundEvidenceBundle,
        contact_round_continuity_chains: Vec<ContactRoundEvidenceBundle>,
    },
    ControllerAgent {
        agent_provision_ref: EventId,
        controller_binding_digest: Hash,
    },
}

impl DirectConversationFoundingAuthorityEvidence {
    pub fn founding_ref(&self) -> arkret_wire::EventRef {
        match self {
            Self::ControllerAgent {
                agent_provision_ref,
                ..
            } => arkret_wire::EventRef::new(
                agent_provision_ref.to_string(),
                "direct_conversation_agent_provision",
            ),
            Self::Human {
                contact_round_evidence,
                ..
            } => arkret_wire::EventRef::new(
                contact_round_evidence.contact_round_id.to_string(),
                "direct_conversation_contact_round",
            ),
        }
    }

    /// Commit to the accepted provision payload that binds the Agent to its
    /// controller, delegation, PCR and accountability scope.
    pub fn from_agent_provision(
        agent_provision_ref: EventId,
        payload: &crate::events_payloads::agent::AgentProvisionPayload,
    ) -> Result<Self, arkret_wire::WireError> {
        payload.validate()?;
        Ok(Self::ControllerAgent {
            agent_provision_ref,
            controller_binding_digest: Hash::new(arkret_canonical::canonical_sha256(payload)?)?,
        })
    }

    pub fn agent_provision_digest(&self) -> Option<Hash> {
        match self {
            Self::ControllerAgent {
                agent_provision_ref,
                ..
            } => Some(agent_provision_ref.event_digest()),
            Self::Human { .. } => None,
        }
    }
}

/// Typed self carrier for the only Direct Conversation founding workflow.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationFoundingUnitSubmission {
    pub unit_kind: DirectConversationFoundingUnitKind,
    pub idempotency_key: IdempotencyKey,
    pub events: [EventInitialSubmission; 4],
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cbs_proof_bundles: Vec<CbsProofBundle>,
}

/// Const-valued discriminator used by both registered carrier branches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationFoundingUnitKind {
    #[default]
    DirectConversationFounding,
}

/// Typed peer carrier for the registered founding exception.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationFoundingFederationSubmission {
    pub unit_kind: DirectConversationFoundingUnitKind,
    pub events: [EventFederationSubmission; 4],
    pub source_acceptance_receipt: DirectConversationFoundingAcceptanceReceipt,
    pub founding_authority_evidence: DirectConversationFoundingAuthorityEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cbs_proof_bundles: Vec<CbsProofBundle>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationFoundingAcceptanceStatus {
    Accepted,
    Duplicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationFoundingAcceptanceOutcome {
    pub unit_kind: DirectConversationFoundingUnitKind,
    pub status: DirectConversationFoundingAcceptanceStatus,
    pub event_ids: [EventId; 4],
    pub receipt: DirectConversationFoundingAcceptanceReceipt,
}

/// Coordinates and digest deterministically derived from the signed unit bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationFoundingPlan {
    pub event_ids: [EventId; 4],
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
}

impl DirectConversationFoundingPlan {
    /// Validate the closed wire order and derive every coordinate without allocating an ID.
    pub fn from_events(events: [&Event; 4]) -> arkret_wire::Result<Self> {
        let [create, founder_member, peer_member, strand] = events;
        if create.kind.as_str() != arkret_wire::event_kind_str::REALM_CREATE
            || peer_member.kind.as_str() != arkret_wire::event_kind_str::MEMBER_STATE
            || strand.kind.as_str() != arkret_wire::event_kind_str::STRAND_CREATE
            || founder_member.kind.as_str() != arkret_wire::event_kind_str::MEMBER_STATE
        {
            return Err(founding_unit_invalid(
                "founding Event kinds or wire order mismatch",
            ));
        }
        create.verify_event_id_matches_content_with_digest_suite(canonical::DigestSuite::Sha256)?;
        let create_payload: RealmCreatePayload = decode_payload_after_kind_validation(create)?;
        let genesis_suite = create_payload.object.digest_algorithm;
        for event in [peer_member, strand, founder_member] {
            event.verify_event_id_matches_content_with_digest_suite(genesis_suite)?;
        }
        for event in events {
            if event.auth_context.is_some() || event.seal_basis.is_some() {
                return Err(founding_unit_invalid(
                    "founding Events must use the bootstrap no-contact_round shape",
                ));
            }
        }
        if !matches!(create.scope_ref, ScopeRef::RealmGenesis)
            || create.actor_id != peer_member.actor_id
            || create.actor_id != strand.actor_id
            || create.actor_id != founder_member.actor_id
        {
            return Err(founding_unit_invalid("founding scope or actor mismatch"));
        }
        let founding_refs = create
            .refs
            .iter()
            .filter(|reference| {
                matches!(
                    reference.role.as_str(),
                    "direct_conversation_agent_provision" | "direct_conversation_contact_round"
                )
            })
            .collect::<Vec<_>>();
        if founding_refs.len() != 1 || !founding_refs[0].critical {
            return Err(founding_unit_invalid(
                "founding requires one critical authorization ref",
            ));
        }
        let founding_ref = founding_refs[0];
        for event in events {
            let refs = event
                .refs
                .iter()
                .filter(|reference| {
                    matches!(
                        reference.role.as_str(),
                        "direct_conversation_agent_provision" | "direct_conversation_contact_round"
                    )
                })
                .collect::<Vec<_>>();
            if refs.len() != 1 || refs[0] != founding_ref {
                return Err(founding_unit_invalid("founding authorization refs differ"));
            }
        }
        let realm_id = RealmId::from_event_id(&create.event_id);
        if create.realm_id != realm_id
            || peer_member.realm_id != realm_id
            || strand.realm_id != realm_id
            || founder_member.realm_id != realm_id
        {
            return Err(founding_unit_invalid("founding Realm coordinate mismatch"));
        }
        if peer_member.scope_ref.realm_id_opt() != Some(&realm_id)
            || strand.scope_ref.realm_id_opt() != Some(&realm_id)
            || founder_member.scope_ref.realm_id_opt() != Some(&realm_id)
            || !founder_member.prev_refs.contains(&create.event_id)
            || !peer_member.prev_refs.contains(&founder_member.event_id)
            || !strand.prev_refs.contains(&peer_member.event_id)
        {
            return Err(founding_unit_invalid(
                "founding scope or prev_refs chain mismatch",
            ));
        }
        let member_payload: crate::governance::membership_invite::MembershipPayload =
            serde_json::from_value(
                serde_json::to_value(&peer_member.payload).map_err(protocol_error)?,
            )
            .map_err(protocol_error)?;
        if member_payload.membership
            != crate::governance::membership_invite::MembershipPayloadState::Join
            || member_payload.member_id == create.actor_id
            || member_payload.realm_id.as_ref() != Some(&realm_id)
        {
            return Err(founding_unit_invalid("founding peer membership mismatch"));
        }
        if (founding_ref.role == "direct_conversation_agent_provision")
            != member_payload.agent_controller_binding.is_some()
        {
            return Err(founding_unit_invalid(
                "founding Agent branch requires its explicit controller binding",
            ));
        }
        if let Some(binding) = &member_payload.agent_controller_binding {
            if create.actor_id.as_account_id() != Some(&binding.controller_account_id)
                || binding.controller_membership_generation_ref != founder_member.event_id
                || binding.controller_terminal_event_ref.is_some()
            {
                return Err(founding_unit_invalid(
                    "founding Agent controller generation mismatch",
                ));
            }
        }
        let founder_member_payload: crate::governance::membership_invite::MembershipPayload =
            serde_json::from_value(
                serde_json::to_value(&founder_member.payload).map_err(protocol_error)?,
            )
            .map_err(protocol_error)?;
        let founder_cell = founding_member_cell(&create.actor_id)?;
        if founder_member_payload.membership
            != crate::governance::membership_invite::MembershipPayloadState::Join
            || founder_member_payload.member_id != create.actor_id
            || founder_member_payload.agent_controller_binding.is_some()
            || founder_member_payload.realm_id.as_ref() != Some(&realm_id)
            || founder_member.preconditions.len() != 1
            || founder_member.preconditions[0].cell_id != founder_cell
            || founder_member.preconditions[0].predicate.op != PredicateOp::HeadEq
            || founder_member.preconditions[0].predicate.value != Some(serde_json::Value::Null)
        {
            return Err(founding_unit_invalid(
                "founding founder membership or head_eq mismatch",
            ));
        }
        let strand_payload: crate::events_payloads::StrandCreatePayload =
            serde_json::from_value(serde_json::to_value(&strand.payload).map_err(protocol_error)?)
                .map_err(protocol_error)?;
        let main_strand_id = StrandId::from_event_id(&strand.event_id);
        let primary_track =
            crate::objects::profiles::resolve_primary_track(&strand_payload.object.tracks, None)?;
        if strand_payload.object.id.is_some()
            || strand_payload.object.realm_id != realm_id
            || strand_payload.object.scope_circle_id.is_some()
            || primary_track.is_none_or(|(name, _)| name.as_str() != "discussion")
        {
            return Err(founding_unit_invalid("founding main Strand mismatch"));
        }
        let event_ids = [
            create.event_id.clone(),
            founder_member.event_id.clone(),
            peer_member.event_id.clone(),
            strand.event_id.clone(),
        ];
        let founding_unit_digest = direct_conversation_founding_unit_digest(&event_ids)?;
        Ok(Self {
            event_ids,
            realm_id,
            main_strand_id,
            founding_unit_digest,
        })
    }
}

impl DirectConversationFoundingAuthorityEvidence {
    pub fn participants_and_founder(&self) -> arkret_wire::Result<([ActorId; 2], ActorId)> {
        match self {
            Self::ControllerAgent { .. } => Err(arkret_wire::WireError::Protocol(
                "controller_agent founding evidence requires the accepted provision projection"
                    .to_owned(),
            )),
            Self::Human {
                contact_round_evidence,
                contact_round_continuity_chains,
            } => {
                validate_contact_contact_round_evidence_shape(contact_round_evidence)?;
                if contact_round_continuity_chains.len() > 64 {
                    return Err(arkret_wire::WireError::Protocol(
                        "direct conversation root contact_round continuity chain exceeds 64 entries"
                            .to_owned(),
                    ));
                }
                for predecessor in contact_round_continuity_chains {
                    validate_contact_contact_round_evidence_shape(predecessor)?;
                }
                crate::contact_operations::validate_recontact_continuity(
                    contact_round_evidence,
                    contact_round_continuity_chains,
                )?;
                let checkpoint_root = contact_round_evidence
                    .continuity_checkpoint
                    .as_ref()
                    .map(|checkpoint| checkpoint.validate_contact_shape())
                    .transpose()?;
                let root = checkpoint_root.as_ref().unwrap_or_else(|| {
                    contact_round_continuity_chains
                        .last()
                        .unwrap_or(contact_round_evidence)
                });
                let (participants, request_ref) = match &root.contact_round {
                    crate::contact_operations::ContactRound::Normal {
                        sorted_pair_member_ids,
                        request_event_ref,
                        ..
                    } => (sorted_pair_member_ids.clone(), request_event_ref),
                    crate::contact_operations::ContactRound::Glare {
                        sorted_pair_member_ids,
                        requests,
                    } => (
                        sorted_pair_member_ids.clone(),
                        &requests[0].request_event_ref,
                    ),
                };
                if participants[0] >= participants[1] {
                    return Err(arkret_wire::WireError::Protocol(
                        "direct conversation contact_round pair is not canonical and distinct"
                            .to_owned(),
                    ));
                }
                let request_author_actor_id = root
                    .request_receipts
                    .iter()
                    .find(|receipt| &receipt.core.request_event_ref == request_ref)
                    .map(|receipt| receipt.core.holder.contact_actor_id())
                    .ok_or_else(|| {
                        arkret_wire::WireError::Protocol(
                            "direct conversation root contact_round request receipt is missing"
                                .to_owned(),
                        )
                    })?;
                let founder = match &root.contact_round {
                    crate::contact_operations::ContactRound::Normal { .. } => {
                        if request_author_actor_id == participants[0] {
                            participants[1].clone()
                        } else if request_author_actor_id == participants[1] {
                            participants[0].clone()
                        } else {
                            return Err(arkret_wire::WireError::Protocol(
                                "direct conversation request author is outside the pair".to_owned(),
                            ));
                        }
                    }
                    crate::contact_operations::ContactRound::Glare { .. } => {
                        request_author_actor_id
                    }
                };
                Ok((participants, founder))
            }
        }
    }

    pub fn human_pair_key_and_authorization_core(
        &self,
        trust_domain_id: TrustDomainId,
    ) -> arkret_wire::Result<(Hash, ActorId, DirectConversationFoundingAuthorizationCore)> {
        let Self::Human {
            contact_round_evidence,
            contact_round_continuity_chains,
        } = self
        else {
            return Err(arkret_wire::WireError::Protocol(
                "human Direct Conversation founding evidence is required".to_owned(),
            ));
        };
        let (participants, founder) = self.participants_and_founder()?;
        let checkpoint_root = contact_round_evidence
            .continuity_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.validate_contact_shape())
            .transpose()?;
        let root = checkpoint_root.as_ref().unwrap_or_else(|| {
            contact_round_continuity_chains
                .last()
                .unwrap_or(contact_round_evidence)
        });
        let pair_key = crate::objects::direct_conversation::direct_conversation_pair_key(
            trust_domain_id,
            crate::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
                participants[0].clone(),
            ),
            crate::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
                participants[1].clone(),
            ),
        )?;
        let evidence_bytes = arkret_canonical::canonical_json_bytes(contact_round_evidence)
            .map_err(protocol_error)?;
        let accepted_contact_evidence_digest =
            Hash::new(arkret_canonical::sha256_digest(evidence_bytes)).map_err(protocol_error)?;
        Ok((
            pair_key,
            founder,
            DirectConversationFoundingAuthorizationCore::Human {
                current_contact_round_id: contact_round_evidence.contact_round_id.clone(),
                root_contact_round_id: root.contact_round_id.clone(),
                accepted_contact_evidence_digest,
            },
        ))
    }
}

fn validate_contact_contact_round_evidence_shape(
    bundle: &ContactRoundEvidenceBundle,
) -> arkret_wire::Result<()> {
    let expected_contact_round_id = contact_round_id(&bundle.contact_round)?;
    if bundle.contact_round_id != expected_contact_round_id || bundle.current_proofs.len() != 2 {
        return Err(protocol_error(
            "Contact round id or current-proof cardinality is invalid",
        ));
    }
    let participants = match &bundle.contact_round {
        crate::contact_operations::ContactRound::Normal {
            sorted_pair_member_ids,
            ..
        }
        | crate::contact_operations::ContactRound::Glare {
            sorted_pair_member_ids,
            ..
        } => sorted_pair_member_ids,
    };
    validate_contact_evidence_directions(bundle)?;
    if participants[0] >= participants[1]
        || bundle.current_proofs.iter().any(|proof| {
            proof.contact_round_id != bundle.contact_round_id
                || proof.complete_through == 0
                || !proof.accepted_frontier.contains(&proof.head_event_ref)
        })
        || bundle
            .current_proofs
            .iter()
            .map(|proof| proof.peer.contact_actor_id())
            .collect::<std::collections::BTreeSet<_>>()
            != participants
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
    {
        return Err(protocol_error("Contact current proofs are invalid"));
    }
    for receipt in &bundle.request_receipts {
        receipt.core.validate()?;
        let digest =
            domain_separated_sha256(b"ak.contact.request_acceptance_core.v1\n", &receipt.core)?;
        if receipt.receipt_digest != digest {
            return Err(protocol_error("Contact request receipt digest is invalid"));
        }
    }
    match &bundle.contact_round {
        crate::contact_operations::ContactRound::Normal {
            request_event_ref,
            request_acceptance_receipt_digest,
            ..
        } => {
            let response = bundle.normal_response_receipt.as_ref().ok_or_else(|| {
                protocol_error("normal Contact round is missing its response receipt")
            })?;
            let [request] = bundle.request_receipts.as_slice() else {
                return Err(protocol_error(
                    "normal Contact round requires one request receipt",
                ));
            };
            let request_acceptance_receipt_digest_actual =
                Hash::new(arkret_canonical::canonical_sha256(request).map_err(protocol_error)?)
                    .map_err(protocol_error)?;
            let response_request_receipt_digest = Hash::new(
                arkret_canonical::canonical_sha256(&response.request_receipt)
                    .map_err(protocol_error)?,
            )
            .map_err(protocol_error)?;
            if bundle.glare_concurrency_attestations.is_some()
                || &request.core.request_event_ref != request_event_ref
                || &request_acceptance_receipt_digest_actual != request_acceptance_receipt_digest
                || response.contact_round_id != bundle.contact_round_id
                || response_request_receipt_digest != request_acceptance_receipt_digest_actual
            {
                return Err(protocol_error("normal Contact round evidence mismatch"));
            }
        }
        crate::contact_operations::ContactRound::Glare { requests, .. } => {
            let attestations = bundle
                .glare_concurrency_attestations
                .as_ref()
                .ok_or_else(|| protocol_error("glare Contact round is missing attestations"))?;
            if bundle.normal_response_receipt.is_some() || bundle.request_receipts.len() != 2 {
                return Err(protocol_error("glare Contact round evidence mismatch"));
            }
            let expected = requests
                .iter()
                .map(|request| {
                    (
                        request.request_event_ref.clone(),
                        request.request_acceptance_receipt_digest.clone(),
                    )
                })
                .collect::<std::collections::BTreeSet<_>>();
            let actual = bundle
                .request_receipts
                .iter()
                .map(|receipt| {
                    Ok((
                        receipt.core.request_event_ref.clone(),
                        Hash::new(arkret_canonical::canonical_sha256(receipt)?)?,
                    ))
                })
                .collect::<arkret_wire::Result<std::collections::BTreeSet<_>>>()?;
            let receipt_digests = bundle
                .request_receipts
                .iter()
                .map(|receipt| {
                    let digest =
                        arkret_canonical::canonical_sha256(receipt).map_err(protocol_error)?;
                    Hash::new(digest).map_err(protocol_error)
                })
                .collect::<arkret_wire::Result<std::collections::BTreeSet<_>>>()?;
            if expected != actual
                || attestations.iter().any(|attestation| {
                    attestation.complete_through == 0
                        || attestation.subject_id == attestation.peer_id
                        || attestation
                            .request_receipt_digests
                            .iter()
                            .cloned()
                            .collect::<std::collections::BTreeSet<_>>()
                            != receipt_digests
                        || !bundle.request_receipts.iter().all(|receipt| {
                            attestation
                                .observed_frontier
                                .contains(&receipt.core.request_event_ref)
                        })
                })
            {
                return Err(protocol_error("glare Contact round evidence mismatch"));
            }
        }
    }
    Ok(())
}

/// Derive the Contact round identity using the normative domain-prefixed JCS transcript.
pub fn contact_round_id(
    contact_round: &crate::contact_operations::ContactRound,
) -> arkret_wire::Result<Hash> {
    contact_round.validate_canonical_order()?;
    domain_separated_sha256(CONTACT_ROUND_DOMAIN, contact_round)
}

fn protocol_error(error: impl std::fmt::Display) -> arkret_wire::WireError {
    arkret_wire::WireError::Protocol(error.to_string())
}

fn founding_member_cell(actor: &ActorId) -> arkret_wire::Result<CellRef> {
    let subject = arkret_wire::composite_subject(&[actor.canonical_key()?])?;
    CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}")).map_err(protocol_error)
}

fn founding_unit_invalid(detail: &str) -> arkret_wire::WireError {
    arkret_wire::WireError::Protocol(format!(
        "direct_conversation_founding_unit_invalid: {detail}"
    ))
}

/// Stable identifier of the exact ordered four-Event unit.
pub fn direct_conversation_founding_unit_digest(
    event_ids: &[EventId; 4],
) -> arkret_wire::Result<Hash> {
    #[derive(Serialize)]
    struct Material<'a> {
        event_ids: &'a [EventId; 4],
    }
    domain_separated_sha256(
        DIRECT_CONVERSATION_FOUNDING_UNIT_DOMAIN,
        &Material { event_ids },
    )
}

fn domain_separated_sha256(domain: &[u8], value: &impl Serialize) -> arkret_wire::Result<Hash> {
    let canonical = arkret_canonical::canonical_json_bytes(value).map_err(protocol_error)?;
    let mut transcript = Vec::with_capacity(domain.len() + canonical.len());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(transcript)).map_err(protocol_error)
}

/// Closed query body for `ak.self.direct_conversation.read.resolve.v1`.
/// `direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_request`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationResolveRequestBody {
    pub peer: ContactPeer,
}

/// Verbatim authoring material returned only when the authenticated principal
/// is entitled to author the immutable four-Event founding unit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationFoundingInput {
    pub founding_authority_evidence: DirectConversationFoundingAuthorityEvidence,
}

/// Permanent Direct Conversation coordinates.
///
/// `binding_event_ref` appears only from `found`/`suspended` onward; it is absent while the pair is
/// still `provisional`, because no binding endorsement exists yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationCoordinates {
    pub pair_key: Hash,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
}

/// Closed machine-readable blocker set surfaced by the resolver.
///
/// Values never disclose peer presence to non-participants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationSendBlocker {
    SessionMissing,
    PresenceOffline,
    KeypackageEmpty,
    GrantMissing,
    PolicyStale,
    ContactScopeStale,
    MlsReconcileRequired,
    AgentRuntimeUnavailable,
    PeerNotJoinedMls,
    PairMaterializationConflict,
    RealmTerminalFault,
    NotaryUnavailable,
    UnsupportedProfile,
}

/// Closed holder-device-only blocker set from
/// `ak.profile.direct_conversation_realm.v1#client_local_send_blockers`.
///
/// This type intentionally implements no Serde traits: these values MUST NOT
/// appear on any operation, Event, peer carrier or federation wire surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DirectConversationClientLocalBlocker {
    PersonalBlocked,
    HistoryKeyUnavailable,
}

impl DirectConversationClientLocalBlocker {
    pub const ALL: [Self; 2] = [Self::PersonalBlocked, Self::HistoryKeyUnavailable];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersonalBlocked => "personal_blocked",
            Self::HistoryKeyUnavailable => "history_key_unavailable",
        }
    }
}

/// Closed tagged outcome of `ak.self.direct_conversation.read.resolve.v1`.
///
/// Evaluation order is fixed: `TemporarilyUnavailable` when the current contact_round or founder
/// cannot be verified; then `CreationBlocked`/`CreationRequired`/`AwaitingFounder` while no Realm
/// exists; then `Suspended` for identity, materialization, terminal or gate conflicts; then
/// `Provisional` while no binding endorsement exists; `Found` last.
///
/// `retry_after_ms` is a scheduling hint only. Waiting never grants create authority to the
/// non-founder: there is no timeout fallback or takeover in base v1.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[allow(clippy::large_enum_variant)]
pub enum DirectConversationResolveOutcome {
    /// No accepted Realm, and this principal is the derived founder.
    CreationRequired {
        next_founding_input: DirectConversationFoundingInput,
    },
    /// No accepted Realm, this principal is the founder, but a current gate refuses creation.
    /// No coordinates are allocated in this state.
    CreationBlocked {
        blockers: Vec<DirectConversationSendBlocker>,
    },
    /// No accepted Realm and this principal is not the founder. Only the founder may create.
    AwaitingFounder {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    /// The founding unit is accepted but no binding endorsement exists yet.
    Provisional {
        coordinates: DirectConversationCoordinates,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_state_ref: Option<EventId>,
    },
    Found {
        #[serde(
            deserialize_with = "deserialize_found_coordinates",
            serialize_with = "serialize_found_coordinates"
        )]
        coordinates: DirectConversationCoordinates,
        group_state_ref: EventId,
        send_blockers: Vec<DirectConversationSendBlocker>,
    },
    Suspended {
        coordinates: DirectConversationCoordinates,
        blockers: Vec<DirectConversationSendBlocker>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_state_ref: Option<EventId>,
    },
    TemporarilyUnavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
}

fn deserialize_found_coordinates<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<DirectConversationCoordinates, D::Error> {
    let value = DirectConversationCoordinates::deserialize(deserializer)?;
    if value.binding_event_ref.is_none() {
        return Err(serde::de::Error::custom("found requires binding_event_ref"));
    }
    Ok(value)
}

fn serialize_found_coordinates<S: serde::Serializer>(
    value: &DirectConversationCoordinates,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if value.binding_event_ref.is_none() {
        return Err(serde::ser::Error::custom(
            "found requires binding_event_ref",
        ));
    }
    value.serialize(serializer)
}

impl DirectConversationResolveOutcome {
    /// Coordinates, when the outcome carries them. Never hidden by presence, session, KeyPackage
    /// inventory or MLS reconcile state.
    #[must_use]
    pub fn coordinates(&self) -> Option<&DirectConversationCoordinates> {
        match self {
            Self::Provisional { coordinates, .. }
            | Self::Found { coordinates, .. }
            | Self::Suspended { coordinates, .. } => Some(coordinates),
            _ => None,
        }
    }

    /// Validate the response shape.
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if let Self::Found { coordinates, .. } = self
            && coordinates.binding_event_ref.is_none()
        {
            return Err(arkret_wire::WireError::Protocol(
                "found requires binding_event_ref".into(),
            ));
        }
        Ok(())
    }
}

/// Branch-specific authorization core of a founding acceptance receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationFoundingAuthorizationCore {
    /// human-to-human and Agent-to-third-party: founder derives from the Contact round.
    Human {
        current_contact_round_id: Hash,
        root_contact_round_id: Hash,
        accepted_contact_evidence_digest: Hash,
    },
    /// controller-to-own-Agent: no Contact round exists, founder is fixed to the controller.
    ControllerAgent {
        agent_provision_ref: EventId,
        controller_binding_digest: Hash,
    },
}

impl DirectConversationFoundingAuthorizationCore {
    pub fn agent_provision_digest(&self) -> Option<Hash> {
        match self {
            Self::ControllerAgent {
                agent_provision_ref,
                ..
            } => Some(agent_provision_ref.event_digest()),
            Self::Human { .. } => None,
        }
    }
}

/// Source-signed evidence that the founder's current Station atomically accepted exactly
/// one founding unit and closed its local unique slot.
///
/// It creates no Realm, authorizes no Message and is not a global slot. A second receipt for the
/// same pair and founder but a different unit is
/// `direct_conversation_pair_materialization_conflict` evidence: implementations MUST NOT pick a
/// winner by UUID or arrival order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationFoundingAcceptanceReceipt {
    pub pair_key: Hash,
    pub founder_id: ActorId,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
    pub authorization_core: DirectConversationFoundingAuthorizationCore,
    pub issuer_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub proof: ProtocolSignature,
}

impl DirectConversationFoundingAcceptanceReceipt {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if self.proof.created_at != self.accepted_at {
            return Err(arkret_wire::WireError::Protocol(
                "direct conversation founding receipt proof.created_at must equal accepted_at"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical closed receipt object with `proof` removed, before domain separation.
    pub fn canonical_transcript_object_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct ReceiptTranscript<'a> {
            pair_key: &'a Hash,
            founder_id: &'a ActorId,
            realm_id: &'a RealmId,
            main_strand_id: &'a StrandId,
            founding_unit_digest: &'a Hash,
            authorization_core: &'a DirectConversationFoundingAuthorizationCore,
            issuer_id: &'a DidCoreId,
            #[serde(
                serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp"
            )]
            accepted_at: DateTime<Utc>,
        }
        arkret_canonical::canonical_json_bytes(&ReceiptTranscript {
            pair_key: &self.pair_key,
            founder_id: &self.founder_id,
            realm_id: &self.realm_id,
            main_strand_id: &self.main_strand_id,
            founding_unit_digest: &self.founding_unit_digest,
            authorization_core: &self.authorization_core,
            issuer_id: &self.issuer_id,
            accepted_at: self.accepted_at,
        })
        .map_err(protocol_error)
    }

    /// Byte-exact preimage consumed by the fixed SHA-256 transcript function.
    pub fn transcript_preimage_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        let object = self.canonical_transcript_object_bytes()?;
        let mut transcript =
            Vec::with_capacity(DIRECT_CONVERSATION_FOUNDING_RECEIPT_DOMAIN.len() + object.len());
        transcript.extend_from_slice(DIRECT_CONVERSATION_FOUNDING_RECEIPT_DOMAIN);
        transcript.extend_from_slice(&object);
        Ok(transcript)
    }

    /// The unique digest signed by `proof` and recomputed by every receiver.
    pub fn transcript_digest(&self) -> arkret_wire::Result<Hash> {
        self.validate_shape()?;
        Hash::new(arkret_canonical::sha256_digest(
            self.transcript_preimage_bytes()?,
        ))
        .map_err(protocol_error)
    }

    /// Byte-exact signing input for `proof`: the registered `H(...)` value.
    pub fn signing_input_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        Ok(self.transcript_digest()?.as_str().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn found_requires_authoring_endorsement_on_decode_validate_and_encode() {
        let mut wire = json!({"state":"found","coordinates":{
            "pair_key":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "realm_id":"ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD",
            "main_strand_id":"ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS"},
            "group_state_ref":"ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml","send_blockers":[]});
        assert!(serde_json::from_value::<DirectConversationResolveOutcome>(wire.clone()).is_err());
        wire["coordinates"]["binding_event_ref"] = wire["group_state_ref"].clone();
        let mut found: DirectConversationResolveOutcome = serde_json::from_value(wire).unwrap();
        assert!(found.validate_shape().is_ok());
        assert!(serde_json::to_value(&found).is_ok());
        if let DirectConversationResolveOutcome::Found { coordinates, .. } = &mut found {
            coordinates.binding_event_ref = None;
        }
        assert!(found.validate_shape().is_err());
        assert!(serde_json::to_value(&found).is_err());
    }

    #[test]
    fn founding_member_cell_hashes_the_full_actor_including_station() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let mut cells = Vec::new();
        for station in [
            "ak:did_core:web:first.example",
            "ak:did_core:web:second.example",
        ] {
            let actor = ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                DidCoreId::new(station).unwrap(),
            ));
            let cell = founding_member_cell(&actor).unwrap();
            let expected_subject =
                arkret_wire::composite_subject(&[actor.canonical_key().unwrap()]).unwrap();
            assert_eq!(
                cell.as_str(),
                format!("ak:cell:ak.component.member.state.v1:{expected_subject}")
            );
            assert!(!cell.as_str().contains('{'));
            cells.push(cell);
        }
        assert_ne!(cells[0], cells[1]);
    }

    #[test]
    fn contact_round_id_matches_normative_known_answers() {
        let cases = [
            (
                json!({
                    "kind": "normal",
                    "sorted_pair_member_ids": [
                        {"kind": "account", "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixturealice",
                            "station_id": "ak:did_core:webvh:z6mkfixturestation"
                        }},
                        {"kind": "account", "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixturebob",
                            "station_id": "ak:did_core:webvh:z6mkfixturestation"
                        }}
                    ],
                    "request_event_ref": "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD",
                    "request_acceptance_receipt_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }),
                "sha256:585e239ded03e52605c8665f0a6b6786be7673cd520eb756eba659374a4a3500",
            ),
            (
                json!({
                    "kind": "glare",
                    "sorted_pair_member_ids": [
                        {"kind": "account", "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixturealice",
                            "station_id": "ak:did_core:webvh:z6mkfixturestation"
                        }},
                        {"kind": "account", "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixturebob",
                            "station_id": "ak:did_core:webvh:z6mkfixturestation"
                        }}
                    ],
                    "requests": [
                        {
                            "request_event_ref": "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD",
                            "request_acceptance_receipt_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        {
                            "request_event_ref": "ak:event:AWi7O9JH8Ib3wHJrt01Tl7Gf67pixYPhAmufRLOXFoBA",
                            "request_acceptance_receipt_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        }
                    ]
                }),
                "sha256:1b5b7d94866f0cbc784fd0138120ca2545b640082863adf621364712e33ef1ce",
            ),
        ];

        for (contact_round, expected) in cases {
            let contact_round = serde_json::from_value(contact_round).unwrap();
            assert_eq!(contact_round_id(&contact_round).unwrap().as_str(), expected);
        }
    }

    use super::*;

    #[test]
    fn controller_binding_digest_commits_to_provision_payload() {
        let payload: crate::events_payloads::agent::AgentProvisionPayload = serde_json::from_value(json!({
            "schema": "ak.schema.agent_provision.v1",
            "agent_id": "ak:did_core:web:agent.example",
            "controller_principal_id": "ak:did_core:web:alice.example",
            "principal_control_realm_id": "ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL",
            "controller_authorization_ref": "did:web:alice.example#managed-controller",
            "agent_slug": "assistant",
            "accountability_scope": "agent_operator",
            "requested_scope_digest": format!("sha256:{}", "a".repeat(64)),
            "selector_visibility": "private",
            "created_at": "2026-09-08T12:00:00.000Z"
        })).unwrap();
        let provision_ref =
            EventId::new("ak:event:AWAIb405aEEenVBHYRG-ZfDs-f9_j3E67tWGI36uYxFJ").unwrap();
        let evidence = DirectConversationFoundingAuthorityEvidence::from_agent_provision(
            provision_ref.clone(),
            &payload,
        )
        .unwrap();
        let mut changed = payload.clone();
        changed.controller_principal_id = DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        let changed_evidence = DirectConversationFoundingAuthorityEvidence::from_agent_provision(
            provision_ref,
            &changed,
        )
        .unwrap();
        assert_ne!(
            serde_json::to_value(&evidence).unwrap()["controller_binding_digest"],
            serde_json::to_value(&changed_evidence).unwrap()["controller_binding_digest"]
        );
        assert_eq!(
            serde_json::to_value(&evidence).unwrap()["controller_binding_digest"],
            arkret_canonical::canonical_sha256(&payload).unwrap()
        );
        changed.agent_slug = "Not Canonical".to_owned();
        assert!(
            DirectConversationFoundingAuthorityEvidence::from_agent_provision(
                EventId::new("ak:event:AWAIb405aEEenVBHYRG-ZfDs-f9_j3E67tWGI36uYxFJ").unwrap(),
                &changed
            )
            .is_err()
        );
    }

    #[test]
    fn controller_agent_provision_digest_is_derived_from_event_ref() {
        let evidence = DirectConversationFoundingAuthorityEvidence::ControllerAgent {
            agent_provision_ref: EventId::new(
                "ak:event:AWAIb405aEEenVBHYRG-ZfDs-f9_j3E67tWGI36uYxFJ",
            )
            .unwrap(),
            controller_binding_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
        };
        assert_eq!(
            evidence.agent_provision_digest().unwrap().as_str(),
            "sha256:60086f8d3968411e9d50476111be65f0ecf9ff7f8f713aeed586237eae631149"
        );
    }

    fn event_ids() -> [EventId; 4] {
        [
            EventId::new("ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD".to_owned())
                .unwrap(),
            EventId::new("ak:event:AWi7O9JH8Ib3wHJrt01Tl7Gf67pixYPhAmufRLOXFoBA".to_owned())
                .unwrap(),
            EventId::new("ak:event:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS".to_owned())
                .unwrap(),
            EventId::new("ak:event:AS_LTHQu5UtXbAIUOgUFzEY5nFJzI1cgPvxODB_NnHSR".to_owned())
                .unwrap(),
        ]
    }

    #[test]
    fn founding_unit_digest_matches_registered_transcript() {
        assert_eq!(
            direct_conversation_founding_unit_digest(&event_ids())
                .unwrap()
                .as_str(),
            "sha256:3cd20dd09f6c8bc93757a03640c1612a6b85599eeb702cc488e2cc083ebfa46e"
        );
    }

    fn receipt() -> DirectConversationFoundingAcceptanceReceipt {
        serde_json::from_value(json!({
            "pair_key": "sha256:93579842aa9c2d29256cae0dcf194185847f43aeb3e69b97cac8e73c3d60ef1f",
            "founder_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixturebob",
                "station_id": "ak:did_core:webvh:z6mkfixturestation"
            }},
            "realm_id": "ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD",
            "main_strand_id": "ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS",
            "founding_unit_digest": "sha256:3cd20dd09f6c8bc93757a03640c1612a6b85599eeb702cc488e2cc083ebfa46e",
            "authorization_core": {
                "kind": "human",
                "current_contact_round_id": "sha256:585e239ded03e52605c8665f0a6b6786be7673cd520eb756eba659374a4a3500",
                "root_contact_round_id": "sha256:585e239ded03e52605c8665f0a6b6786be7673cd520eb756eba659374a4a3500",
                "accepted_contact_evidence_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "issuer_id": "ak:did_core:web:ps.example",
            "accepted_at": "2026-08-08T00:00:00.000Z",
            "proof": {
                "verification_method": "did:web:ps.example#key-1",
                "created_at": "2026-08-08T00:00:00.000Z",
                "jws": "eyJhbGciOiJFZERTQSJ9"
            }
        }))
        .unwrap()
    }

    #[test]
    fn receipt_transcript_is_closed_and_matches_known_answer() {
        let receipt = receipt();
        assert_eq!(
            receipt.transcript_digest().unwrap().as_str(),
            "sha256:d90f5f27feb944bf8686e065ee29e3839c3058a5f9091aef1540685b60d3b16e"
        );
        assert_eq!(
            receipt.signing_input_bytes().unwrap(),
            b"sha256:d90f5f27feb944bf8686e065ee29e3839c3058a5f9091aef1540685b60d3b16e"
        );
        let mut changed_proof = receipt.clone();
        changed_proof.proof.jws = Base64UrlString::new("ZGlmZmVyZW50".to_owned()).unwrap();
        assert_eq!(
            receipt.transcript_digest().unwrap(),
            changed_proof.transcript_digest().unwrap()
        );
    }

    #[test]
    fn receipt_rejects_split_accepted_at_and_signature_time() {
        let mut receipt = receipt();
        receipt.proof.created_at = DateTime::parse_from_rfc3339("2026-08-08T00:00:01.000Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(receipt.validate_shape().is_err());
    }
}
