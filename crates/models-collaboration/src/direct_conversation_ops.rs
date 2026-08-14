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
    CbaProofBundle, DidCoreId, Event, EventFederationSubmission, EventId, EventInitialSubmission,
    Hash, IdempotencyKey, ProtocolSignature, RealmId, ScopeRef, StrandId, TrustDomainId,
};
pub use arkret_wire::{
    DidBindingEvidenceKind, DidBindingEvidenceReceipt, DidBindingMethodProof,
    DidBindingMethodProofKind, DidBindingWitness,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::contact_operations::{ContactPeer, ContactRoundEvidenceBundle};

pub const DIRECT_CONVERSATION_FOUNDING_UNIT_KIND: &str = "direct_conversation_founding";
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
        contact_round_continuity_chain: Vec<ContactRoundEvidenceBundle>,
    },
    ControllerAgent {
        agent_provision_ref: EventId,
        agent_provision_digest: Hash,
        controller_binding_digest: Hash,
    },
}

/// Typed self carrier for the only Direct Conversation founding workflow.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationFoundingUnitSubmission {
    pub unit_kind: DirectConversationFoundingUnitKind,
    pub idempotency_key: IdempotencyKey,
    pub events: [EventInitialSubmission; 3],
    pub founding_authority_evidence: DirectConversationFoundingAuthorityEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
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
    pub events: [EventFederationSubmission; 3],
    pub source_acceptance_receipt: DirectConversationFoundingAcceptanceReceipt,
    pub founding_authority_evidence: DirectConversationFoundingAuthorityEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
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
    pub event_ids: [EventId; 3],
    pub receipt: DirectConversationFoundingAcceptanceReceipt,
}

/// Coordinates and digest deterministically derived from the signed unit bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationFoundingPlan {
    pub event_ids: [EventId; 3],
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
}

impl DirectConversationFoundingPlan {
    /// Validate the closed wire order and derive every coordinate without allocating an ID.
    pub fn from_events(events: [&Event; 3]) -> arkret_wire::Result<Self> {
        let [create, member, strand] = events;
        if create.kind.as_str() != "ak.realm.create"
            || member.kind.as_str() != "ak.member.state"
            || strand.kind.as_str() != "ak.strand.create"
        {
            return Err(founding_unit_invalid(
                "founding Event kinds or wire order mismatch",
            ));
        }
        for event in events {
            event.verify_event_id_matches_content()?;
            if event.seal_ref.is_some()
                || event.auth_context.is_some()
                || event.seal_basis.is_some()
            {
                return Err(founding_unit_invalid(
                    "founding Events must use the bootstrap no-contact_round shape",
                ));
            }
        }
        if !matches!(create.scope_ref, ScopeRef::RealmGenesis)
            || create.actor_id != member.actor_id
            || create.actor_id != strand.actor_id
        {
            return Err(founding_unit_invalid("founding scope or actor mismatch"));
        }
        let realm_id = RealmId::from_event_id(&create.event_id);
        if create.realm_id != realm_id || member.realm_id != realm_id || strand.realm_id != realm_id
        {
            return Err(founding_unit_invalid("founding Realm coordinate mismatch"));
        }
        if member.scope_ref.realm_id_opt() != Some(&realm_id)
            || strand.scope_ref.realm_id_opt() != Some(&realm_id)
            || !member.prev_refs.contains(&create.event_id)
            || !strand.prev_refs.contains(&member.event_id)
        {
            return Err(founding_unit_invalid(
                "founding scope or prev_refs chain mismatch",
            ));
        }
        let member_payload: crate::governance::membership_invite::MembershipPayload =
            serde_json::from_value(serde_json::to_value(&member.payload).map_err(protocol_error)?)
                .map_err(protocol_error)?;
        if member_payload.membership
            != crate::governance::membership_invite::MembershipPayloadState::Join
            || member_payload
                .actor_id
                .as_ref()
                .is_some_and(|actor_id| actor_id == &create.actor_id)
            || member_payload.realm_id.as_ref() != Some(&realm_id)
        {
            return Err(founding_unit_invalid("founding peer membership mismatch"));
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
            member.event_id.clone(),
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
    pub fn participants_and_founder(&self) -> arkret_wire::Result<([DidCoreId; 2], DidCoreId)> {
        match self {
            Self::ControllerAgent { .. } => Err(arkret_wire::Error::Protocol(
                "controller_agent founding evidence requires the accepted provision projection"
                    .to_owned(),
            )),
            Self::Human {
                contact_round_evidence,
                contact_round_continuity_chain,
            } => {
                validate_contact_contact_round_evidence_shape(contact_round_evidence)?;
                if contact_round_continuity_chain.len() > 64 {
                    return Err(arkret_wire::Error::Protocol(
                        "direct conversation root contact_round continuity chain exceeds 64 entries"
                            .to_owned(),
                    ));
                }
                for predecessor in contact_round_continuity_chain {
                    validate_contact_contact_round_evidence_shape(predecessor)?;
                }
                crate::contact_operations::validate_recontact_continuity(
                    contact_round_evidence,
                    contact_round_continuity_chain,
                )?;
                let root = contact_round_continuity_chain
                    .last()
                    .unwrap_or(contact_round_evidence);
                let (participants, request_ref) = match &root.contact_round {
                    crate::contact_operations::ContactRound::Normal {
                        sorted_pair_members,
                        request_event_ref,
                        ..
                    } => (sorted_pair_members.clone(), request_event_ref),
                    crate::contact_operations::ContactRound::Glare {
                        sorted_pair_members,
                        requests,
                    } => (sorted_pair_members.clone(), &requests[0].request_event_ref),
                };
                if participants[0].as_str() >= participants[1].as_str() {
                    return Err(arkret_wire::Error::Protocol(
                        "direct conversation contact_round pair is not canonical and distinct"
                            .to_owned(),
                    ));
                }
                let request_issuer = root
                    .request_receipts
                    .iter()
                    .find(|receipt| &receipt.core.request_event_ref == request_ref)
                    .map(|receipt| receipt.core.holder.contact_actor_id())
                    .ok_or_else(|| {
                        arkret_wire::Error::Protocol(
                            "direct conversation root contact_round request receipt is missing"
                                .to_owned(),
                        )
                    })?;
                let founder = match &root.contact_round {
                    crate::contact_operations::ContactRound::Normal { .. } => {
                        if request_issuer == participants[0] {
                            participants[1].clone()
                        } else if request_issuer == participants[1] {
                            participants[0].clone()
                        } else {
                            return Err(arkret_wire::Error::Protocol(
                                "direct conversation request issuer is outside the pair".to_owned(),
                            ));
                        }
                    }
                    crate::contact_operations::ContactRound::Glare { .. } => request_issuer,
                };
                Ok((participants, founder))
            }
        }
    }

    pub fn human_pair_key_and_authorization_core(
        &self,
        trust_domain_id: TrustDomainId,
    ) -> arkret_wire::Result<(Hash, DidCoreId, DirectConversationFoundingAuthorizationCore)> {
        let Self::Human {
            contact_round_evidence,
            contact_round_continuity_chain,
        } = self
        else {
            return Err(arkret_wire::Error::Protocol(
                "human Direct Conversation founding evidence is required".to_owned(),
            ));
        };
        let (participants, founder) = self.participants_and_founder()?;
        let root = contact_round_continuity_chain
            .last()
            .unwrap_or(contact_round_evidence);
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
            sorted_pair_members,
            ..
        }
        | crate::contact_operations::ContactRound::Glare {
            sorted_pair_members,
            ..
        } => sorted_pair_members,
    };
    if participants[0].as_str() >= participants[1].as_str()
        || bundle.current_proofs.iter().any(|proof| {
            proof.contact_round_id != bundle.contact_round_id
                || proof.complete_through == 0
                || !proof.accepted_frontier.contains(&proof.head_event_ref)
        })
        || bundle
            .current_proofs
            .iter()
            .map(|proof| &proof.issuer)
            .collect::<std::collections::BTreeSet<_>>()
            != participants
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
    {
        return Err(protocol_error("Contact current proofs are invalid"));
    }
    for receipt in &bundle.request_receipts {
        receipt.core.validate()?;
        let digest =
            domain_separated_sha256(b"ak.contact.request-acceptance-core.v1\n", &receipt.core)?;
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
                        || attestation.issuer.as_core_id() == attestation.peer.as_core_id()
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

fn contact_round_id(
    contact_round: &crate::contact_operations::ContactRound,
) -> arkret_wire::Result<Hash> {
    domain_separated_sha256(CONTACT_ROUND_DOMAIN, contact_round)
}

fn protocol_error(error: impl std::fmt::Display) -> arkret_wire::Error {
    arkret_wire::Error::Protocol(error.to_string())
}

fn founding_unit_invalid(detail: &str) -> arkret_wire::Error {
    arkret_wire::Error::Protocol(format!(
        "direct_conversation_founding_unit_invalid: {detail}"
    ))
}

/// Stable identifier of the exact ordered three-Event unit.
pub fn direct_conversation_founding_unit_digest(
    event_ids: &[EventId; 3],
) -> arkret_wire::Result<Hash> {
    #[derive(Serialize)]
    struct Material<'a> {
        event_ids: &'a [EventId; 3],
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

/// Closed query body for `ak.self.direct_conversation.read.resolve`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationResolveRequestBody {
    pub peer: ContactPeer,
}

/// Verbatim authoring material returned only when the authenticated principal
/// is entitled to author the immutable three-Event founding unit.
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

    pub fn from_profile_value(value: &str) -> Option<Self> {
        match value {
            "personal_blocked" => Some(Self::PersonalBlocked),
            "history_key_unavailable" => Some(Self::HistoryKeyUnavailable),
            _ => None,
        }
    }
}

/// Closed tagged outcome of `ak.self.direct_conversation.read.resolve`.
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
        active_mls_generation_ref: Option<EventId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_mls_generation_value_digest: Option<Hash>,
    },
    Found {
        coordinates: DirectConversationCoordinates,
        active_mls_generation_ref: EventId,
        active_mls_generation_value_digest: Hash,
        send_blockers: Vec<DirectConversationSendBlocker>,
    },
    Suspended {
        coordinates: DirectConversationCoordinates,
        blockers: Vec<DirectConversationSendBlocker>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_mls_generation_ref: Option<EventId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_mls_generation_value_digest: Option<Hash>,
    },
    TemporarilyUnavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
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

    /// Whether the caller may author the founding unit for this pair.
    #[must_use]
    pub fn is_founder_creation_point(&self) -> bool {
        matches!(self, Self::CreationRequired { .. })
    }

    /// Validate the dependent pair used as the repair/CAS predecessor. A
    /// resolver never returns an Event ref without the digest of the complete
    /// accepted singleton value, or vice versa.
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        let pair = match self {
            Self::Provisional {
                active_mls_generation_ref,
                active_mls_generation_value_digest,
                ..
            }
            | Self::Suspended {
                active_mls_generation_ref,
                active_mls_generation_value_digest,
                ..
            } => Some((
                active_mls_generation_ref.is_some(),
                active_mls_generation_value_digest.is_some(),
            )),
            _ => None,
        };
        if pair.is_some_and(|(event_ref, value_digest)| event_ref != value_digest) {
            return Err(arkret_wire::Error::Protocol(
                "active MLS generation Event ref and whole-value digest must be paired".to_owned(),
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
        agent_provision_digest: Hash,
        controller_binding_digest: Hash,
    },
}

/// Source-signed evidence that the founder's current Principal Server atomically accepted exactly
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
    pub founder_id: DidCoreId,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
    pub authorization_core: DirectConversationFoundingAuthorizationCore,
    /// Always `true` on the wire: the receipt is only emitted inside the slot-committing
    /// transaction.
    pub slot_committed: bool,
    pub issuer_service_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub proof: ProtocolSignature,
}

impl DirectConversationFoundingAcceptanceReceipt {
    /// Shape check that does not replace admission: `slot_committed` MUST be true, otherwise the
    /// receipt does not attest that the founder's unique slot was closed.
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if !self.slot_committed {
            return Err(arkret_wire::Error::Protocol(
                "direct conversation founding acceptance receipt must set slot_committed"
                    .to_owned(),
            ));
        }
        if self.proof.created_at != self.accepted_at {
            return Err(arkret_wire::Error::Protocol(
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
            founder_id: &'a DidCoreId,
            realm_id: &'a RealmId,
            main_strand_id: &'a StrandId,
            founding_unit_digest: &'a Hash,
            authorization_core: &'a DirectConversationFoundingAuthorizationCore,
            slot_committed: bool,
            issuer_service_id: &'a DidCoreId,
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
            slot_committed: self.slot_committed,
            issuer_service_id: &self.issuer_service_id,
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
    fn contact_round_id_matches_normative_known_answers() {
        let cases = [
            (
                json!({
                    "kind": "normal",
                    "sorted_pair_members": [
                        "ak:did_core:webvh:z6mkfixturealice",
                        "ak:did_core:webvh:z6mkfixturebob"
                    ],
                    "request_event_ref": "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD",
                    "request_acceptance_receipt_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }),
                "sha256:55e2bdad8a06d2503f04e1d0cb5046a918f1002eab53e560ce399fe5aaf10c82",
            ),
            (
                json!({
                    "kind": "glare",
                    "sorted_pair_members": [
                        "ak:did_core:webvh:z6mkfixturealice",
                        "ak:did_core:webvh:z6mkfixturebob"
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
                "sha256:4c0fa7e71411764bfa71af12c350b37b34ad128e81d46152219b65d5780995de",
            ),
        ];

        for (contact_round, expected) in cases {
            let contact_round = serde_json::from_value(contact_round).unwrap();
            assert_eq!(contact_round_id(&contact_round).unwrap().as_str(), expected);
        }
    }

    use super::*;

    fn event_ids() -> [EventId; 3] {
        [
            EventId::new("ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD".to_owned())
                .unwrap(),
            EventId::new("ak:event:AWi7O9JH8Ib3wHJrt01Tl7Gf67pixYPhAmufRLOXFoBA".to_owned())
                .unwrap(),
            EventId::new("ak:event:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS".to_owned())
                .unwrap(),
        ]
    }

    #[test]
    fn founding_unit_digest_matches_registered_transcript() {
        assert_eq!(
            direct_conversation_founding_unit_digest(&event_ids())
                .unwrap()
                .as_str(),
            "sha256:dc604271ea8bbefce03b4ef6916f12a01af81722e44b2f3640adc61d3a9e31dd"
        );
    }

    fn receipt() -> DirectConversationFoundingAcceptanceReceipt {
        serde_json::from_value(json!({
            "pair_key": "sha256:71eac812be14d047f791749f9409bbdc6ab0af5999daa9077bc21f23bdfca1eb",
            "founder_id": "ak:did_core:webvh:z6mkfixturebob",
            "realm_id": "ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD",
            "main_strand_id": "ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS",
            "founding_unit_digest": "sha256:dc604271ea8bbefce03b4ef6916f12a01af81722e44b2f3640adc61d3a9e31dd",
            "authorization_core": {
                "kind": "human",
                "current_contact_round_id": "sha256:55e2bdad8a06d2503f04e1d0cb5046a918f1002eab53e560ce399fe5aaf10c82",
                "root_contact_round_id": "sha256:55e2bdad8a06d2503f04e1d0cb5046a918f1002eab53e560ce399fe5aaf10c82",
                "accepted_contact_evidence_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "slot_committed": true,
            "issuer_service_id": "ak:did_core:web:ps.example",
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
            "sha256:685e8a499cda01827b37c8485feddaab1e6ac7c9af636666de30d59127e851f2"
        );
        assert_eq!(
            receipt.signing_input_bytes().unwrap(),
            b"sha256:685e8a499cda01827b37c8485feddaab1e6ac7c9af636666de30d59127e851f2"
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

    #[test]
    fn client_local_blockers_match_profile_values_but_are_not_server_blockers() {
        assert_eq!(
            DirectConversationClientLocalBlocker::ALL
                .map(DirectConversationClientLocalBlocker::as_str),
            ["personal_blocked", "history_key_unavailable"]
        );
        for blocker in DirectConversationClientLocalBlocker::ALL {
            assert_eq!(
                DirectConversationClientLocalBlocker::from_profile_value(blocker.as_str()),
                Some(blocker)
            );
            assert!(
                serde_json::from_value::<DirectConversationSendBlocker>(json!(blocker.as_str()))
                    .is_err(),
                "holder-local blockers must not deserialize into a server DTO"
            );
        }
        assert!(
            DirectConversationClientLocalBlocker::from_profile_value("peer_presence_hidden")
                .is_none()
        );
    }
}
