//! Direct Conversation Realm role, builders, validation, and candidate folding.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, ActorId, DidCoreId, Discoverability, EventId, GenesisSalt, Hash, HistoryAccess,
    JoinRule, ObjectStage, ObjectState, RealmId, Result, SecurityClass, TrustDomainId, WireError,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::{RealmCreatePayload, RealmGenesis, RealmPurpose, StrandCreatePayload};
use crate::governance::membership_invite::MembershipPayload;
use crate::objects::profiles::{STRAND_TRACK_NAME_DISCUSSION, StrandTrack};
use crate::objects::strand::Strand;

pub const DIRECT_CONVERSATION_REALM_ROLE_FEATURE: &str =
    "ak.feature.direct_conversation_realm_role.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationAuthorizationKind {
    AcceptedContact,
    AgentController,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationAuthorizationBasis {
    pub kind: DirectConversationAuthorizationKind,
    pub event_refs: Vec<EventId>,
}

impl DirectConversationAuthorizationBasis {
    pub fn accepted_contact(event_refs: Vec<EventId>) -> Self {
        Self {
            kind: DirectConversationAuthorizationKind::AcceptedContact,
            event_refs,
        }
    }

    pub fn agent_controller(event_refs: Vec<EventId>) -> Self {
        Self {
            kind: DirectConversationAuthorizationKind::AgentController,
            event_refs,
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        let unique = self.event_refs.iter().collect::<BTreeSet<_>>();
        let expected_len = match self.kind {
            DirectConversationAuthorizationKind::AcceptedContact => 2,
            DirectConversationAuthorizationKind::AgentController => 2,
        };
        if self.event_refs.len() != expected_len || unique.len() != self.event_refs.len() {
            return Err(WireError::Protocol(format!(
                "direct conversation authorization authority requires {expected_len} unique event_refs (schema_violation)"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationRealmRole {
    DirectConversation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationPairKeyParticipant {
    pub actor_id: ActorId,
    pub stable_subject: ActorId,
}

impl DirectConversationPairKeyParticipant {
    pub fn unmapped(actor_id: ActorId) -> Self {
        Self {
            stable_subject: actor_id.clone(),
            actor_id,
        }
    }
}

#[derive(Serialize)]
struct DirectConversationPairKeyMaterial {
    participants: [ActorId; 2],
    trust_domain_id: TrustDomainId,
}

const DIRECT_CONVERSATION_PAIR_KEY_DOMAIN: &[u8] = b"ak.direct-conversation.pair-key.v1\n";

pub fn direct_conversation_pair_key(
    trust_domain: TrustDomainId,
    left: DirectConversationPairKeyParticipant,
    right: DirectConversationPairKeyParticipant,
) -> Result<Hash> {
    let mut participants = [left.stable_subject, right.stable_subject];
    participants.sort();
    if participants[0] == participants[1] {
        return Err(WireError::Protocol(
            "direct conversation participants must be distinct (schema_violation)".to_owned(),
        ));
    }
    let material = DirectConversationPairKeyMaterial {
        participants,
        trust_domain_id: trust_domain,
    };
    let canonical = canonical::canonical_json_bytes(&material)?;
    let mut transcript =
        Vec::with_capacity(DIRECT_CONVERSATION_PAIR_KEY_DOMAIN.len() + canonical.len());
    transcript.extend_from_slice(DIRECT_CONVERSATION_PAIR_KEY_DOMAIN);
    transcript.extend_from_slice(&canonical);
    Ok(Hash::new(canonical::sha256_digest(transcript))?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectConversationRealmRole;

impl DirectConversationRealmRole {
    pub fn validate(genesis: &RealmGenesis) -> Result<Self> {
        if genesis.purpose != RealmPurpose::DirectConversation {
            return Err(WireError::Protocol(
                "direct conversation Realm purpose/profile mismatch (schema_violation)".to_owned(),
            ));
        }
        Ok(Self)
    }

    pub fn matches(genesis: &RealmGenesis) -> bool {
        Self::validate(genesis).is_ok()
    }
}

pub fn direct_conversation_realm_create_payload(
    genesis_salt: GenesisSalt,
    trust_domain: TrustDomainId,
    governance_station_id: DidCoreId,
    _created_at: DateTime<Utc>,
) -> Result<RealmCreatePayload> {
    let genesis = RealmGenesis::new(
        RealmPurpose::DirectConversation,
        genesis_salt,
        trust_domain,
        SecurityClass::Standard,
        governance_station_id,
        JoinRule::Invite,
        HistoryAccess::SinceJoin,
        Discoverability::InviteOnly,
        None,
        None,
    )?;
    Ok(RealmCreatePayload::new(genesis))
}

/// Build the peer membership payload in the exact four-Event Direct
/// Conversation founding unit. The founder membership is the unit's preceding
/// explicit genesis slot and uses [`direct_conversation_member_join_payload`].
pub fn direct_conversation_peer_membership_bootstrap(
    realm_id: RealmId,
    founder: &AccountId,
    participants: [AccountId; 2],
) -> Result<MembershipPayload> {
    if participants[0] == participants[1] {
        return Err(WireError::Protocol(
            "direct conversation participants must be distinct (schema_violation)".to_owned(),
        ));
    }
    if !participants
        .iter()
        .any(|participant| participant == founder)
    {
        return Err(WireError::Protocol(
            "direct conversation founder must be one of the two participants (schema_violation)"
                .to_owned(),
        ));
    }
    let peer = participants
        .into_iter()
        .find(|participant| participant != founder)
        .expect("distinct participant pair containing founder has one peer");
    Ok(MembershipPayload::join(
        realm_id,
        ActorId::account(peer),
        "direct_conversation_bootstrap",
    ))
}

pub fn direct_conversation_member_join_payload(
    realm_id: RealmId,
    participant: AccountId,
) -> MembershipPayload {
    MembershipPayload::join(
        realm_id,
        ActorId::account(participant),
        "direct_conversation_bootstrap",
    )
}

pub fn direct_conversation_main_strand_create_payload(
    realm_id: RealmId,
    creator: ActorId,
    created_at: DateTime<Utc>,
) -> StrandCreatePayload {
    let mut strand = Strand::new_create(realm_id, "Direct conversation", creator);
    strand.tracks.clear();
    strand.tracks.insert(
        STRAND_TRACK_NAME_DISCUSSION.to_owned(),
        StrandTrack::discussion_primary(),
    );
    strand.scope_circle_id = None;
    strand.state = Some(ObjectState::Active);
    strand.stage = Some(ObjectStage::InProgress);
    strand.created_at = created_at;
    StrandCreatePayload { object: strand }
}

/// Which participant of a pair is allowed to author the Direct Conversation founding unit.
///
/// The founder is derived from the pair's **root** Contact round and never from the current one, so
/// tombstone/recontact cycles cannot flip it. Both sides compute it independently from data both
/// can independently verify. Incomplete evidence grants neither participant creation authority.
/// Only after the same founder is established can its current Station's atomic unique slot
/// serialize competing units; a local index alone does not establish cross-Station authority.
///
/// See `zh/identity/contact-and-direct-conversation.md` §5.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectConversationFoundingAuthority {
    /// Exactly one accepted request. The founder is the **responder** — the participant that is not
    /// the request author.
    ///
    /// The caller must first validate the root round and its exact request and normal-response
    /// acceptance evidence. Current online status does not select or replace the founder;
    /// an offline founder retains authority and there is no timeout takeover.
    Normal { request_author_actor_id: ActorId },
    /// Concurrent requests from both sides. The caller supplies the signed Event author ActorId
    /// of requests[0] after validating strict full request_event_ref wire-byte order and evidence.
    /// This is never the Station receipt issuer, receipt-digest order, or arrival order.
    Glare {
        first_request_author_actor_id: ActorId,
    },
    /// controller-to-own-Agent conversations have no Contact round at all. The founder is fixed to
    /// the controller so an Agent runtime key never needs Direct Conversation founding scope.
    ControllerOwnedAgent { controller_actor_id: ActorId },
}

/// Derive the sole ActorId allowed to author the founding unit for `participants`.
///
/// `participants` is the unordered pair; ordering of the argument does not matter.
pub fn direct_conversation_founder(
    participants: [ActorId; 2],
    authority: &DirectConversationFoundingAuthority,
) -> Result<ActorId> {
    let [left, right] = participants;
    if left == right {
        return Err(WireError::Protocol(
            "direct conversation requires two distinct participants".to_owned(),
        ));
    }
    match authority {
        DirectConversationFoundingAuthority::Normal {
            request_author_actor_id,
        } => {
            if *request_author_actor_id == left {
                Ok(right)
            } else if *request_author_actor_id == right {
                Ok(left)
            } else {
                Err(WireError::Protocol(
                    "direct conversation normal authority request author is not a pair participant"
                        .to_owned(),
                ))
            }
        }
        DirectConversationFoundingAuthority::Glare {
            first_request_author_actor_id,
        } => {
            if *first_request_author_actor_id == left || *first_request_author_actor_id == right {
                Ok(first_request_author_actor_id.clone())
            } else {
                Err(WireError::Protocol(
                    "direct conversation glare authority requests[0] request author is not a pair participant"
                        .to_owned(),
                ))
            }
        }
        DirectConversationFoundingAuthority::ControllerOwnedAgent {
            controller_actor_id,
        } => {
            let controller_actor = controller_actor_id.clone();
            if controller_actor == left || controller_actor == right {
                Ok(controller_actor)
            } else {
                Err(WireError::Protocol(
                    "direct conversation controller-owned-Agent authority controller is not a pair participant"
                        .to_owned(),
                ))
            }
        }
    }
}

/// Whether `actor` may author the founding unit for `participants` under `authority`.
///
/// Callers MUST NOT fall back to "whoever asked first" or to a timeout: waiting never grants create
/// authority to the non-founder.
pub fn direct_conversation_may_found(
    actor: &ActorId,
    participants: [ActorId; 2],
    authority: &DirectConversationFoundingAuthority,
) -> Result<bool> {
    Ok(direct_conversation_founder(participants, authority)? == *actor)
}
