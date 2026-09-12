//! Direct Conversation Realm role, builders, validation, and candidate folding.

use std::collections::BTreeSet;

use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    AccountId, ActorId, EncryptionProfile, EventId, GenesisSalt, Hash, ObjectStage, ObjectState,
    ProfileId, RealmId, Result, SchemaId, SecurityClass, TrustDomainId, WireError, canonical,
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
        let has_profile = genesis
            .schema_refs
            .iter()
            .any(|profile| profile == ProfileId::DIRECT_CONVERSATION_REALM_V1);
        if !has_profile || genesis.purpose != RealmPurpose::DirectConversation {
            return Err(WireError::Protocol(
                "direct conversation Realm purpose/profile mismatch (schema_violation)".to_owned(),
            ));
        }
        if genesis.encryption_profile != EncryptionProfile::MlsRfc9420 {
            return Err(WireError::Protocol(
                "direct conversation Realm genesis mismatch (schema_violation)".to_owned(),
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
    notary: NotaryValue,
    _created_at: DateTime<Utc>,
) -> Result<RealmCreatePayload> {
    let genesis = RealmGenesis::event_derived(
        RealmPurpose::DirectConversation,
        genesis_salt,
        trust_domain,
        vec![
            SchemaId::REALM_V1.to_owned(),
            ProfileId::DIRECT_CONVERSATION_REALM_V1.to_owned(),
        ],
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_canonical::DigestSuite::Sha256,
        SecurityClass::Standard,
        EncryptionProfile::MlsRfc9420,
        notary,
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

#[cfg(test)]
mod tests {
    use arkret_wire::notary::{NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor};
    use arkret_wire::{Did, DidCoreId, DidUrl};

    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn actor(value: &str) -> ActorId {
        ActorId::service(arkret_wire::project_did_to_core_id(&did(value)).unwrap())
    }

    fn principal(value: &str) -> ActorId {
        ActorId::service(arkret_wire::project_did_to_core_id(&did(value)).unwrap())
    }

    fn trust_domain() -> TrustDomainId {
        TrustDomainId::new("ak:trust_domain:example.test".to_owned()).unwrap()
    }

    fn notary(creator: &Did) -> NotaryValue {
        NotaryValue::new(
            NotarySignerDescriptor {
                actor_id: ActorId::service(arkret_wire::project_did_to_core_id(creator).unwrap()),
                verification_method: DidUrl::new(format!("{}#key-1", creator.as_str())).unwrap(),
                key_kind: NotaryKeyKind::Ed25519Raw32,
                jose_algorithm: NotaryJoseAlgorithm::Ed25519,
                frozen_public_key_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                frozen_public_key_digest: Hash::new(
                    "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
                )
                .unwrap(),
            },
            0,
        )
        .unwrap()
    }

    #[test]
    fn pair_key_is_order_independent() {
        let alice = DirectConversationPairKeyParticipant::unmapped(actor(
            "did:webvh:z6mkfixturealice:alice.example",
        ));
        let bob = DirectConversationPairKeyParticipant::unmapped(actor(
            "did:webvh:z6mkfixturebob:bob.example",
        ));

        let a = direct_conversation_pair_key(trust_domain(), alice.clone(), bob.clone()).unwrap();
        let b = direct_conversation_pair_key(trust_domain(), bob, alice).unwrap();

        assert_eq!(a, b);
        assert!(a.as_str().starts_with("sha256:"));
    }

    #[test]
    fn pair_key_matches_normative_known_answer() {
        let alice = DirectConversationPairKeyParticipant::unmapped(actor(
            "did:webvh:z6mkfixturealice:alice.example",
        ));
        let bob = DirectConversationPairKeyParticipant::unmapped(actor(
            "did:webvh:z6mkfixturebob:bob.example",
        ));

        let pair_key = direct_conversation_pair_key(trust_domain(), alice, bob).unwrap();

        assert_eq!(
            pair_key.as_str(),
            "sha256:93579842aa9c2d29256cae0dcf194185847f43aeb3e69b97cac8e73c3d60ef1f"
        );
    }

    #[test]
    fn pairwise_did_maps_to_stable_subject() {
        let stable = actor("did:webvh:z6mkfixturebob:bob.example");
        let alice = DirectConversationPairKeyParticipant::unmapped(actor(
            "did:webvh:z6mkfixturealice:alice.example",
        ));
        let pairwise_bob = DirectConversationPairKeyParticipant {
            actor_id: ActorId::service(
                DidCoreId::new("ak:did_core:webvh:z6mkpairwisebob").unwrap(),
            ),
            stable_subject: stable.clone(),
        };
        let stable_bob = DirectConversationPairKeyParticipant {
            actor_id: stable.clone(),
            stable_subject: stable,
        };

        let pairwise_key =
            direct_conversation_pair_key(trust_domain(), alice.clone(), pairwise_bob).unwrap();
        let stable_key = direct_conversation_pair_key(trust_domain(), alice, stable_bob).unwrap();

        assert_eq!(pairwise_key, stable_key);
    }

    #[test]
    fn pair_key_rejects_identical_stable_subjects() {
        let alice = DirectConversationPairKeyParticipant::unmapped(actor(
            "did:webvh:z6mkfixturealice:alice.example",
        ));
        assert!(direct_conversation_pair_key(trust_domain(), alice.clone(), alice).is_err());
    }

    #[test]
    fn builder_emits_closed_profiled_e2ee_realm() {
        let creator = did("did:webvh:z6mkfixturealice:alice.example");
        let payload = direct_conversation_realm_create_payload(
            GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            trust_domain(),
            notary(&creator),
            DateTime::parse_from_rfc3339("2026-07-21T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        assert_eq!(payload.object.purpose, RealmPurpose::DirectConversation);
        assert_eq!(
            payload.object.genesis_salt.as_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(payload.object.security_class, SecurityClass::Standard);
    }

    fn event_id(suffix: &str) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn authorization_basis_enforces_kind_specific_event_refs() {
        assert!(
            DirectConversationAuthorizationBasis::accepted_contact(vec![
                event_id("301"),
                event_id("308"),
            ])
            .validate_shape()
            .is_ok()
        );
        assert!(
            DirectConversationAuthorizationBasis::agent_controller(vec![
                event_id("311"),
                event_id("313"),
            ])
            .validate_shape()
            .is_ok()
        );
        assert!(
            DirectConversationAuthorizationBasis::accepted_contact(vec![event_id("301")])
                .validate_shape()
                .is_err()
        );
        assert!(
            DirectConversationAuthorizationBasis::agent_controller(vec![
                event_id("311"),
                event_id("311"),
            ])
            .validate_shape()
            .is_err()
        );
        assert!(
            DirectConversationAuthorizationBasis::agent_controller(vec![
                event_id("311"),
                event_id("312"),
                event_id("313"),
            ])
            .validate_shape()
            .is_err()
        );
    }

    #[test]
    fn normal_basis_founder_is_the_responder_not_the_requester() {
        let alice = actor("did:webvh:z6mkexamplealice:alice.example");
        let bob = actor("did:webvh:z6mkexamplebob:bob.example");

        // Alice sends the request, Bob accepts. Bob lit up the authority and is provably online at
        // that moment, so Bob founds. Naming Alice would pick the party most likely to be
        // absent, and base v1 has no fallback.
        let authority = DirectConversationFoundingAuthority::Normal {
            request_author_actor_id: alice.clone(),
        };
        let founder =
            direct_conversation_founder([alice.clone(), bob.clone()], &authority).unwrap();
        assert_eq!(founder, bob);
        assert_ne!(founder, alice, "founder must not be the request author");

        // Argument order must not matter.
        assert_eq!(
            direct_conversation_founder([bob.clone(), alice.clone()], &authority).unwrap(),
            bob
        );

        assert!(
            direct_conversation_may_found(&bob, [alice.clone(), bob.clone()], &authority).unwrap()
        );
        assert!(
            !direct_conversation_may_found(&alice, [alice.clone(), bob], &authority).unwrap(),
            "the non-founder may never author the founding unit"
        );
    }

    #[test]
    fn glare_basis_founder_is_the_first_request_author() {
        let alice = actor("did:webvh:z6mkexamplealice:alice.example");
        let bob = actor("did:webvh:z6mkexamplebob:bob.example");
        let authority = DirectConversationFoundingAuthority::Glare {
            first_request_author_actor_id: alice.clone(),
        };
        assert_eq!(
            direct_conversation_founder([alice.clone(), bob], &authority).unwrap(),
            alice
        );
    }

    #[test]
    fn controller_owned_agent_founder_is_fixed_to_the_controller() {
        let controller = principal("did:webvh:z6mkexamplealice:alice.example");
        let controller_actor = actor("did:webvh:z6mkexamplealice:alice.example");
        let agent = actor("did:webvh:z6mkexampleagent:alice-agent.example");
        let authority = DirectConversationFoundingAuthority::ControllerOwnedAgent {
            controller_actor_id: controller,
        };
        // Fixed regardless of DID ordering, so an Agent runtime key never needs founding scope.
        assert_eq!(
            direct_conversation_founder([agent.clone(), controller_actor.clone()], &authority)
                .unwrap(),
            controller_actor
        );
        assert!(
            !direct_conversation_may_found(&agent.clone(), [agent, controller_actor], &authority)
                .unwrap()
        );
    }

    #[test]
    fn founder_derivation_rejects_malformed_pairs() {
        let alice = actor("did:webvh:z6mkexample:alice.example");
        let bob = actor("did:webvh:z6mkexample:bob.example");
        let carol = actor("did:webvh:z6mkexample:carol.example");

        // Issuer outside the pair: never guess the complement.
        assert!(
            direct_conversation_founder(
                [alice.clone(), bob],
                &DirectConversationFoundingAuthority::Normal {
                    request_author_actor_id: carol,
                },
            )
            .is_err()
        );

        // Not two distinct participants.
        assert!(
            direct_conversation_founder(
                [alice.clone(), alice.clone()],
                &DirectConversationFoundingAuthority::Normal {
                    request_author_actor_id: alice,
                },
            )
            .is_err()
        );
    }
}
