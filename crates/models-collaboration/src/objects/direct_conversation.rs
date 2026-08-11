//! Direct Conversation Realm role, builders, validation, and candidate folding.

use std::collections::BTreeSet;

use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    DidCoreId, EncryptionProfile, Error, EventId, GenesisSalt, Hash, ObjectStage, ObjectState,
    ProfileId, RealmId, Result, SchemaId, SecurityClass, TypedTrustDomainId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::device_identity::DirectConversationBoundPayload;
use crate::events_payloads::{RealmCreatePayload, RealmGenesis, RealmPurpose, StrandCreatePayload};
use crate::governance::delivery_binding::DeliveryStatus;
use crate::governance::membership_invite::MembershipPayload;
use crate::objects::profiles::{STRAND_TRACK_NAME_DISCUSSION, StrandTrackConfig};
use crate::objects::realm::NotaryProfile;
use crate::objects::strand::Strand;

pub const DIRECT_CONVERSATION_REALM_ROLE_FEATURE: &str =
    "ak.feature.direct_conversation_realm_role.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationAuthoredBindingState {
    Active,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationAuthorizationKind {
    AcceptedContact,
    ManagedAgentController,
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

    pub fn managed_agent_controller(event_refs: Vec<EventId>) -> Self {
        Self {
            kind: DirectConversationAuthorizationKind::ManagedAgentController,
            event_refs,
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        let unique = self.event_refs.iter().collect::<BTreeSet<_>>();
        let expected_len = match self.kind {
            DirectConversationAuthorizationKind::AcceptedContact => 2,
            DirectConversationAuthorizationKind::ManagedAgentController => 2,
        };
        if self.event_refs.len() != expected_len || unique.len() != self.event_refs.len() {
            return Err(Error::Protocol(format!(
                "direct conversation authorization basis requires {expected_len} unique event_refs (schema_violation)"
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
    pub actor_id: DidCoreId,
    pub stable_subject: DidCoreId,
}

impl DirectConversationPairKeyParticipant {
    pub fn unmapped(did: DidCoreId) -> Self {
        Self {
            stable_subject: did.clone(),
            actor_id: did,
        }
    }
}

#[derive(Serialize)]
struct DirectConversationPairKeyMaterial {
    participants: [DidCoreId; 2],
    trust_domain_id: TypedTrustDomainId,
}

const DIRECT_CONVERSATION_PAIR_KEY_DOMAIN: &[u8] = b"ak.direct-conversation.pair-key.v1\n";

pub fn direct_conversation_pair_key(
    trust_domain: TypedTrustDomainId,
    left: DirectConversationPairKeyParticipant,
    right: DirectConversationPairKeyParticipant,
) -> Result<Hash> {
    let mut participants = [left.stable_subject, right.stable_subject];
    participants.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    if participants[0] == participants[1] {
        return Err(Error::Protocol(
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
            return Err(Error::Protocol(
                "direct conversation Realm purpose/profile mismatch (schema_violation)".to_owned(),
            ));
        }
        if genesis.encryption_profile != EncryptionProfile::MlsRfc9420 {
            return Err(Error::Protocol(
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
    trust_domain: TypedTrustDomainId,
    notary_profile: NotaryProfile,
    notary: NotaryValue,
    capability_action_registry_digest: Hash,
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
        notary_profile,
        notary,
        capability_action_registry_digest,
    )?;
    Ok(RealmCreatePayload::new(genesis))
}

/// Build the sole explicit membership Event in the exact three-Event Direct
/// Conversation founding unit. The founder membership is a fixed profile
/// projection of `ak.realm.create`; authoring two membership Events would make
/// the unit non-canonical.
pub fn direct_conversation_peer_membership_bootstrap(
    realm_id: RealmId,
    founder: &DidCoreId,
    participants: [DidCoreId; 2],
    delivery_status: DeliveryStatus,
) -> Result<MembershipPayload> {
    if participants[0] == participants[1] {
        return Err(Error::Protocol(
            "direct conversation participants must be distinct (schema_violation)".to_owned(),
        ));
    }
    if !participants
        .iter()
        .any(|participant| participant == founder)
    {
        return Err(Error::Protocol(
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
        peer,
        delivery_status,
        "direct_conversation_bootstrap",
    ))
}

pub fn direct_conversation_member_join_payload(
    realm_id: RealmId,
    participant: DidCoreId,
    delivery_status: DeliveryStatus,
) -> MembershipPayload {
    MembershipPayload::join(
        realm_id,
        participant,
        delivery_status,
        "direct_conversation_bootstrap",
    )
}

pub fn direct_conversation_main_strand_create_payload(
    realm_id: RealmId,
    creator: DidCoreId,
    created_at: DateTime<Utc>,
) -> StrandCreatePayload {
    let mut strand = Strand::new_create(realm_id, "Direct conversation", creator);
    strand.tracks.clear();
    strand.tracks.insert(
        STRAND_TRACK_NAME_DISCUSSION.to_owned(),
        StrandTrackConfig::discussion_primary(),
    );
    strand.scope_circle_id = None;
    strand.state = Some(ObjectState::Active);
    strand.stage = Some(ObjectStage::InProgress);
    strand.created_at = created_at;
    StrandCreatePayload {
        object: strand,
        initial_relations: None,
    }
}

pub fn validate_direct_conversation_binding(
    payload: &DirectConversationBoundPayload,
    trust_domain: TypedTrustDomainId,
    genesis: &RealmGenesis,
    realm_id: &RealmId,
    active_members: &BTreeSet<DidCoreId>,
    main_strand: &Strand,
) -> Result<()> {
    payload.validate_pair_key(trust_domain)?;
    DirectConversationRealmRole::validate(genesis)?;
    if &payload.realm_id != realm_id || Some(&payload.main_strand_id) != main_strand.id.as_ref() {
        return Err(Error::Protocol(
            "direct conversation binding object reference mismatch (schema_violation)".to_owned(),
        ));
    }
    let participants: BTreeSet<DidCoreId> =
        payload.participants_unordered.iter().cloned().collect();
    if participants.len() != 2 || &participants != active_members {
        return Err(Error::Protocol(
            "direct_conversation_member_count_invalid".to_owned(),
        ));
    }
    if &main_strand.realm_id != realm_id
        || main_strand.scope_circle_id.is_some()
        || main_strand.state != Some(ObjectState::Active)
    {
        return Err(Error::Protocol(
            "direct conversation main Strand boundary mismatch (schema_violation)".to_owned(),
        ));
    }
    let discussion = main_strand
        .tracks
        .get(STRAND_TRACK_NAME_DISCUSSION)
        .ok_or_else(|| {
            Error::Protocol(
                "direct conversation main Strand discussion track missing (schema_violation)"
                    .to_owned(),
            )
        })?;
    if discussion.enabled == Some(false) || discussion.is_primary != Some(true) {
        return Err(Error::Protocol(
            "direct conversation main Strand discussion track is not active primary (schema_violation)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Which participant of a pair is allowed to author the Direct Conversation founding unit.
///
/// The founder is derived from the pair's **root** Contact basis and never from the current one, so
/// tombstone/recontact cycles cannot flip it. Both sides compute it independently from data both
/// already hold and both already signed, which is what removes the cross-server creation race: only
/// one principal can create, so the contention collapses into a unique index on that principal's
/// own Principal Server.
///
/// See `zh/identity/contact-and-direct-conversation.md` §5.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectConversationFounderBasis {
    /// Exactly one accepted request. The founder is the **responder** — the participant that is not
    /// the request issuer.
    ///
    /// This is deliberate and normative: the basis is lit up by the responder's
    /// `normal_response_acceptance_receipt`, which proves the responder was online at the moment
    /// the basis came into existence. The requester may have gone offline days earlier. Since
    /// base v1 defines no fallback, naming the possibly-absent party as founder would leave the
    /// pair unable to ever create the conversation.
    Normal { request_issuer: DidCoreId },
    /// Concurrent requests from both sides. There is no responder, so the founder is the issuer of
    /// `requests[0]` under the ordering already registered for glare requests.
    Glare { first_request_issuer: DidCoreId },
    /// controller-to-own-Agent conversations have no Contact basis at all. The founder is fixed to
    /// the controller so an Agent runtime key never needs Direct Conversation founding scope.
    ControllerOwnedAgent { controller_id: DidCoreId },
}

/// Derive the sole principal allowed to author the founding unit for `participants`.
///
/// `participants` is the unordered pair; ordering of the argument does not matter.
pub fn direct_conversation_founder(
    participants: [DidCoreId; 2],
    basis: &DirectConversationFounderBasis,
) -> Result<DidCoreId> {
    let [left, right] = participants;
    if left == right {
        return Err(Error::Protocol(
            "direct conversation requires two distinct participants".to_owned(),
        ));
    }
    match basis {
        DirectConversationFounderBasis::Normal { request_issuer } => {
            if *request_issuer == left {
                Ok(right)
            } else if *request_issuer == right {
                Ok(left)
            } else {
                Err(Error::Protocol(
                    "direct conversation normal basis request issuer is not a pair participant"
                        .to_owned(),
                ))
            }
        }
        DirectConversationFounderBasis::Glare {
            first_request_issuer,
        } => {
            if *first_request_issuer == left || *first_request_issuer == right {
                Ok(first_request_issuer.clone())
            } else {
                Err(Error::Protocol(
                    "direct conversation glare basis requests[0] issuer is not a pair participant"
                        .to_owned(),
                ))
            }
        }
        DirectConversationFounderBasis::ControllerOwnedAgent { controller_id } => {
            let controller_actor = controller_id.clone();
            if controller_actor == left || controller_actor == right {
                Ok(controller_actor)
            } else {
                Err(Error::Protocol(
                    "direct conversation controller-owned-Agent basis controller is not a pair participant"
                        .to_owned(),
                ))
            }
        }
    }
}

/// Whether `actor` may author the founding unit for `participants` under `basis`.
///
/// Callers MUST NOT fall back to "whoever asked first" or to a timeout: waiting never grants create
/// authority to the non-founder.
pub fn direct_conversation_may_found(
    actor: &DidCoreId,
    participants: [DidCoreId; 2],
    basis: &DirectConversationFounderBasis,
) -> Result<bool> {
    Ok(direct_conversation_founder(participants, basis)? == *actor)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidCoreId, DidFullId, StrandId};

    use super::*;

    fn full_id(value: &str) -> DidFullId {
        DidFullId::new(value.to_owned()).unwrap()
    }

    fn actor(value: &str) -> DidCoreId {
        arkret_wire::project_full_id_to_core_id(&full_id(value)).unwrap()
    }

    fn principal(value: &str) -> DidCoreId {
        arkret_wire::project_full_id_to_core_id(&full_id(value)).unwrap()
    }

    fn trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:example.test".to_owned()).unwrap()
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
            "sha256:71eac812be14d047f791749f9409bbdc6ab0af5999daa9077bc21f23bdfca1eb"
        );
    }

    #[test]
    fn pairwise_did_maps_to_stable_subject() {
        let stable = actor("did:webvh:z6mkfixturebob:bob.example");
        let alice = DirectConversationPairKeyParticipant::unmapped(actor(
            "did:webvh:z6mkfixturealice:alice.example",
        ));
        let pairwise_bob = DirectConversationPairKeyParticipant {
            actor_id: DidCoreId::new("ak:did_core:webvh:z6mkpairwisebob").unwrap(),
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
        let creator = full_id("did:webvh:z6mkfixturealice:alice.example");
        let payload = direct_conversation_realm_create_payload(
            GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            trust_domain(),
            NotaryProfile::SingleDid,
            NotaryValue::single_did(actor(creator.as_str())),
            Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
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
            DirectConversationAuthorizationBasis::managed_agent_controller(vec![
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
            DirectConversationAuthorizationBasis::managed_agent_controller(vec![
                event_id("311"),
                event_id("311"),
            ])
            .validate_shape()
            .is_err()
        );
        assert!(
            DirectConversationAuthorizationBasis::managed_agent_controller(vec![
                event_id("311"),
                event_id("312"),
                event_id("313"),
            ])
            .validate_shape()
            .is_err()
        );
    }

    fn binding_payload() -> DirectConversationBoundPayload {
        let alice = actor("did:webvh:z6mkfixturealice:alice.example");
        let bob = actor("did:webvh:z6mkfixturebob:bob.example");
        DirectConversationBoundPayload {
            pair_key: direct_conversation_pair_key(
                trust_domain(),
                DirectConversationPairKeyParticipant::unmapped(alice.clone()),
                DirectConversationPairKeyParticipant::unmapped(bob.clone()),
            )
            .unwrap(),
            participants_unordered: vec![alice, bob],
            realm_id: RealmId::new(
                "ak:realm:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz".to_owned(),
            )
            .unwrap(),
            main_strand_id: StrandId::new(
                "ak:strand:AVBgYTmzSkzTSd1dlFH4ZADaQRkVcx_iTAvXdxlTfxrg".to_owned(),
            )
            .unwrap(),
            founding_unit_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            authorization_basis: DirectConversationAuthorizationBasis::accepted_contact(vec![
                event_id("301"),
                event_id("308"),
            ]),
            initial_exact_pair_generation_ref: event_id("309"),
            created_at: DateTime::parse_from_rfc3339("2026-07-21T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn validator_rejects_third_member_and_circle_scoped_main_strand() {
        let creator = full_id("did:webvh:z6mkfixturealice:alice.example");
        let realm = direct_conversation_realm_create_payload(
            GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            trust_domain(),
            NotaryProfile::SingleDid,
            NotaryValue::single_did(actor(creator.as_str())),
            Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
            Utc::now(),
        )
        .unwrap()
        .object;
        let realm_id =
            RealmId::new("ak:realm:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz").unwrap();
        let payload = binding_payload();
        let mut strand = direct_conversation_main_strand_create_payload(
            realm_id,
            actor(creator.as_str()),
            Utc::now(),
        )
        .object;
        assert!(
            strand.id.is_none(),
            "create payload must omit the derived id"
        );
        // The binding validator consumes the materialized projection, where the
        // reducer has retyped the accepted create Event id.
        strand.id = Some(payload.main_strand_id.clone());
        let mut members: BTreeSet<_> = payload.participants_unordered.iter().cloned().collect();
        assert!(
            validate_direct_conversation_binding(
                &payload,
                trust_domain(),
                &realm,
                &payload.realm_id,
                &members,
                &strand,
            )
            .is_ok()
        );

        members.insert(actor("did:webvh:z6mkfixture:carol.example"));
        assert!(
            validate_direct_conversation_binding(
                &payload,
                trust_domain(),
                &realm,
                &payload.realm_id,
                &members,
                &strand,
            )
            .is_err()
        );
        members.remove(&actor("did:webvh:z6mkfixture:carol.example"));
        strand.scope_circle_id = Some(
            arkret_wire::CircleId::new(
                "ak:circle:AQaY-AgUKie8pbyjuUgx-yC0rr0hNo4pI80rr9GC6eAd".to_owned(),
            )
            .unwrap(),
        );
        assert!(
            validate_direct_conversation_binding(
                &payload,
                trust_domain(),
                &realm,
                &payload.realm_id,
                &members,
                &strand,
            )
            .is_err()
        );
    }

    #[test]
    fn normal_basis_founder_is_the_responder_not_the_requester() {
        let alice = actor("did:webvh:z6mkexamplealice:alice.example");
        let bob = actor("did:webvh:z6mkexamplebob:bob.example");

        // Alice sends the request, Bob accepts. Bob lit up the basis and is provably online at that
        // moment, so Bob founds. Naming Alice would pick the party most likely to be absent, and
        // base v1 has no fallback.
        let basis = DirectConversationFounderBasis::Normal {
            request_issuer: alice.clone(),
        };
        let founder = direct_conversation_founder([alice.clone(), bob.clone()], &basis).unwrap();
        assert_eq!(founder, bob);
        assert_ne!(founder, alice, "founder must not be the request issuer");

        // Argument order must not matter.
        assert_eq!(
            direct_conversation_founder([bob.clone(), alice.clone()], &basis).unwrap(),
            bob
        );

        assert!(direct_conversation_may_found(&bob, [alice.clone(), bob.clone()], &basis).unwrap());
        assert!(
            !direct_conversation_may_found(&alice, [alice.clone(), bob], &basis).unwrap(),
            "the non-founder may never author the founding unit"
        );
    }

    #[test]
    fn glare_basis_founder_is_the_first_request_issuer() {
        let alice = actor("did:webvh:z6mkexamplealice:alice.example");
        let bob = actor("did:webvh:z6mkexamplebob:bob.example");
        let basis = DirectConversationFounderBasis::Glare {
            first_request_issuer: alice.clone(),
        };
        assert_eq!(
            direct_conversation_founder([alice.clone(), bob], &basis).unwrap(),
            alice
        );
    }

    #[test]
    fn controller_owned_agent_founder_is_fixed_to_the_controller() {
        let controller = principal("did:webvh:z6mkexamplealice:alice.example");
        let controller_actor = actor("did:webvh:z6mkexamplealice:alice.example");
        let agent = actor("did:webvh:z6mkexampleagent:alice-agent.example");
        let basis = DirectConversationFounderBasis::ControllerOwnedAgent {
            controller_id: controller,
        };
        // Fixed regardless of DID ordering, so an Agent runtime key never needs founding scope.
        assert_eq!(
            direct_conversation_founder([agent.clone(), controller_actor.clone()], &basis).unwrap(),
            controller_actor
        );
        assert!(
            !direct_conversation_may_found(&agent.clone(), [agent, controller_actor], &basis)
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
                &DirectConversationFounderBasis::Normal {
                    request_issuer: carol,
                },
            )
            .is_err()
        );

        // Not two distinct participants.
        assert!(
            direct_conversation_founder(
                [alice.clone(), alice.clone()],
                &DirectConversationFounderBasis::Normal {
                    request_issuer: alice,
                },
            )
            .is_err()
        );
    }
}
