//! Direct Conversation Realm role, builders, validation, and candidate folding.

use std::collections::BTreeSet;

use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    Did, Discoverability, EncryptionProfile, Error, EventId, FederationPolicy, Hash,
    HistoryVisibility, JoinRule, ObjectStage, ObjectState, ProfileId, RealmId, Result,
    SecurityClass, StrandId, TypedTrustDomainId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::device_identity::DirectConversationBoundPayload;
use crate::events_payloads::{RealmCreatePayload, StrandCreatePayload};
use crate::governance::circle::EncryptionFloor;
use crate::governance::delivery_binding::DeliveryStatus;
use crate::governance::membership_invite::MembershipPayload;
use crate::objects::profiles::STRAND_TRACK_NAME_DISCUSSION;
use crate::objects::realm::{NotaryProfile, Realm};
use crate::objects::strand::Strand;

pub const DIRECT_CONVERSATION_REALM_ROLE_FEATURE: &str =
    "ak.feature.direct_conversation_realm_role.v1";
pub const DIRECT_CONVERSATION_COLLABORATION_ROLE_FIELD: &str = "collaboration_role";
pub const DIRECT_CONVERSATION_COLLABORATION_ROLE: &str = "direct_conversation";

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
    pub did: Did,
    pub stable_subject: Did,
}

impl DirectConversationPairKeyParticipant {
    pub fn unmapped(did: Did) -> Self {
        Self {
            stable_subject: did.clone(),
            did,
        }
    }
}

#[derive(Serialize)]
struct DirectConversationPairKeyMaterial {
    participants: [Did; 2],
    trust_domain: TypedTrustDomainId,
}

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
        trust_domain,
    };
    let canonical = canonical::canonical_json_bytes(&material)?;
    Ok(Hash::new(canonical::sha256_digest(canonical))?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectConversationRealmRole;

impl DirectConversationRealmRole {
    pub fn validate(realm: &Realm) -> Result<Self> {
        let has_profile = realm
            .schema_refs
            .iter()
            .any(|profile| profile == ProfileId::DIRECT_CONVERSATION_REALM_V1);
        let has_discriminator = realm
            .fields
            .get(DIRECT_CONVERSATION_COLLABORATION_ROLE_FIELD)
            .and_then(Value::as_str)
            == Some(DIRECT_CONVERSATION_COLLABORATION_ROLE);
        if !has_profile || !has_discriminator {
            return Err(Error::Protocol(
                "direct conversation Realm profile/discriminator mismatch (schema_violation)"
                    .to_owned(),
            ));
        }
        if realm
            .schema_refs
            .iter()
            .any(|profile| profile == "ak.profile.principal_control_realm.v1")
            || realm.fields.contains_key("purpose")
        {
            return Err(Error::Protocol(
                "direct conversation Realm cannot also be a principal control Realm (schema_violation)"
                    .to_owned(),
            ));
        }
        if realm.encryption_profile != EncryptionProfile::MlsRfc9420
            || realm.default_join_rule != JoinRule::Closed
            || realm.content_encryption_floor != Some(EncryptionFloor::E2eeRequired)
            || realm.metadata_encryption_floor != Some(EncryptionFloor::E2eeRequired)
        {
            return Err(Error::Protocol(
                "direct conversation Realm security fields mismatch (schema_violation)".to_owned(),
            ));
        }
        Ok(Self)
    }

    pub fn matches(realm: &Realm) -> bool {
        Self::validate(realm).is_ok()
    }
}

pub fn direct_conversation_realm_create_payload(
    realm_id: RealmId,
    creator: Did,
    trust_domain: TypedTrustDomainId,
    notary_profile: NotaryProfile,
    notary: NotaryValue,
    capability_action_registry_digest: Hash,
    created_at: DateTime<Utc>,
) -> RealmCreatePayload {
    let mut realm = Realm::new(
        realm_id,
        "Direct conversation",
        creator,
        trust_domain,
        arkret_wire::CORE_REDUCER_PROFILE,
        notary_profile,
        notary,
        capability_action_registry_digest,
    );
    realm.security_class = Some(SecurityClass::Standard);
    realm
        .schema_refs
        .push(ProfileId::DIRECT_CONVERSATION_REALM_V1.to_owned());
    realm.fields.insert(
        DIRECT_CONVERSATION_COLLABORATION_ROLE_FIELD.to_owned(),
        Value::String(DIRECT_CONVERSATION_COLLABORATION_ROLE.to_owned()),
    );
    realm.default_discoverability = Discoverability::InviteOnly;
    realm.default_join_rule = JoinRule::Closed;
    realm.history_visibility = HistoryVisibility::Joined;
    realm.encryption_profile = EncryptionProfile::MlsRfc9420;
    realm.content_encryption_floor = Some(EncryptionFloor::E2eeRequired);
    realm.metadata_encryption_floor = Some(EncryptionFloor::E2eeRequired);
    realm.federation_policy = Some(FederationPolicy::Restricted);
    realm.created_at = created_at;
    RealmCreatePayload {
        object: realm,
        initial_relations: None,
    }
}

pub fn direct_conversation_membership_bootstrap(
    realm_id: RealmId,
    participants: [Did; 2],
    delivery_status: DeliveryStatus,
) -> Result<[MembershipPayload; 2]> {
    if participants[0] == participants[1] {
        return Err(Error::Protocol(
            "direct conversation participants must be distinct (schema_violation)".to_owned(),
        ));
    }
    Ok(participants.map(|participant| {
        MembershipPayload::join(
            realm_id.clone(),
            participant,
            delivery_status,
            "direct_conversation_bootstrap",
        )
    }))
}

pub fn direct_conversation_member_join_payload(
    realm_id: RealmId,
    participant: Did,
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
    strand_id: StrandId,
    realm_id: RealmId,
    creator: Did,
    created_at: DateTime<Utc>,
) -> StrandCreatePayload {
    let mut strand = Strand::discussion(strand_id, realm_id, "Direct conversation", creator);
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
    realm: &Realm,
    active_members: &BTreeSet<Did>,
    main_strand: &Strand,
) -> Result<()> {
    payload.validate_pair_key(trust_domain)?;
    DirectConversationRealmRole::validate(realm)?;
    if payload.realm_id != realm.id || payload.main_strand_id != main_strand.id {
        return Err(Error::Protocol(
            "direct conversation binding object reference mismatch (schema_violation)".to_owned(),
        ));
    }
    let participants: BTreeSet<Did> = payload.participants_unordered.iter().cloned().collect();
    if participants.len() != 2 || &participants != active_members {
        return Err(Error::Protocol(
            "direct_conversation_member_count_invalid".to_owned(),
        ));
    }
    if main_strand.realm_id != realm.id
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
    match payload.binding_state {
        DirectConversationAuthoredBindingState::Active => {}
        DirectConversationAuthoredBindingState::Retired => {
            if payload.supersedes_binding_ref.is_none() {
                return Err(Error::Protocol(
                    "retired direct conversation binding requires supersedes_binding_ref (schema_violation)"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct DirectConversationBindingCandidate {
    pub event_ref: EventId,
    pub event_digest: Hash,
    pub payload: DirectConversationBoundPayload,
}

#[derive(Clone, Debug)]
pub struct DirectConversationCandidateSelection {
    pub canonical: Option<DirectConversationBindingCandidate>,
    pub duplicate_active_refs: Vec<EventId>,
    pub retired_active_refs: Vec<EventId>,
}

pub fn select_canonical_direct_conversation_binding(
    candidates: impl IntoIterator<Item = DirectConversationBindingCandidate>,
) -> Result<DirectConversationCandidateSelection> {
    let candidates: Vec<_> = candidates.into_iter().collect();
    let Some(pair_key) = candidates
        .first()
        .map(|candidate| candidate.payload.pair_key.clone())
    else {
        return Ok(DirectConversationCandidateSelection {
            canonical: None,
            duplicate_active_refs: Vec::new(),
            retired_active_refs: Vec::new(),
        });
    };
    if candidates
        .iter()
        .any(|candidate| candidate.payload.pair_key != pair_key)
    {
        return Err(Error::Protocol(
            "direct conversation candidate reducer requires one pair_key".to_owned(),
        ));
    }

    let retired_active_refs: BTreeSet<EventId> = candidates
        .iter()
        .filter(|candidate| {
            candidate.payload.binding_state == DirectConversationAuthoredBindingState::Retired
        })
        .filter_map(|candidate| candidate.payload.supersedes_binding_ref.clone())
        .collect();
    let mut active: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| {
            candidate.payload.binding_state == DirectConversationAuthoredBindingState::Active
                && !retired_active_refs.contains(&candidate.event_ref)
        })
        .collect();
    active.sort_by(|left, right| left.event_digest.as_str().cmp(right.event_digest.as_str()));
    let canonical = active.pop();
    let duplicate_active_refs = active
        .into_iter()
        .map(|candidate| candidate.event_ref)
        .collect();
    Ok(DirectConversationCandidateSelection {
        canonical,
        duplicate_active_refs,
        retired_active_refs: retired_active_refs.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use arkret_wire::MlsGroupId;

    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn trust_domain() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:example.test".to_owned()).unwrap()
    }

    #[test]
    fn pair_key_is_order_independent() {
        let alice = DirectConversationPairKeyParticipant::unmapped(did(
            "did:webvh:z6mkfixture:alice.example",
        ));
        let bob = DirectConversationPairKeyParticipant::unmapped(did(
            "did:webvh:z6mkfixture:bob.example",
        ));

        let a = direct_conversation_pair_key(trust_domain(), alice.clone(), bob.clone()).unwrap();
        let b = direct_conversation_pair_key(trust_domain(), bob, alice).unwrap();

        assert_eq!(a, b);
        assert!(a.as_str().starts_with("sha256:"));
    }

    #[test]
    fn pair_key_matches_normative_known_answer() {
        let alice = DirectConversationPairKeyParticipant::unmapped(did(
            "did:webvh:z6mkfixture:alice.example",
        ));
        let bob = DirectConversationPairKeyParticipant::unmapped(did(
            "did:webvh:z6mkfixture:bob.example",
        ));

        let pair_key = direct_conversation_pair_key(trust_domain(), alice, bob).unwrap();

        assert_eq!(
            pair_key.as_str(),
            "sha256:a97a411daac39d8fe9c29755109c5785e86b83e9f966c65363bafcf02654790b"
        );
    }

    #[test]
    fn pairwise_did_maps_to_stable_subject() {
        let stable = did("did:webvh:z6mkfixture:bob.example");
        let alice = DirectConversationPairKeyParticipant::unmapped(did(
            "did:webvh:z6mkfixture:alice.example",
        ));
        let pairwise_bob = DirectConversationPairKeyParticipant {
            did: did("did:peer:2.ezbobpairwise"),
            stable_subject: stable.clone(),
        };
        let stable_bob = DirectConversationPairKeyParticipant {
            did: stable.clone(),
            stable_subject: stable,
        };

        let pairwise_key =
            direct_conversation_pair_key(trust_domain(), alice.clone(), pairwise_bob).unwrap();
        let stable_key = direct_conversation_pair_key(trust_domain(), alice, stable_bob).unwrap();

        assert_eq!(pairwise_key, stable_key);
    }

    #[test]
    fn pair_key_rejects_identical_stable_subjects() {
        let alice = DirectConversationPairKeyParticipant::unmapped(did(
            "did:webvh:z6mkfixture:alice.example",
        ));
        assert!(direct_conversation_pair_key(trust_domain(), alice.clone(), alice).is_err());
    }

    #[test]
    fn builder_emits_closed_profiled_e2ee_realm() {
        let creator = did("did:webvh:z6mkfixture:alice.example");
        let payload = direct_conversation_realm_create_payload(
            RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000101").unwrap(),
            creator.clone(),
            trust_domain(),
            NotaryProfile::SingleDid,
            NotaryValue::single_did(creator),
            Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
            DateTime::parse_from_rfc3339("2026-07-21T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert!(DirectConversationRealmRole::matches(&payload.object));
        assert_eq!(payload.object.default_join_rule, JoinRule::Closed);
        assert_eq!(
            payload.object.metadata_encryption_floor,
            Some(EncryptionFloor::E2eeRequired)
        );
    }

    fn event_id(suffix: &str) -> EventId {
        EventId::new(format!("ak:event:0196419b-0000-7000-8000-{suffix:0>12}")).unwrap()
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

    fn binding_payload(
        state: DirectConversationAuthoredBindingState,
        supersedes_binding_ref: Option<EventId>,
    ) -> DirectConversationBoundPayload {
        let alice = did("did:webvh:z6mkfixture:alice.example");
        let bob = did("did:webvh:z6mkfixture:bob.example");
        DirectConversationBoundPayload {
            pair_key: direct_conversation_pair_key(
                trust_domain(),
                DirectConversationPairKeyParticipant::unmapped(alice.clone()),
                DirectConversationPairKeyParticipant::unmapped(bob.clone()),
            )
            .unwrap(),
            binding_state: state,
            participants_unordered: vec![alice, bob],
            realm_id: RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000101".to_owned())
                .unwrap(),
            main_strand_id: StrandId::new(
                "ak:strand:0196419b-0000-7000-8000-000000000201".to_owned(),
            )
            .unwrap(),
            authorization_basis: DirectConversationAuthorizationBasis::accepted_contact(vec![
                event_id("301"),
                event_id("308"),
            ]),
            member_event_refs: vec![event_id("302"), event_id("303")],
            main_strand_create_ref: event_id("304"),
            mls_group_id: MlsGroupId::new("ak:mls_group:direct-fixture").unwrap(),
            mls_genesis_event_ref: event_id("305"),
            mls_commit_event_ref: event_id("306"),
            mls_welcome_event_ref: event_id("307"),
            created_at: DateTime::parse_from_rfc3339("2026-07-21T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            supersedes_binding_ref,
        }
    }

    #[test]
    fn validator_rejects_third_member_and_circle_scoped_main_strand() {
        let creator = did("did:webvh:z6mkfixture:alice.example");
        let realm = direct_conversation_realm_create_payload(
            RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000101").unwrap(),
            creator.clone(),
            trust_domain(),
            NotaryProfile::SingleDid,
            NotaryValue::single_did(creator.clone()),
            Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
            Utc::now(),
        )
        .object;
        let mut strand = direct_conversation_main_strand_create_payload(
            StrandId::new("ak:strand:0196419b-0000-7000-8000-000000000201").unwrap(),
            realm.id.clone(),
            creator,
            Utc::now(),
        )
        .object;
        let payload = binding_payload(DirectConversationAuthoredBindingState::Active, None);
        let mut members: BTreeSet<_> = payload.participants_unordered.iter().cloned().collect();
        assert!(
            validate_direct_conversation_binding(
                &payload,
                trust_domain(),
                &realm,
                &members,
                &strand,
            )
            .is_ok()
        );

        members.insert(did("did:webvh:z6mkfixture:carol.example"));
        assert!(
            validate_direct_conversation_binding(
                &payload,
                trust_domain(),
                &realm,
                &members,
                &strand,
            )
            .is_err()
        );
        members.remove(&did("did:webvh:z6mkfixture:carol.example"));
        strand.scope_circle_id = Some(
            arkret_wire::CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000401".to_owned())
                .unwrap(),
        );
        assert!(
            validate_direct_conversation_binding(
                &payload,
                trust_domain(),
                &realm,
                &members,
                &strand,
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_reducer_uses_digest_max_and_retirement() {
        let lower_ref = event_id("501");
        let higher_ref = event_id("502");
        let lower = DirectConversationBindingCandidate {
            event_ref: lower_ref.clone(),
            event_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            payload: binding_payload(DirectConversationAuthoredBindingState::Active, None),
        };
        let higher = DirectConversationBindingCandidate {
            event_ref: higher_ref.clone(),
            event_digest: Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap(),
            payload: binding_payload(DirectConversationAuthoredBindingState::Active, None),
        };
        let selection =
            select_canonical_direct_conversation_binding([lower, higher.clone()]).unwrap();
        assert_eq!(selection.canonical.unwrap().event_ref, higher.event_ref);
        assert_eq!(selection.duplicate_active_refs, vec![lower_ref]);

        let retired = DirectConversationBindingCandidate {
            event_ref: event_id("503"),
            event_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
            payload: binding_payload(
                DirectConversationAuthoredBindingState::Retired,
                Some(higher_ref.clone()),
            ),
        };
        let selection = select_canonical_direct_conversation_binding([higher, retired]).unwrap();
        assert!(selection.canonical.is_none());
        assert_eq!(selection.retired_active_refs, vec![higher_ref]);
    }
}
