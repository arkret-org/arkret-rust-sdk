//! Direct-conversation helpers shared by SDK consumers.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[cfg(test)]
mod tests {
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
}
