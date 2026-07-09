//! Direct-conversation helpers shared by SDK consumers.

use super::*;

pub const DIRECT_CONVERSATION_PAIR_KEY_VERSION: &str = "ak.direct_conversation.pair_key.v1";
pub const DIRECT_CONVERSATION_PAIR_KEY_PREFIX: &str = "ak:direct_pair:";

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
    version: &'static str,
    trust_domain: TypedTrustDomainId,
    participants: [Did; 2],
}

pub fn direct_conversation_pair_key(
    trust_domain: TypedTrustDomainId,
    left: DirectConversationPairKeyParticipant,
    right: DirectConversationPairKeyParticipant,
) -> Result<String> {
    let mut participants = [left.stable_subject, right.stable_subject];
    participants.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let material = DirectConversationPairKeyMaterial {
        version: DIRECT_CONVERSATION_PAIR_KEY_VERSION,
        trust_domain,
        participants,
    };
    let canonical = canonical::canonical_json_bytes(&material)?;
    Ok(format!(
        "{}{}",
        DIRECT_CONVERSATION_PAIR_KEY_PREFIX,
        canonical::sha256_base64url(&canonical)
    ))
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
        assert!(a.starts_with(DIRECT_CONVERSATION_PAIR_KEY_PREFIX));
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
}
