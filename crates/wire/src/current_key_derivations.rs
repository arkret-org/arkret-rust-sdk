//! Family-specific typed-current row-key derivations.
//!
//! These opaque digests locate registered current rows. They are not wire IDs,
//! signature inputs, revisions, governance tenure, or authorization evidence.
//! Deliberately no public API accepts an arbitrary component slice or JSON value.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{AccountId, ActorId, DidCoreId, Result, WireError};

const MEMBER_STATE_DOMAIN: &str = "ak.current_key.member_state.v1";
const AGENT_INTERACTION_DOMAIN: &str = "ak.current_key.agent_interaction.v1";
const AGENT_STATUS_DOMAIN: &str = "ak.current_key.agent_status.v1";
const AGENT_KEY_DOMAIN: &str = "ak.current_key.agent_key.v1";

/// Closed `agent_key_id` scalar used by the Agent-key current-row derivation.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentKeyId(String);

impl AgentKeyId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_agent_key_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_agent_key_identifier(self.as_str())
    }
}

impl AsRef<str> for AgentKeyId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for AgentKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for AgentKeyId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentKeyId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Canonical Agent-key selector profile; verification methods keep their own bounds.
pub fn validate_agent_key_identifier(value: &str) -> Result<()> {
    crate::validate_bounded_non_typed_identifier(value, 256)
        .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
    static VOCABULARY: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\A(?:did:[a-z0-9]+:[^\s#]+#[^\s#]+|[a-zA-Z0-9._:-]{1,256})\z")
            .expect("the canonical Agent-key vocabulary is a valid regular expression")
    });
    if !VOCABULARY.is_match(value) {
        return Err(WireError::Protocol(
            "Agent key selector violates its DID-URL/local-token vocabulary".into(),
        ));
    }
    Ok(())
}

pub fn deserialize_agent_key_identifier<'de, D, T>(
    deserializer: D,
) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + AsRef<str>,
{
    let value = T::deserialize(deserializer)?;
    validate_agent_key_identifier(value.as_ref()).map_err(de::Error::custom)?;
    Ok(value)
}

pub fn deserialize_optional_agent_key_identifier<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + AsRef<str>,
{
    deserialize_agent_key_identifier(deserializer).map(Some)
}

fn derive<T: Serialize + ?Sized>(domain: &str, components: &T) -> Result<String> {
    let mut preimage = domain.as_bytes().to_vec();
    preimage.push(b'\n');
    preimage.extend(arkret_canonical::canonical_json_bytes(components)?);
    Ok(arkret_canonical::sha256_base64url(preimage))
}

/// Derive the opaque current-row locator for the complete member `ActorId`.
pub fn derive_member_state_current_key(member_actor_id: &ActorId) -> Result<String> {
    derive(MEMBER_STATE_DOMAIN, &[member_actor_id])
}

/// Derive the opaque current-row locator for an Agent lifecycle `ActorId`.
pub fn derive_agent_status_current_key(agent_actor_id: &ActorId) -> Result<String> {
    derive(AGENT_STATUS_DOMAIN, &[agent_actor_id])
}

/// Derive the Realm-local mode locator from the complete Agent AccountId.
pub fn derive_agent_interaction_current_key(agent_account_id: &AccountId) -> Result<String> {
    derive(AGENT_INTERACTION_DOMAIN, &[agent_account_id])
}

/// Derive the opaque current-row locator for one `(agent_id, key_id)` pair.
pub fn derive_agent_key_current_key(agent_id: &DidCoreId, key_id: &AgentKeyId) -> Result<String> {
    key_id.validate()?;
    derive(AGENT_KEY_DOMAIN, &(agent_id, key_id))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::AccountId;

    fn actor(principal: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
        ))
    }

    #[test]
    fn formal_kats_match() {
        assert_eq!(
            derive_member_state_current_key(&actor("ak:did_core:webvh:z6mkfixturemember")).unwrap(),
            "skNSTfT-fp3xvq7ZDIjPEfry6fz9p160YeTYRoGCW_o"
        );
        assert_eq!(
            derive_agent_status_current_key(&actor("ak:did_core:webvh:z6mkfixtureagent")).unwrap(),
            "1-8BcBY4BwpOnF47FI4Vc2KfTP0OMyAdHkKyKbGNXZU"
        );
        assert_eq!(
            derive_agent_key_current_key(
                &DidCoreId::new("ak:did_core:webvh:z6mkfixtureagent").unwrap(),
                &AgentKeyId::new("did:webvh:z6mkfixtureagent:agent.example#runtime-1").unwrap(),
            )
            .unwrap(),
            "PfgyVkXhI1H9x4sv9t1SYQ-_HMqFNm0iiOtE_s_cODU"
        );
    }

    #[test]
    fn agent_mode_key_binds_both_account_components_and_the_family() {
        let a = actor("ak:did_core:webvh:z6mkfixtureagent");
        let account = a.as_account_id().unwrap();
        let other = AccountId::new(
            account.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );
        assert_ne!(
            derive_agent_interaction_current_key(account).unwrap(),
            derive_agent_interaction_current_key(&other).unwrap()
        );
        assert_ne!(
            derive_agent_interaction_current_key(account).unwrap(),
            derive_agent_status_current_key(&a).unwrap()
        );
    }

    #[test]
    fn family_domain_and_component_order_diverge() {
        let components = json!([
            "ak:did_core:webvh:z6mkfixtureagent",
            "did:webvh:z6mkfixtureagent:agent.example#runtime-1"
        ]);
        assert_eq!(
            derive(AGENT_KEY_DOMAIN, &components).unwrap(),
            "PfgyVkXhI1H9x4sv9t1SYQ-_HMqFNm0iiOtE_s_cODU"
        );
        assert_eq!(
            derive(
                AGENT_KEY_DOMAIN,
                &json!([
                    "did:webvh:z6mkfixtureagent:agent.example#runtime-1",
                    "ak:did_core:webvh:z6mkfixtureagent"
                ])
            )
            .unwrap(),
            "81mRszOIXlPY523kSrncRmktgEbQ0_5JpdP65ml0PCc"
        );
        assert_eq!(
            derive("ak.current_key.wrong_family.v1", &components).unwrap(),
            "qCsEjY2f2RJ9gYyWeMkdl_NGuuJrDAtDE7oNCaGKV2Y"
        );
    }

    #[test]
    fn agent_key_selector_has_shared_total_bounds_and_absolute_vocabulary() {
        let unicode = format!("did:web:{}#k", "é".repeat(246));
        assert_eq!(unicode.chars().count(), 256);
        for value in ["runtime-key".to_owned(), "a".repeat(256), unicode] {
            let id = AgentKeyId::new(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(&id).unwrap(), json!(value));
            assert!(serde_json::from_value::<AgentKeyId>(json!(value)).is_ok());
            assert!(
                derive_agent_key_current_key(
                    &DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                    &id
                )
                .is_ok()
            );
        }
        for value in [
            String::new(),
            "a".repeat(257),
            "ak:key:example".to_owned(),
            " ".to_owned(),
            "runtime\n".to_owned(),
            "did:web:example#key\n".to_owned(),
            format!("did:web:{}#k", "é".repeat(247)),
        ] {
            assert!(AgentKeyId::new(value.clone()).is_err(), "{value:?}");
            assert!(serde_json::from_value::<AgentKeyId>(json!(value)).is_err());
            let invalid = AgentKeyId(value);
            assert!(
                derive_agent_key_current_key(
                    &DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                    &invalid
                )
                .is_err()
            );
        }
        assert!(serde_json::from_value::<AgentKeyId>(serde_json::Value::Null).is_err());
    }

    #[test]
    fn agent_key_id_is_closed() {
        for invalid in ["", "contains space", "did:web:example#"] {
            assert!(AgentKeyId::new(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(AgentKeyId::new("runtime_key-1").is_ok());
    }
}
