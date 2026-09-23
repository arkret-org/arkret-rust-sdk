//! Family-specific typed-current row-key derivations.
//!
//! These opaque digests locate registered current rows. They are not wire IDs,
//! signature inputs, revisions, governance tenure, or authorization evidence.
//! Deliberately no public API accepts an arbitrary component slice or JSON value.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{ActorId, DidCoreId, Result, WireError};

const MEMBER_STATE_DOMAIN: &str = "ak.current_key.member_state.v1";
const AGENT_STATUS_DOMAIN: &str = "ak.current_key.agent_status.v1";
const AGENT_KEY_DOMAIN: &str = "ak.current_key.agent_key.v1";

/// Closed `agent_key_id` scalar used by the Agent-key current-row derivation.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentKeyId(String);

impl AgentKeyId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_agent_key_id(&value) {
            Ok(Self(value))
        } else {
            Err(WireError::Protocol(
                "agent key id must be a DID URL or a 1..=256 character closed key token".to_owned(),
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

fn is_agent_key_id(value: &str) -> bool {
    if let Some((did, fragment)) = value.split_once('#') {
        return !fragment.is_empty()
            && !fragment.chars().any(char::is_whitespace)
            && !did.chars().any(char::is_whitespace)
            && did.starts_with("did:")
            && did[4..]
                .split_once(':')
                .is_some_and(|(method, method_specific)| {
                    !method.is_empty()
                        && method
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                        && !method_specific.is_empty()
                })
            && !fragment.contains('#');
    }
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
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

/// Derive the opaque current-row locator for one `(agent_id, key_id)` pair.
pub fn derive_agent_key_current_key(agent_id: &DidCoreId, key_id: &AgentKeyId) -> Result<String> {
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
    fn agent_key_id_is_closed() {
        for invalid in ["", "contains space", "did:web:example#"] {
            assert!(AgentKeyId::new(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(AgentKeyId::new("runtime_key-1").is_ok());
    }
}
