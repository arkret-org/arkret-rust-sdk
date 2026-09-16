//! Durable governance wire records carried by operations: policy
//! documents and invite objects (`policy.schema.json` /
//! `invite.schema.json`).

use std::collections::BTreeMap;

use arkret_models_crypto::recovery_policy::RecoveryPolicy;
use arkret_wire::{
    AccountId, ActorId, GrantId, Hash, InviteId, InviteState, PolicyEffect, PolicyId, PolicyKind,
    RealmId, Result, SchemaId, WireError, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::third_party_invite::ThirdPartyInvite;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub schema: String,
    pub id: PolicyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub policy_kind: PolicyKind,
    pub rules: Vec<PolicyRule>,
    pub default_effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl Policy {
    pub const SCHEMA: &'static str = SchemaId::POLICY_V1;

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(WireError::Protocol(
                "policy schema must be ak.schema.policy.v1".to_owned(),
            ));
        }
        if self.rules.is_empty() {
            return Err(WireError::Protocol(
                "policy rules must contain at least one rule".to_owned(),
            ));
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }
}

/// Discriminator for a [`PolicyRule`] (mirrors `policy.schema.json`
/// `$defs.policy_rule.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleKind {
    Action,
    Resource,
    Server,
    Actor,
    Temporal,
    RateLimit,
    Crypto,
    Moderation,
    Extension,
}

/// Closed fields of `policy.schema.json#/$defs/policy_rule`.
/// Kind-specific presence constraints are checked by [`Self::validate`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub rule_id: String,
    pub kind: PolicyRuleKind,
    pub effect: PolicyEffect,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub priority: i64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub actions: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub resources: Option<Vec<PolicyResourceSelector>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub servers: Option<Vec<PolicyServerSelector>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub conditions: Option<arkret_wire::NonEmptyJsonObject>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub schema_ref: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub profile_ref: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub params: Option<BTreeMap<String, Value>>,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

// Missing fields default to None; an explicitly present null is not an object,
// array or string and must not silently become an omitted schema property.
fn deserialize_present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyResourceKind {
    Realm,
    Strand,
    Space,
    Object,
    Service,
}

/// Resource selector from `policy.schema.json#/$defs/policy_rule/properties/resources/items`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResourceSelector {
    pub kind: PolicyResourceKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub realm_id: Option<RealmId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub resource_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyServerKind {
    ServiceId,
    Domain,
    TrustDomain,
}

/// Federation selector from `policy.schema.json#/$defs/server_selector`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyServerSelector {
    pub kind: PolicyServerKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub service_id: Option<arkret_wire::DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub domain: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub match_subdomains: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub trust_domain: Option<arkret_identifiers::TrustDomainId>,
}

impl PolicyRule {
    /// Validate field grammars, unique nonempty selectors and kind requirements.
    pub fn validate(&self) -> Result<()> {
        use std::sync::LazyLock;
        static ACTION: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"^ak\.[a-z0-9_]+(?:\.[a-z0-9_]+)*$").unwrap());
        static RESOURCE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r"^(ak:[a-z0-9_]+:[A-Za-z0-9._~=-]+(?::[A-Za-z0-9._~=-]+)*|did:[^\s]+)$",
            )
            .unwrap()
        });
        static SCHEMA: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"^ak\.schema\.[a-z0-9_]+(?:\.[a-z0-9_]+)*\.v[0-9]+$").unwrap()
        });
        static PROFILE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"^ak\.profile\.[a-z0-9][a-z0-9_.-]*\.v[0-9]+$").unwrap()
        });
        static DOMAIN: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
            )
            .unwrap()
        });
        fn require(valid: bool, field: &str) -> Result<()> {
            if valid {
                Ok(())
            } else {
                Err(WireError::Protocol(format!("invalid policy rule {field}")))
            }
        }
        fn unique_nonempty<T: PartialEq>(values: &[T]) -> bool {
            !values.is_empty()
                && values
                    .iter()
                    .enumerate()
                    .all(|(index, value)| !values[..index].contains(value))
        }
        require(!self.rule_id.trim().is_empty(), "rule_id")?;
        if let Some(actions) = &self.actions {
            require(
                unique_nonempty(actions) && actions.iter().all(|value| ACTION.is_match(value)),
                "actions",
            )?;
        }
        if let Some(resources) = &self.resources {
            require(unique_nonempty(resources), "resources")?;
            for resource in resources {
                require(
                    resource
                        .resource_ref
                        .as_ref()
                        .is_none_or(|value| RESOURCE.is_match(value)),
                    "resource_ref",
                )?;
            }
        }
        if let Some(servers) = &self.servers {
            require(unique_nonempty(servers), "servers")?;
            for server in servers {
                require(
                    server
                        .domain
                        .as_ref()
                        .is_none_or(|value| value.len() <= 253 && DOMAIN.is_match(value)),
                    "domain",
                )?;
                require(
                    match server.kind {
                        PolicyServerKind::ServiceId => server.service_id.is_some(),
                        PolicyServerKind::Domain => server.domain.is_some(),
                        PolicyServerKind::TrustDomain => server.trust_domain.is_some(),
                    },
                    "server selector",
                )?;
            }
        }
        require(
            self.schema_ref
                .as_ref()
                .is_none_or(|value| SCHEMA.is_match(value)),
            "schema_ref",
        )?;
        require(
            self.profile_ref
                .as_ref()
                .is_none_or(|value| PROFILE.is_match(value)),
            "profile_ref",
        )?;
        require(
            match self.kind {
                PolicyRuleKind::Action => self.actions.is_some(),
                PolicyRuleKind::Resource => self.resources.is_some(),
                PolicyRuleKind::Server => self.servers.is_some(),
                PolicyRuleKind::Extension => {
                    self.params.is_some()
                        && (self.schema_ref.is_some() || self.profile_ref.is_some())
                }
                _ => true,
            },
            "kind requirements",
        )
    }
}

/// Invite object. Mirrors `invite.schema.json` (required: `id`, `schema`,
/// `realm_id`, `inviter`, `state`, `expires_at`, `created_at`).
///
/// There is deliberately no materialized join-rule snapshot: the admission
/// basis is the create Event's own authority-committed governance basis, reachable by retyping
/// the Invite id back to that Event (`governance-objects.md` §5.3). Private
/// delivery material never reaches this object either — only the
/// `introduction_evidence_digest` commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub id: InviteId,
    pub schema: String,
    pub realm_id: RealmId,
    pub inviter_account_id: AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee_account_id: Option<AccountId>,
    /// Digest of the private invite delivery `introduction_evidence`. Raw
    /// locator tokens MUST NOT appear in durable Realm events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduction_evidence_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_invite: Option<ThirdPartyInvite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<GrantId>,
    pub state: InviteState,
    /// Required by `invite.schema.json` — every invite carries a hard expiry.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// Reducer-derived actor that produced the most recent state update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Invite {
    pub const SCHEMA: &'static str = SchemaId::INVITE_V1;
}

/// The two v1 Policy document families `ak.policy.set` can carry.
///
/// `event-payload.schema.json#/$defs/policy_set_state_payload` selects the
/// family directly from `value.schema`, and an unknown family fails schema
/// validation. The dispatch below is written against that member rather than
/// left to an untagged `oneOf`: [`Policy`] carries a flattened extension map,
/// so an untagged decoder would silently absorb a recovery policy into the
/// governance branch instead of rejecting it.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum PolicySetValue {
    Governance(Box<Policy>),
    Recovery(Box<RecoveryPolicy>),
}

impl PolicySetValue {
    /// The document's own policy identity, which the enclosing payload's
    /// `policy_id` subject must equal.
    #[must_use]
    pub fn policy_id(&self) -> &PolicyId {
        match self {
            Self::Governance(policy) => &policy.id,
            Self::Recovery(policy) => &policy.policy_id,
        }
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        match self {
            Self::Governance(policy) => &policy.schema,
            Self::Recovery(policy) => &policy.schema,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Governance(policy) => policy.validate(),
            Self::Recovery(policy) => policy.validate_shape(),
        }
    }
}

impl<'de> Deserialize<'de> for PolicySetValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let schema = value
            .get("schema")
            .and_then(Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("policy value must carry a schema member"))?;
        match schema {
            SchemaId::POLICY_V1 => serde_json::from_value(value)
                .map(|policy| Self::Governance(Box::new(policy)))
                .map_err(serde::de::Error::custom),
            SchemaId::RECOVERY_POLICY_V1 => serde_json::from_value(value)
                .map(|policy| Self::Recovery(Box::new(policy)))
                .map_err(serde::de::Error::custom),
            other => Err(serde::de::Error::custom(format!(
                "policy value schema {other} is not a registered v1 Policy document family"
            ))),
        }
    }
}

/// Counterpart for
/// `event-payload.schema.json#/$defs/policy_set_state_payload`.
///
/// `policy_id` is the stable subject of the Policy typed current result, so
/// repeated `ak.policy.set` Events under the same `policy_id` converge on one
/// document rather than accumulating versions. There is no cell head, basis or
/// version member on the wire: concurrency is resolved by the typed current
/// result's `expected_revision` precondition.
// Field declaration order is byte-for-byte the properties order of
// event-payload.schema.json#/$defs/policy_set_state_payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySetStatePayload {
    pub policy_id: PolicyId,
    pub value: PolicySetValue,
}

impl PolicySetStatePayload {
    /// The payload subject and the document it carries are the same policy, so
    /// a payload that files one document under another subject is refused
    /// before it is authored.
    pub fn validate(&self) -> Result<()> {
        if self.policy_id != *self.value.policy_id() {
            return Err(WireError::Protocol(
                "policy set payload policy_id must equal the carried document policy id".to_owned(),
            ));
        }
        self.value.validate()
    }
}

#[cfg(test)]
mod policy_set_state_tests {
    use serde_json::json;

    use super::*;

    const POLICY: &str = "ak:policy:0198ff00-0000-7000-8000-000000000001";
    const OTHER_POLICY: &str = "ak:policy:0198ff00-0000-7000-8000-000000000002";

    fn governance_value() -> Value {
        json!({
            "policy_id": POLICY,
            "value": {
                "schema": "ak.schema.policy.v1",
                "id": POLICY,
                "policy_kind": "access",
                "rules": [{
                    "rule_id": "allow_members",
                    "kind": "action",
                    "effect": "allow",
                    "actions": ["ak.message.create"]
                }],
                "default_effect": "deny",
                "created_by": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkowner",
                        "station_id": "ak:did_core:web:station.example"
                    }
                },
                "created_at": "2026-09-16T00:00:00.000Z"
            }
        })
    }

    fn recovery_value() -> Value {
        json!({
            "policy_id": POLICY,
            "value": {
                "schema": "ak.schema.recovery_policy.v1",
                "policy_id": POLICY,
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkholder",
                    "station_id": "ak:did_core:web:station.example"
                },
                "version": 1,
                "supersedes_id": null,
                "trust_domain": "ak:trust_domain:station.example",
                "issued_at": "2026-09-16T00:00:00.000Z",
                "auth_data": {
                    "verification_method": "did:web:station.example#key-1",
                    "signature_algorithm": "Ed25519",
                    "signature": "c2lnbmF0dXJl"
                },
                "methods": []
            }
        })
    }

    #[test]
    fn the_governance_family_round_trips() {
        let payload: PolicySetStatePayload = serde_json::from_value(governance_value()).unwrap();
        assert!(matches!(payload.value, PolicySetValue::Governance(_)));
        assert_eq!(payload.value.schema(), SchemaId::POLICY_V1);
        payload.validate().unwrap();
        assert_eq!(serde_json::to_value(&payload).unwrap(), governance_value());
    }

    #[test]
    fn the_recovery_family_round_trips() {
        let payload: PolicySetStatePayload = serde_json::from_value(recovery_value()).unwrap();
        assert!(matches!(payload.value, PolicySetValue::Recovery(_)));
        assert_eq!(payload.value.schema(), SchemaId::RECOVERY_POLICY_V1);
        payload.validate().unwrap();
        assert_eq!(serde_json::to_value(&payload).unwrap(), recovery_value());
    }

    #[test]
    fn a_recovery_document_never_decodes_into_the_governance_branch() {
        // `Policy` carries a flattened extension map, so this is the exact
        // case an untagged decoder would get wrong.
        let payload: PolicySetStatePayload = serde_json::from_value(recovery_value()).unwrap();
        assert!(!matches!(payload.value, PolicySetValue::Governance(_)));
    }

    #[test]
    fn an_unregistered_document_family_fails_closed() {
        let mut unknown = governance_value();
        unknown["value"]
            .as_object_mut()
            .unwrap()
            .insert("schema".to_owned(), json!("ak.schema.policy.v2"));
        assert!(serde_json::from_value::<PolicySetStatePayload>(unknown).is_err());

        let mut without_schema = governance_value();
        without_schema["value"]
            .as_object_mut()
            .unwrap()
            .remove("schema");
        assert!(serde_json::from_value::<PolicySetStatePayload>(without_schema).is_err());
    }

    #[test]
    fn the_subject_must_be_the_carried_document_id() {
        for mut mismatched in [governance_value(), recovery_value()] {
            mismatched
                .as_object_mut()
                .unwrap()
                .insert("policy_id".to_owned(), json!(OTHER_POLICY));
            let payload: PolicySetStatePayload = serde_json::from_value(mismatched).unwrap();
            assert!(payload.validate().is_err());
        }
    }

    #[test]
    fn both_members_are_required_and_no_other_is_accepted() {
        for member in ["policy_id", "value"] {
            let mut missing = governance_value();
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<PolicySetStatePayload>(missing).is_err(),
                "{member} must be required"
            );
        }
        for absent in ["expected_revision", "version", "basis"] {
            let mut extended = governance_value();
            extended
                .as_object_mut()
                .unwrap()
                .insert(absent.to_owned(), json!(1));
            assert!(
                serde_json::from_value::<PolicySetStatePayload>(extended).is_err(),
                "{absent} must not be a payload member"
            );
        }
    }

    #[test]
    fn a_governance_document_with_no_rule_is_refused() {
        let mut ruleless = governance_value();
        ruleless["value"]
            .as_object_mut()
            .unwrap()
            .insert("rules".to_owned(), json!([]));
        let payload: PolicySetStatePayload = serde_json::from_value(ruleless).unwrap();
        assert!(payload.validate().is_err());
    }

    #[test]
    fn a_recovery_document_at_version_zero_is_refused() {
        let mut zero = recovery_value();
        zero["value"]
            .as_object_mut()
            .unwrap()
            .insert("version".to_owned(), json!(0));
        let payload: PolicySetStatePayload = serde_json::from_value(zero).unwrap();
        assert!(payload.validate().is_err());
    }
}
