//! Durable governance wire records carried by operations: policy
//! documents and invite objects (`policy.schema.json` /
//! `invite.schema.json`).

use std::collections::BTreeMap;

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
        require(
            crate::events_payloads::state::PolicyRuleId::new(self.rule_id.clone()).is_ok(),
            "rule_id",
        )?;
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
/// basis is the create Event's own CBS governance basis, reachable by retyping
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
