//! Durable governance wire records carried by operations: policy
//! documents and invite objects (`policy.schema.json` /
//! `invite.schema.json`).

use std::collections::BTreeMap;

use arkret_wire::{
    DidCoreId, Error, GrantId, Hash, InviteId, InviteState, PolicyEffect, PolicyId, PolicyKind,
    RealmId, Result, SchemaId, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::invite_addressing::InviteDeliveryTarget;
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
    pub created_by: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<DidCoreId>,
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
            return Err(Error::Protocol(
                "policy schema must be ak.schema.policy.v1".to_owned(),
            ));
        }
        if self.rules.is_empty() {
            return Err(Error::Protocol(
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

/// A single typed policy rule (mirrors `policy.schema.json`
/// `$defs.policy_rule`). `rule_id` / `kind` / `effect` are required; the
/// kind-specific fields (e.g. `actions` for `kind=action`) ride in `extra`
/// and are validated by [`PolicyRule::validate`]. This replaces the former
/// untyped `Vec<Value>` so callers can no longer build a rule that is
/// missing its required discriminators without the SDK noticing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub kind: PolicyRuleKind,
    pub effect: PolicyEffect,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub priority: i64,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

impl PolicyRule {
    /// Validate the kind-conditional required fields that
    /// `policy.schema.json` enforces (e.g. `kind=action` MUST carry a
    /// non-empty `actions` array). Returns `Err(Error::Protocol(...))` on
    /// violation.
    pub fn validate(&self) -> Result<()> {
        if self.rule_id.trim().is_empty() {
            return Err(Error::Protocol(
                "policy rule rule_id must not be empty".to_owned(),
            ));
        }
        const DECLARED_FIELDS: &[&str] = &[
            "actions",
            "resources",
            "servers",
            "conditions",
            "schema_ref",
            "profile_ref",
            "params",
        ];
        if self
            .extra
            .keys()
            .any(|field| !DECLARED_FIELDS.contains(&field.as_str()))
        {
            return Err(Error::Protocol(
                "policy rule contains a field outside the closed schema".to_owned(),
            ));
        }
        let require = |field: &str| -> Result<()> {
            match self.extra.get(field) {
                Some(Value::Array(items)) if !items.is_empty() => Ok(()),
                Some(value) if !value.is_null() => Ok(()),
                _ => Err(Error::Protocol(format!(
                    "policy rule kind={:?} requires field '{field}'",
                    self.kind
                ))),
            }
        };
        match self.kind {
            PolicyRuleKind::Action => require("actions"),
            PolicyRuleKind::Resource => require("resources"),
            PolicyRuleKind::Server => require("servers"),
            PolicyRuleKind::Extension => {
                require("params")?;
                if !self.extra.contains_key("schema_ref") && !self.extra.contains_key("profile_ref")
                {
                    return Err(Error::Protocol(
                        "policy extension rule requires schema_ref or profile_ref".to_owned(),
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Invite object. Mirrors `invite.schema.json` (required: `id`, `schema`,
/// `realm_id`, `inviter`, `state`, `expires_at`, `created_at`).
///
/// There is deliberately no materialized join-rule snapshot: the admission
/// basis is the create Event's own CBA governance basis, reachable by retyping
/// the Invite id back to that Event (`governance-objects.md` §5.3). Private
/// delivery material never reaches this object either — only
/// `introduction_evidence_digest` and `invite_delivery_target`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub id: InviteId,
    pub schema: String,
    pub realm_id: RealmId,
    pub inviter: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee: Option<DidCoreId>,
    /// Public durable target for private invite delivery (required by the
    /// schema `allOf` when `invitee` is set without `third_party_invite`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_delivery_target: Option<InviteDeliveryTarget>,
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
    pub updated_by: Option<DidCoreId>,
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
