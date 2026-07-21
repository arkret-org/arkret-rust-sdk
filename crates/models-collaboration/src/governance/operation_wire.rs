//! Durable governance wire records carried by operations: policy
//! documents and invite objects (`policy.schema.json` /
//! `invite.schema.json`).

use std::collections::BTreeMap;

use arkret_wire::{
    Did, Error, GrantId, Hash, InviteId, InviteState, PolicyEffect, PolicyId, PolicyType, RealmId,
    Result, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::invite_addressing::InviteDeliveryTarget;
use crate::governance::third_party_invite::ThirdPartyInvite;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct Policy {
    pub schema: String,
    pub id: PolicyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub policy_type: PolicyType,
    pub rules: Vec<PolicyRule>,
    pub default_effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Discriminator for a [`PolicyRule`] (mirrors `policy.schema.json`
/// `$defs.policy_rule.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct PolicyRule {
    pub rule_id: String,
    pub kind: PolicyRuleKind,
    pub effect: PolicyEffect,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: XExtensionMap,
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
            PolicyRuleKind::RateLimit => require("rate_limit"),
            PolicyRuleKind::Temporal => require("temporal"),
            // server / actor / crypto / moderation / extension have no
            // additional unconditional required field beyond the base triple.
            _ => Ok(()),
        }
    }
}

/// Invite object. Mirrors `invite.schema.json` (required: `id`, `schema`,
/// `realm_id`, `inviter`, `join_rule_snapshot`, `state`, `expires_at`,
/// `created_at`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct Invite {
    pub id: InviteId,
    pub schema: String,
    pub realm_id: RealmId,
    pub inviter: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee: Option<Did>,
    /// Public durable target for private invite delivery (required by the
    /// schema `allOf` when `invitee` is set without `third_party_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_delivery_target: Option<InviteDeliveryTarget>,
    /// Digest of the private invite delivery `introduction_evidence`. Raw
    /// locator tokens MUST NOT appear in durable Realm events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduction_evidence_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_id: Option<ThirdPartyInvite>,
    pub join_rule_snapshot: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<GrantId>,
    pub state: InviteState,
    /// Required by `invite.schema.json` — every invite carries a hard expiry.
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    /// Reducer-derived actor that produced the most recent state update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}
