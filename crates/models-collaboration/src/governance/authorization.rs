//! Authorization decision, grant listing, and invite listing wire DTOs.

use std::collections::BTreeMap;

use arkret_wire::{AuthzDecision, Did, FreshnessState, Hash, NotaryStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::governance::grant_constraint::CapabilityGrant;
use crate::governance::operation_wire::Invite;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AuthzCheckRequestBody {
    pub actor_id: Did,
    pub action: String,
    /// Optional resource selector (Realm / Strand / Space / Morph / etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<BTreeMap<String, Value>>,
    /// Optional decision context — claim presentations, frontier reference,
    /// request metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AuthzCheckOutcome {
    pub decision: AuthzDecision,
    #[serde(default)]
    pub matched_grants: Vec<Value>,
    #[serde(default)]
    pub applied_constraints: Vec<Value>,
    #[serde(default)]
    pub policy_results: Vec<Value>,
    #[serde(default)]
    pub missing_proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness_state: Option<FreshnessState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_frontier_age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notary_status: Option<NotaryStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub cache_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default)]
    pub obligations: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct GrantList {
    #[serde(default)]
    pub grants: Vec<CapabilityGrant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<Hash>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AuthzInviteList {
    #[serde(default)]
    pub invites: Vec<Invite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}
