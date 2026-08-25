//! Policy-check request and response bindings.

use std::collections::BTreeMap;

use arkret_wire::{
    AuthzDecision, DeviceId, DidCoreId, FreshnessState, Hash, RealmId, ReasonCode, Result,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── PolicyCheck ─────────────────────────────────────────────────────────

/// `source` discriminator for [`PolicyCheckRequestBody`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckSource {
    pub service_id: DidCoreId,
    pub service_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip_digest: Option<Hash>,
    pub signed_transport: bool,
}

/// Typed `/policy/check` request body.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckRequestBody {
    pub request_id: String,
    pub realm_id: RealmId,
    pub request_canonical_digest: Hash,
    pub action: String,
    pub actor_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub source: PolicyCheckSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_preview: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<BTreeMap<String, Value>>,
}

/// `bound_to` binding inside [`PolicyCheckOutcome`].
///
/// MUST include all five fields so the response can be verified against
/// the request transcript without trusting the policy server.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckBoundTo {
    pub realm_id: RealmId,
    pub actor_id: DidCoreId,
    pub action: String,
    pub request_canonical_digest: Hash,
    pub policy_server_id: DidCoreId,
}

/// Signature carrier for [`PolicyCheckOutcome`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckSignature {
    /// DID URL verification method, MUST match
    /// `^did:[a-z0-9]+:[^\s]+#.+$`.
    pub kid: String,
    pub sig: String,
}

/// `/policy/check` response with full binding transcript.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckOutcome {
    pub request_id: String,
    pub bound_to: PolicyCheckBoundTo,
    pub decision: AuthzDecision,
    pub reason_code: ReasonCode,
    pub freshness_state: FreshnessState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub auth_state_digest: Hash,
    pub policy_frontier_digest: Hash,
    pub membership_frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub next_retry_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Value>,
    pub signature: PolicyCheckSignature,
}

#[derive(Serialize)]
struct PolicyDecisionTranscript<'a> {
    domain: &'static str,
    request_id: &'a str,
    decision: &'a AuthzDecision,
    bound_to: &'a PolicyCheckBoundTo,
    freshness_state: &'a FreshnessState,
    auth_state_digest: &'a Hash,
    policy_frontier_digest: &'a Hash,
    membership_frontier_digest: &'a Hash,
    reason_code: &'a str,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_retry_at: Option<String>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    obligations: &'a [Value],
}

/// Canonical v1 transcript signed by policy issuers and rebuilt by verifiers.
pub fn policy_decision_transcript_bytes(outcome: &PolicyCheckOutcome) -> Result<Vec<u8>> {
    let transcript = PolicyDecisionTranscript {
        domain: arkret_wire::DomainSeparationId::POLICY_CHECK_TRANSCRIPT_V1,
        request_id: &outcome.request_id,
        decision: &outcome.decision,
        bound_to: &outcome.bound_to,
        freshness_state: &outcome.freshness_state,
        auth_state_digest: &outcome.auth_state_digest,
        policy_frontier_digest: &outcome.policy_frontier_digest,
        membership_frontier_digest: &outcome.membership_frontier_digest,
        reason_code: outcome.reason_code.as_str(),
        expires_at: arkret_canonical::format_timestamp_canonical(outcome.expires_at),
        next_retry_at: outcome
            .next_retry_at
            .map(arkret_canonical::format_timestamp_canonical),
        obligations: &outcome.obligations,
    };
    Ok(canonical::canonical_json_bytes(&transcript)?)
}
