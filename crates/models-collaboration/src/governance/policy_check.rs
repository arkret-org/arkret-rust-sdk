//! Policy-check request and response bindings.

use std::collections::BTreeMap;

use arkret_wire::{
    AuthzDecision, DeviceId, DidCoreId, FreshnessState, Hash, RealmId, ReasonCode, Result,
    TypedTrustDomainId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Trust domain plumbing ───────────────────────────────────────────────

/// Round 4 — compute the canonical `audit_policy_version_digest` 4-tuple
/// digest. Wire-breaking: the pre-round-4 2-arg signature
/// `(audit_disclosure, audit_assurance)` is deleted. Receipts issued
/// against the old hash MUST be rejected.
///
/// Canonical JSON over the object:
/// ```text
/// { "realm_id": <realm_id>,
///   "trust_domain": <trust_domain>,
///   "audit_disclosure": <audit_disclosure>,
///   "audit_assurance": <audit_assurance> }
/// ```
/// hashed with SHA-256 per RFC 8785 JCS.
pub fn compute_audit_policy_version_digest(
    realm_id: &RealmId,
    trust_domain: &TypedTrustDomainId,
    audit_disclosure: &Value,
    audit_assurance: &Value,
) -> Result<[u8; 32]> {
    let canonical_bytes = canonical::canonical_json_bytes(&serde_json::json!({
        "realm_id": realm_id.as_str(),
        "trust_domain": trust_domain.as_str(),
        "audit_disclosure": audit_disclosure,
        "audit_assurance": audit_assurance,
    }))?;
    Ok(canonical::sha256_bytes(&canonical_bytes))
}

// ── PolicyCheck v2 ──────────────────────────────────────────────────────

/// Round 4 — `source` discriminator for [`PolicyCheckRequestBody`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckSource {
    pub service_id: DidCoreId,
    pub service_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip_digest: Option<Hash>,
    pub signed_transport: bool,
}

/// Round 4 (commit 7446832) — typed `/policy/check` request body.
///
/// Wire-breaking: replaces the pre-round-4 `PolicyCheckRequestBody`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckRequestBody {
    pub request_id: String,
    pub realm_id: RealmId,
    pub actor_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub action: String,
    pub request_canonical_digest: Hash,
    pub source: PolicyCheckSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_preview: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<BTreeMap<String, Value>>,
}

/// Round 4 — `bound_to` binding inside [`PolicyCheckOutcome`].
///
/// MUST include all five fields so the response can be verified against
/// the request transcript without trusting the policy server.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckBoundTo {
    pub realm_id: RealmId,
    pub actor_id: DidCoreId,
    pub action: String,
    pub request_canonical_digest: Hash,
    pub policy_server_id: DidCoreId,
}

/// Round 4 — signature carrier for [`PolicyCheckOutcome`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckSignature {
    /// DID URL verification method, MUST match
    /// `^did:[a-z0-9]+:[^\s]+#.+$`.
    pub kid: String,
    pub sig: String,
}

/// Round 4 (commit 7446832) — `/policy/check` response with full
/// binding transcript.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckOutcome {
    pub request_id: String,
    pub decision: AuthzDecision,
    pub bound_to: PolicyCheckBoundTo,
    pub reason_code: ReasonCode,
    pub freshness_state: FreshnessState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub auth_state_digest: Hash,
    pub policy_frontier_digest: Hash,
    pub membership_frontier_digest: Hash,
    pub signature: PolicyCheckSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub next_retry_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Value>,
}

#[derive(Serialize)]
struct PolicyDecisionTranscript<'a> {
    kind: &'static str,
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
        kind: "ak.policy.check.transcript.v1",
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
