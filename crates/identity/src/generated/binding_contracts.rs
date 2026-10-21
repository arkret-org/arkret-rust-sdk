// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/did-binding-contracts.schema.json
// sha256=ebb5bf702cab4bfb1c8fc1a0b843a48021723633d08116cef2b33bc1f54449fa
//
// Bindings: tools/closed-model-bindings.json
// sha256=d27aff562a6c1628ec46d4e850170d384869963a898494b561139f314ad91286

/// Counterpart: `did-binding-contracts.schema.json#/$defs/limited_trust`.
/// Per-pin limited-trust record
/// (`did-binding-contracts.schema.json#/$defs/limited_trust`).
///
/// §5.5 replaced the old single "reason" with one state per pin, because the two
/// pins fail independently and for different reasons: a `did:webvh` binding that
/// lost only `version_id` because the resolver did not surface it is a resolver
/// defect, while a `did:key` binding that has no history at all is a terminal
/// property of the method. Collapsing both into one enum made those
/// indistinguishable.
///
/// The record is omitted entirely when both pins are present; every state MUST
/// agree with the actual presence of its pin, and [`VerifiedDidBinding::new`]
/// rejects a binding where it does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitedTrust {
    pub history_head_status: PinState,
    pub version_id_status: PinState,
}

/// Counterpart: `did-binding-contracts.schema.json#/$defs/freshness_profile`.
/// One registered freshness profile row
/// (`did-binding-contracts.schema.json#/$defs/freshness_profile`).
///
/// §5.4 makes every DID authority call site reference exactly one profile id
/// through its operation / action registration — natural-language tier guessing
/// ("directory-ish, so any cache will do") is forbidden, and an unknown id is
/// treated as `high`, never as "anything cached is fine".
///
/// `fresh_for_seconds` is the **single** freshness threshold: `refresh_after =
/// verified_at + fresh_for_seconds` and an authority call's `max_age` is the
/// same value. Two separately maintained constants are exactly the drift §5.4
/// forbids, so [`Self::requirement`] is the only way to obtain a
/// [`FreshnessRequirement`] from a profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessProfile {
    pub freshness_profile_id: String,
    pub risk_tier: DidFreshnessRiskTier,
    pub did_method_selector: Vec<String>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub fresh_for_seconds: Option<u64>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub stale_grace_seconds: Option<u64>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub hard_expiry_seconds: Option<u64>,
    pub stale_behavior: StaleBehavior,
}
