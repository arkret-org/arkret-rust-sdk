// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/policy.schema.json
// sha256=f31a32e76dd6026205c48226af03e5b860c147c87335da0ff60ea481c9755729
//
// Input: schemas/common-ids.schema.json
// sha256=dadc47194ca411baa38f3a7f44ae8115bec7cbcd98e68a2fffd389fdfc039713
//
// Input: schemas/event-payload.schema.json
// sha256=961bb4df946585c3ad9cafbdcd82d199c69fb519262229d82943cca11d1641ca
//
// Bindings: tools/closed-model-bindings.json
// sha256=a78e63d1f3a48c87115a3e40e578dc4aeb5f619833613e5eb9fae1be319bff29

/// Counterpart: `policy.schema.json#/$defs/policy_rule/properties/resources/items`.
/// Resource selector from `policy.schema.json#/$defs/policy_rule/properties/resources/items`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResourceSelector {
    pub kind: PolicyResourceKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub realm_id: Option<RealmId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub resource_ref: Option<String>,
}

/// Counterpart: `policy.schema.json#/$defs/policy_rule`.
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
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub actions: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub resources: Option<Vec<PolicyResourceSelector>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub servers: Option<Vec<PolicyServerSelector>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub conditions: Option<arkret_wire::NonEmptyJsonObject>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub schema_ref: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub profile_ref: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub parameters: Option<BTreeMap<String, Value>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub agent_target: Option<AgentPolicyTarget>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub agent_operations: Option<Vec<AgentPolicyOperation>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub applet_target: Option<AppletPolicyTarget>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub applet_operations: Option<Vec<AppletPolicyOperation>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub review_requirement: Option<ManagementReviewRequirement>,
}

/// Counterpart: `policy.schema.json#/$defs/server_selector`.
/// Federation selector from `policy.schema.json#/$defs/server_selector`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyServerSelector {
    pub kind: PolicyServerKind,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub service_id: Option<arkret_wire::DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub domain: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub match_subdomains: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub trust_domain: Option<arkret_identifiers::TrustDomainId>,
}

/// Counterpart: `event-payload.schema.json#/$defs/policy_set_state_payload`.
/// Counterpart for
/// `event-payload.schema.json#/$defs/policy_set_state_payload`.
///
/// `policy_id` is the stable subject of the Policy current state, so
/// repeated `ak.policy.set` Events under the same `policy_id` converge on one
/// document rather than accumulating versions. There is no cell head, basis or
/// version member on the wire. Agent and Applet governance policies carry a required
/// nullable `expected_commit_id` precondition; other policy families omit it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySetStatePayload {
    pub policy_id: PolicyId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_value_preserving_null"
    )]
    pub expected_commit_id: Option<Option<RealmCommitId>>,
    pub value: PolicySetValue,
}
