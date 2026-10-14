// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/policy.schema.json
// sha256=b6d399554a12c940bc78470ac0954c08e051caaf735625e065dddae01320354a
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/typed-current-result.schema.json
// sha256=fec530d3711c83b9a3bf0c4bc9bb5bee2c350c552440b12a98c5e723f7740529
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

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
    pub params: Option<BTreeMap<String, Value>>,
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
/// `policy_id` is the stable subject of the Policy typed current result, so
/// repeated `ak.policy.set` Events under the same `policy_id` converge on one
/// document rather than accumulating versions. There is no cell head, basis or
/// version member on the wire. Agent and Applet governance policies carry a required
/// nullable `expected_revision` precondition; other policy families omit it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySetStatePayload {
    pub policy_id: PolicyId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub expected_revision: Option<Option<CurrentRevision>>,
    pub value: PolicySetValue,
}
