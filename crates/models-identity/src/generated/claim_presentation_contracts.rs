// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=fe2f5aa29f51e9d6243e74433c0ee027e4d15f04b8e01c3354a423f069b285a5
//
// Input: schemas/agent-provision.schema.json
// sha256=4d82da00b1a80c01ca4ce46938ae687ea60b1aff59c31f9e2211e496eed6070c
//
// Bindings: tools/closed-model-bindings.json
// sha256=6fcfadb0c7e06a31e4528be5ebd9b087cda5b2394c144df9292de9b946c7d7a8

/// Counterpart: `typed-current-result.schema.json#/$defs/agent_selector_claim_value`.
/// Value of the `agent_selector_claim` typed current result
/// (`typed-current-result.schema.json#/$defs/agent_selector_claim_value`).
///
/// The selector is `(controller principal, agent_slug)`; the only writer is
/// the selector projection of the accepted `ak.agent.provision`. The value is
/// read only to verify a picker label against an Agent AccountId the client
/// already obtained from an authorized source; it never selects a target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSelectorClaimValue {
    pub subject_account_id: AccountId,
    pub visibility: HandleVisibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub audience: Option<String>,
}
