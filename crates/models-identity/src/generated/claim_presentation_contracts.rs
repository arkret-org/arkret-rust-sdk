// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=b9b2fcecf87470a1def1e55bf536bdb637b04f0e6f42083d5ed9962a80b14c61
//
// Input: schemas/agent-provision.schema.json
// sha256=9fd05ffd6b0ea5ee7437f17c2883c0d1811fe7e77e1cfc46c3405c63b4788e27
//
// Bindings: tools/closed-model-bindings.json
// sha256=113d054c1defb3940cb07e0f04bb10848b9d375692c24056c947cb624743840a

/// Counterpart: `current-state.schema.json#/$defs/agent_selector_claim_value`.
/// Value of the `agent_selector_claim` current state
/// (`current-state.schema.json#/$defs/agent_selector_claim_value`).
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
