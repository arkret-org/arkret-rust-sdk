// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=feba0ff19e227c276a3792aaed506b6534bf9ff8ce6c2e91a0ab36c04777785f
//
// Input: schemas/agent-provision.schema.json
// sha256=32904862ed391edbb9ccbe4d29eedb1afb0edd8bbfd1ebb6fd4e70b24332cc53
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

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
