// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=8cab7974d8b7e149d6140a0f5b999ae7b95908d5b46f034cb36ce6580ba737cf
//
// Input: schemas/agent-provision.schema.json
// sha256=9fd05ffd6b0ea5ee7437f17c2883c0d1811fe7e77e1cfc46c3405c63b4788e27
//
// Bindings: tools/closed-model-bindings.json
// sha256=db527b364017054646ca12898f9051885245c63852c0c52b9960a568cc897f0f

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
