// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=ad33beeae92adb2bdf6ce5528d33435ba67cc5608647a5e0d5e8728902c543a7
//
// Input: schemas/agent-provision.schema.json
// sha256=4d82da00b1a80c01ca4ce46938ae687ea60b1aff59c31f9e2211e496eed6070c
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c0dd616b73cb58355247f04ec903123c52cd61b038fe2b7df35029d0b6802c1

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
