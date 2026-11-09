// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=c1b7f6c9f9f4ceb88c4b7c2924da91d09b11c7dd9ef63fe1e1097a133c1d6fe0
//
// Input: schemas/current-state.schema.json
// sha256=12c6338f4680c74863df4fb44a782ce08bf15a489ee12c019864141f0f6962f2
//
// Bindings: tools/closed-model-bindings.json
// sha256=586dcc2160f190a9fbbcb1f5857251190e1fa6d65f55d7ab65cdec8105d1c8ef

/// Counterpart: `event-payload.schema.json#/$defs/agent_interaction_set_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_interaction_set_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionSetPayload {
    pub agent_account_id: AccountId,
    pub controller_account_id: AccountId,
    pub interaction_mode: AgentInteractionMode,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub expected_revision: Option<CurrentRevision>,
}

/// Counterpart: `current-state.schema.json#/$defs/agent_interaction_value`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/current-state.schema.json#/$defs/agent_interaction_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionCurrentValue {
    pub controller_account_id: AccountId,
    pub interaction_mode: AgentInteractionMode,
}

/// Counterpart: `current-state.schema.json#/$defs/current_agent_interaction/properties/selector`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/current-state.schema.json#/$defs/current_agent_interaction/
/// properties/selector`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionExactCurrentSelector {
    pub kind: AgentInteractionSelectorKind,
    pub agent_account_id: AccountId,
}

/// Counterpart: `current-state.schema.json#/$defs/current_agent_interaction`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/current-state.schema.json#/$defs/current_agent_interaction`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentAgentInteraction {
    pub selector: AgentInteractionExactCurrentSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: AgentInteractionCurrentValue,
}
