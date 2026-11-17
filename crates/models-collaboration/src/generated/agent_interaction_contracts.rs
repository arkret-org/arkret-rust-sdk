// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e82aa2728d1f60c88a7493e0ec3093f76e625428156e83978a5e8e4b14614034
//
// Input: schemas/common-ids.schema.json
// sha256=81b18acd21f4382860d5cab2384d9bb78ee5dbc23629752a6cc74ce384186149
//
// Input: schemas/current-state.schema.json
// sha256=72b3aa5374e048b1fd8bf165fcb91f6bc06d12d8d6542d44d2845089bd3a5e7c
//
// Bindings: tools/closed-model-bindings.json
// sha256=6f2298d507cfeaf587b0a77d565af971535b7d029bf667f2e4b743448bcc016f

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
    pub expected_commit_id: Option<RealmCommitId>,
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
