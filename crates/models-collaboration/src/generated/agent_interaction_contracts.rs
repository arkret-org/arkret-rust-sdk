// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=db43f4934d4601ea90be4c1dd25628271e264c7fd7058283c6b765e30217463c
//
// Input: schemas/typed-current-result.schema.json
// sha256=bfee8c04c7b3d9e76727652feaa2e49488bb443f0bb99670a13dd07f2be02fe3
//
// Bindings: tools/closed-model-bindings.json
// sha256=ee958bb963f35540b3d330cc3731d78e388ab09c402e48014a9739bbca5c1c40

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

/// Counterpart: `typed-current-result.schema.json#/$defs/agent_interaction_value`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/typed-current-result.schema.json#/$defs/agent_interaction_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionCurrentValue {
    pub controller_account_id: AccountId,
    pub interaction_mode: AgentInteractionMode,
}

/// Counterpart:
/// `typed-current-result.schema.json#/$defs/agent_interaction_result/properties/selector`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/typed-current-result.schema.json#/$defs/agent_interaction_result/
/// properties/selector`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionExactCurrentSelector {
    pub kind: AgentInteractionSelectorKind,
    pub agent_account_id: AccountId,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/agent_interaction_result`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/typed-current-result.schema.json#/$defs/agent_interaction_result`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionExactCurrentRow {
    pub selector: AgentInteractionExactCurrentSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: AgentInteractionCurrentValue,
}
