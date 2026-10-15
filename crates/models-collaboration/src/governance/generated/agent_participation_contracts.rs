// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=36e5a56549700189157622d316488eb920a2f2aba8e368caedfc14b91dd8be5c
//
// Bindings: tools/closed-model-bindings.json
// sha256=e2e41b9d9b5da297b85bcf0625d64744849f300d860c9e74d0c6d3be8869a6aa

/// Counterpart: `agent-operations.schema.json#/$defs/agent_participation_outcome`.
/// Response for `ak.self.agent.participation.{set,get}`.
///
/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/agent_participation_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentParticipationOutcome {
    pub agent_id: String,
    #[serde(rename = "participation_entries")]
    pub agent_participation_entries: Vec<AgentParticipationEntry>,
}
