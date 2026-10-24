// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=15fedd4b4e4462c678d93ac6521a5dfd0372854cd62cd76ec5e777fd88857ae5
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

/// Counterpart: `agent-operations.schema.json#/$defs/agent_participation_response_body`.
/// Response for `ak.self.agent.participation.{set,get}`.
///
/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/
/// agent_participation_response_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentParticipationResponseBody {
    pub agent_id: String,
    #[serde(rename = "participation_entries")]
    pub agent_participation_entries: Vec<AgentParticipationEntry>,
}
