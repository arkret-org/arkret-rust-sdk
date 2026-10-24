// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=f43b1500107a166134dea8fe97289450aedc12da8db65302be386fe1d4ed2e6a
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

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
