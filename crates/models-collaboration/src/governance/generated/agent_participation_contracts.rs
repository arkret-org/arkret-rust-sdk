// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=0d2950977b4b8d7c76137b107fd4dbf11401b0b1e5b480ba6ce34d31b82ad5aa
//
// Bindings: tools/closed-model-bindings.json
// sha256=a815d160b11bd278cacb26a2d096a99bf7042e5f84772a439fcda2a7f9dedf7c

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
