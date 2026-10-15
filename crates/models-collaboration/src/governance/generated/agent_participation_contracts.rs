// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=0d2950977b4b8d7c76137b107fd4dbf11401b0b1e5b480ba6ce34d31b82ad5aa
//
// Bindings: tools/closed-model-bindings.json
// sha256=08dd3be10645b0c4e133fe72a1a0f80596e47ca0c707a290dcd23d1116f56607

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
