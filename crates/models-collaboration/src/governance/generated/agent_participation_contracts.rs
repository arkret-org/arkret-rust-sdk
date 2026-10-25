// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=57acbc5881e4ce66c0742968ae383fe5bda77fe0461abc395560e10fcdca637a
//
// Bindings: tools/closed-model-bindings.json
// sha256=107c58e1dbd8a2701005c9cd1dc573b3c5e861cc4f3c68403bae0ff3d579bd03

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
    pub participation_entries: Vec<AgentParticipationView>,
}
