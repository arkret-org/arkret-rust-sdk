// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=57acbc5881e4ce66c0742968ae383fe5bda77fe0461abc395560e10fcdca637a
//
// Bindings: tools/closed-model-bindings.json
// sha256=3d8286ffa86f9dd01d3c540d77924093bfc6e9642d4effb361307f36e3ffd625

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
