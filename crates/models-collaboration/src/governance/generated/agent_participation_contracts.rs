// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=9aa8e4ac8e3674122e0db9ede934930c6a5b515932794fb4e352562d8ba1cf26
//
// Bindings: tools/closed-model-bindings.json
// sha256=5c71516a86f6e77bf88bd907edc9f7002dddfcc4a5457d0ba636150543e5b28e

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
    pub agent_id: DidCoreId,
    pub participation_entries: Vec<AgentParticipationView>,
}
