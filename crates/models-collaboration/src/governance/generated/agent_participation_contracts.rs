// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/agent-operations.schema.json
// sha256=80fba7d397f1c4d067304c83b87dcdacee8db4585991eda985aceb0272890fa1
//
// Bindings: tools/closed-model-bindings.json
// sha256=14d7f312a6557af02e4e1a8496c76be3e3c902a74c9d7d175190d30caaf07567

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
    pub agent_id: arkret_wire::DidCoreId,
    pub participation_entries: Vec<AgentParticipationView>,
}
