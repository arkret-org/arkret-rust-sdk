// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=82c5f11f9fa36d98b43744ed61b4e37de0a13f8ea468b80f5d05fdeb5ffd6876
//
// Input: schemas/agent-requested-scope-disclosure.schema.json
// sha256=d463d06dcb5b56f44e628a8acb13a156e83d830d2899552f608e59230d4f6c3f
//
// Input: schemas/common-ids.schema.json
// sha256=81b18acd21f4382860d5cab2384d9bb78ee5dbc23629752a6cc74ce384186149
//
// Bindings: tools/closed-model-bindings.json
// sha256=3bfe22afd0deee9b00a0fd4b2c1e2c7eee318ee6752681d944e4cc4b38492100

/// Counterpart: `service-operation-dtos.schema.json#/$defs/AgentSessionGrantRequestBody`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantRequestBody {
    pub principal_id: DidCoreId,
    pub requested_scope: Vec<String>,
    pub agent_key_authorization_ref: EventId,
    pub agent_scope_request: RequestedAgentSessionGrantScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub approval_evidence_refs: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    pub proof: AgentSessionGrantProof,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/HumanSessionGrantRequestBody`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSessionGrantRequestBody {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
    pub accepted_device_possession_proof: AcceptedDeviceIssuePossessionProof,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/HumanSessionGrantRefreshRequestBody`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSessionGrantRefreshRequestBody {
    pub session_grant: SessionGrantSecret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub audience_id: Option<DidCoreId>,
    pub device_id: DeviceId,
    pub accepted_device_possession_proof: AcceptedDeviceRefreshPossessionProof,
}

/// Counterpart:
/// `service-operation-dtos.schema.json#/$defs/AgentSessionGrantRequestBody/properties/proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantProof {
    pub proof_kind: AgentSessionGrantProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub signature: String,
}
