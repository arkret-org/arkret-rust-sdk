// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=32238f873daa77303a2e6cc8484e057a69a03e6735d7562183346041a6bfdcaf
//
// Input: schemas/agent-requested-scope-disclosure.schema.json
// sha256=0f1d7f670bdbaab69f35732b248d1d5f01d004f11c50e9feeb0cbc726af06b57
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Bindings: tools/closed-model-bindings.json
// sha256=6fcfadb0c7e06a31e4528be5ebd9b087cda5b2394c144df9292de9b946c7d7a8

/// Counterpart: `service-operation-dtos.schema.json#/$defs/AgentSessionGrantRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantRequest {
    pub principal_id: DidCoreId,
    pub requested_scope: Vec<String>,
    pub agent_key_authorization_ref: EventId,
    pub agent_scope_request: SessionGrantAgentScopeRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub approval_evidence_refs: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    pub proof: AgentSessionGrantProof,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/HumanSessionGrantRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSessionGrantRequest {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
    pub accepted_device_possession_proof: AcceptedDeviceIssuePossessionProof,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/HumanSessionGrantRefreshRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSessionGrantRefreshRequest {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub audience_id: Option<DidCoreId>,
    pub device_id: DeviceId,
    pub accepted_device_possession_proof: AcceptedDeviceRefreshPossessionProof,
}

/// Counterpart:
/// `service-operation-dtos.schema.json#/$defs/AgentSessionGrantRequest/properties/proof`.
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
