// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=ff3723be2839fd0ebb89296b6e3a61a209be5e24d0bbbd37b21870dd55799a39
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

/// Counterpart: `service-operation-dtos.schema.json#/$defs/RecoverySessionGrantRequest`.
/// Fresh-device existing-principal recovery issuance.
///
/// Authorization is the Bound AccountHandoff plus a matching per-request DPoP
/// proof. The Account Authority binds this request to its account/principal
/// mapping and does not consume the handoff on success, so the candidate
/// device is deliberately not required to hold an accepted-device
/// authorization yet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionGrantRequest {
    pub credential_class: SessionGrantCredentialClass,
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/AgentSessionGrantRefreshRequest`.
/// DPoP-bound Agent SessionGrant rotation.
///
/// The predecessor is presented as `Authorization: DPoP` plus a matching DPoP
/// proof; this body carries no client-generated challenge and no polymorphic
/// proof kind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantRefreshRequest {
    pub grant_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub audience_id: Option<DidCoreId>,
    pub principal_id: DidCoreId,
    pub agent_key_authorization_ref: EventId,
    pub agent_session_refresh_proof: AgentSessionRefreshProof,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/AgentSessionRefreshProof`.
/// Current Agent runtime-key proof for SessionGrant rotation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionRefreshProof {
    pub context: AgentSessionRefreshProofContext,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub signature: Base64UrlString,
}
