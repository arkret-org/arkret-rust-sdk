// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=32d523d2ce78c43bf47a897d97a4dab2e7d0ae38a392c38d96200ae946dfdd4e
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

/// Counterpart: `service-operation-dtos.schema.json#/$defs/RecoverySessionGrantRequestBody`.
/// Fresh-device existing-principal recovery issuance.
///
/// Authorization is the Bound AccountHandoff plus a matching per-request DPoP
/// proof. The Account Authority binds this request to its account/principal
/// mapping and does not consume the handoff on success, so the candidate
/// device is deliberately not required to hold an accepted-device
/// authorization yet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionGrantRequestBody {
    pub credential_class: SessionGrantCredentialClass,
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
}

/// Counterpart: `service-operation-dtos.schema.json#/$defs/AgentSessionGrantRefreshRequestBody`.
/// DPoP-bound Agent SessionGrant rotation.
///
/// The predecessor is presented as `Authorization: DPoP` plus a matching DPoP
/// proof; this body carries no client-generated challenge and no polymorphic
/// proof kind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantRefreshRequestBody {
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
