// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/recovery-session.schema.json
// sha256=d1611974b0c00d6bd347ff52e1842366ec13eea38b8b81a0ce533ab0e9c5fffd
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Input: schemas/recovery-policy.schema.json
// sha256=64ee8fa0a54cb044195141e91cfb8989320d304f2ebef750eaa857ef712a4b05
//
// Input: schemas/recovery-authority.schema.json
// sha256=6386cc9e6bc7aab507d81d9e7d20e082c748ce4451fcee5e830e5e72a96a32ea
//
// Bindings: tools/closed-model-bindings.json
// sha256=ea613fae32e25a94687889845566828fe050317b185350eceb320391ae60c2f4

/// Counterpart: `recovery-session.schema.json#/$defs/proof_summary`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSummary {
    pub kind: RecoveryProofKind,
    pub proof_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub verification_method: Option<DidUrl>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/publication_authority_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationAuthorityContext {
    pub authority_commit_id: RealmCommitId,
    pub scope_ref: ScopeRef,
    pub authority_set_policy: AuthoritySetPolicy,
    pub allowed_actions: Vec<String>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_session_create_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCreateRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub requesting_device_signature: Base64UrlString,
    pub trust_domain: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_recovery_policy_ref: Option<RecoveryPolicyRef>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_device_possession_transcript`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDevicePossessionTranscript {
    pub schema: String,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_recovery_policy_ref: Option<RecoveryPolicyRef>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/did_root_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidRootProofBody {
    pub kind: DidRootProofKind,
    pub challenge: Base64UrlString,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_unlock_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnlockProofBodyWithSignature {
    pub kind: RecoveryUnlockProofKind,
    pub challenge: Base64UrlString,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

/// Counterpart: `recovery-session.schema.json#/$defs/device_quorum_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumProofBodyWithSignatures {
    pub kind: DeviceQuorumProofKind,
    pub challenge: Base64UrlString,
    pub threshold: u32,
    pub signatures: Vec<DeviceQuorumSignature>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/trusted_recovery_service_proof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceProofBodyWithSignature {
    pub kind: TrustedRecoveryServiceProofKind,
    pub challenge: Base64UrlString,
    pub service_id: DidCoreId,
    pub audience: String,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

/// Counterpart:
/// `recovery-session.schema.json#/$defs/device_quorum_proof/properties/signatures/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumSignature {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

/// Counterpart:
/// `recovery-session.schema.json#/$defs/device_quorum_proof_body/properties/signatures/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumSignatureBody {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
}

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_unlock_proof_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnlockProofBody {
    pub kind: RecoveryUnlockProofKind,
    pub challenge: Base64UrlString,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
}

/// Counterpart: `recovery-session.schema.json#/$defs/device_quorum_proof_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumProofBody {
    pub kind: DeviceQuorumProofKind,
    pub challenge: Base64UrlString,
    pub threshold: u32,
    pub signatures: Vec<DeviceQuorumSignatureBody>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/trusted_recovery_service_proof_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceProofBody {
    pub kind: TrustedRecoveryServiceProofKind,
    pub challenge: Base64UrlString,
    pub service_id: DidCoreId,
    pub audience: String,
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
}

/// Counterpart: `recovery-session.schema.json#/$defs/did_root_transcript`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidRootRecoveryTranscript {
    pub schema: String,
    pub kind: RecoveryProofKind,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    pub model_generation_ref: u64,
    pub publication_authority_context_digest: Hash,
    pub challenge: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_session_proof_submit_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof: RecoverySessionProof,
}

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_session_proof_submit_response_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitResponseBody {
    pub recovery_session_id: RecoverySessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub proof_summary: Option<RecoverySessionProofSummary>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_session_state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySession {
    pub schema: String,
    pub request_id: RequestId,
    pub recovery_session_id: RecoverySessionId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub identity_model: RecoveryIdentityModel,
    pub current_device_generation_ref: u64,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub realm_stream_head: CommitStreamHead,
    pub publication_authority_context: PublicationAuthorityContext,
    pub publication_authority_context_digest: Hash,
    pub challenge: Base64UrlString,
    pub state: RecoverySessionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub proof_summary: Option<RecoverySessionProofSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub transaction_id: Option<TransactionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub rejection_reason_code: Option<RecoverySessionRejectionReasonCode>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// Counterpart: `recovery-session.schema.json#/$defs/generic_recovery_transcript`.
/// Canonical transcript shared by `recovery_unlock`, `device_quorum` and
/// `trusted_recovery_service` proofs. Producers and receivers bind exactly this
/// session tuple.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericRecoveryTranscript {
    pub schema: String,
    pub kind: RecoveryProofKind,
    pub request_id: RequestId,
    pub session_grant_id: SessionGrantId,
    pub session_grant_cnf_jkt: Base64UrlString,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub requesting_device_public_key_did: DidKey,
    pub trust_domain: TrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    pub model_generation_ref: u64,
    pub publication_authority_context_digest: Hash,
    pub challenge: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof_body: RecoveryTranscriptProofBody,
}
