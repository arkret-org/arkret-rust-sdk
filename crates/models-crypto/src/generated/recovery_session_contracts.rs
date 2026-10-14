// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/recovery-session.schema.json
// sha256=8a9bfd64d8eb6c86b035c57c8da9d4d38a3db63ef0a08ed0e61add38250b6a05
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/recovery-policy.schema.json
// sha256=819fc1da2cfe93f35ca0ee9802a6a621f227e22d8ec61d499bb11721f546a741
//
// Input: schemas/recovery-authority.schema.json
// sha256=175897c1fe545d915a82fa9244f7d2a31a2fd2169e16f811c0eac424c6102047
//
// Bindings: tools/closed-model-bindings.json
// sha256=a09494f9b20fd0b06cee86eb504c26b02dab5a7b147a7e5a1034a07d05811aef

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

/// Counterpart: `recovery-session.schema.json#/$defs/recovery_session_proof_submit_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitOutcome {
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
