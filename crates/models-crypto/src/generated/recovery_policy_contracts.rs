// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/recovery-policy.schema.json
// sha256=819fc1da2cfe93f35ca0ee9802a6a621f227e22d8ec61d499bb11721f546a741
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/call-recording-artifact.schema.json
// sha256=d8f6f18b12611c37cf56573ef2cffe8d817a978f0df348bfc1d9a003ad576d92
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

/// Counterpart: `recovery-policy.schema.json#/$defs/recovery_key_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyEntry {
    pub verification_method: DidUrl,
    pub public_key_multibase: String,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    pub backup_hpke: RecoveryKeyAgreementEntry,
}

/// Counterpart: `recovery-policy.schema.json#/$defs/recovery_key_agreement_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyAgreementEntry {
    pub key_agreement_ref: DidUrl,
    pub key_agreement_algorithm: RecoveryKeyAgreementAlgorithm,
    pub public_key_multibase: String,
    pub hpke_suites: Vec<RecoveryBackupHpkeSuite>,
    pub r#use: RecoveryKeyAgreementUse,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Counterpart: `recovery-policy.schema.json#/$defs/recovery_policy_ref`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyRef {
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

/// Counterpart: `recovery-policy.schema.json#/$defs/recovery_policy_summary`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySummary {
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    pub version: u64,
    pub acceptance_basis_ref: RealmCommitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    pub trust_domain: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_id: Option<PolicyId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub accepted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub policy: Option<RecoveryPolicy>,
    pub methods: Vec<RecoveryMethod>,
}

/// Counterpart: `recovery-policy.schema.json#/$defs/recovery_policy_set_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySetPayload {
    pub policy_id: PolicyId,
    pub value: RecoveryPolicy,
}

/// Counterpart: `recovery-policy.schema.json#/$defs/authority_stream_head`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorityStreamHead {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub source_commit_ref: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub observed_at: Option<DateTime<Utc>>,
}

/// Counterpart: `recovery-policy.schema.json#/$defs/recovery_policy_active_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyActiveOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub account_id: Option<AccountId>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub active_policy: Option<RecoveryPolicySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub authority_stream_head: Option<RecoveryAuthorityStreamHead>,
}

/// Counterpart: `recovery-policy.schema.json#/$defs/recovery_policy_publish_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyPublishOutcome {
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    pub version: u64,
    pub acceptance_basis_ref: RealmCommitId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

/// Counterpart: `recovery-policy.schema.json#/properties/auth_data`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}
