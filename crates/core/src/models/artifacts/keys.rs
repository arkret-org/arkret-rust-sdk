//! Key management and recovery schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupPlaintext {
    pub schema: String,
    pub backup_id: BackupId,
    pub backup_class: BackupClass,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
    pub items: Vec<PlaintextItem>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json#/$defs/item_type`.
pub type ItemType = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json#/$defs/plaintext_item`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaintextItem {
    pub item_type: ItemType,
    pub secret_id: String,
    pub secret_b64u: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_principal_binding: Option<ManagedPrincipalBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json#/properties/auth_data`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockProofAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub signed_fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupUnlockProof {
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub backup_id: BackupId,
    pub backup_class: BackupClass,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
    pub proof_kind: ProofKind,
    pub proof_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupUnlockProofAuthData,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json#/$defs/proof_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    PrincipalSigning,
    RecoveryUnlock,
    DeviceQuorum,
    TrustedRecoveryService,
    ThresholdRecovery,
}

/// Counterpart for the shared signature object used by key operations:
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/signature` and
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/signature`
/// (identical shape: `{kid, alg?, sig}`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyOperationSignature {
    pub kid: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<NonEmptyString>,
    pub sig: Base64UrlString,
}

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyPackageOperations {
    KeyPackagesUploadRequestBody(crate::KeyPackagesUploadRequestBody),
    KeyPackagesUploadOutcome(crate::KeyPackagesUploadOutcome),
    KeyPackagesClaimRequestBody(crate::KeyPackagesClaimRequestBody),
    KeyPackagesClaimOutcome(crate::KeyPackagesClaimOutcome),
    KeyPackagesConsumeRequestBody(crate::KeyPackagesConsumeRequestBody),
    KeyPackagesConsumeOutcome(crate::KeyPackagesConsumeOutcome),
    KeyPackagesRevokeRequestBody(crate::KeyPackagesRevokeRequestBody),
    KeyPackagesRevokeOutcome(crate::KeyPackagesRevokeOutcome),
}

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/failure`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Failure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_claim_record`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyPackageClaimRecord {
    pub claim_id: String,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub principal_id: Did,
    pub device_id: String,
    pub key_package: String,
    pub capabilities: Vec<String>,
    pub capabilities_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssk_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub device_signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_ref_array`.
pub type KeyPackageRefArray = Vec<ObjectRef>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_upload_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyPackageUploadEntry {
    pub keypackage_id: String,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub key_package: Base64UrlString,
    pub cipher_suites: Vec<String>,
    pub capabilities: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<KeyOperationSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeysOperations {
    KeysUploadRequestBody(KeysUploadRequestBody),
    KeysUploadOutcome(KeysUploadOutcome),
    KeysQueryRequestBody(KeysQueryRequestBody),
    KeysQueryOutcome(KeysQueryOutcome),
    KeysClaimRequestBody(KeysClaimRequestBody),
    KeysClaimOutcome(KeysClaimOutcome),
    KeysBackupsReplaceOutcome(KeysBackupsReplaceOutcome),
    KeysBackupsList(KeysBackupsList),
    KeysBackupsDeleteRequestBody(KeysBackupsDeleteRequestBody),
    KeysBackupsDeleteOutcome(KeysBackupsDeleteOutcome),
}

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_counts`.
pub type AlgorithmCounts = BTreeMap<NonEmptyString, u64>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_key_records`.
pub type AlgorithmKeyRecords = BTreeMap<NonEmptyString, KeyRecord>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/backup_metadata`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupMetadata {
    pub backup_id: BackupId,
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub backup_class: BackupClass,
    pub backup_version: String,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<BackupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    pub ciphertext_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<BTreeMap<String, Value>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/device_algorithm_map`.
pub type DeviceAlgorithmMap = BTreeMap<DeviceId, NonEmptyString>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/device_key_records`.
pub type DeviceKeyRecords = BTreeMap<DeviceId, AlgorithmKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/key_record`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key: Base64UrlString,
    pub algorithm: NonEmptyString,
    pub signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_algorithm_map`.
pub type PrincipalDeviceAlgorithmMap = BTreeMap<Did, DeviceAlgorithmMap>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_key_records`.
pub type PrincipalDeviceKeyRecords = BTreeMap<Did, DeviceKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/query_device_map`.
pub type QueryDeviceMap = BTreeMap<Did, Vec<DeviceId>>;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-policy.schema.json#/$defs/share`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ShareShareCommitment {
    pub algorithm: RecoveryShareCommitmentAlgorithm,
    pub commitment_b64u: Base64UrlString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryShareCommitmentAlgorithm {
    FeldmanVssSha256,
    PedersenVssSha256,
    ShareHashSha256,
    ShareHashBlake3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub share_id: String,
    pub holder: Did,
    pub transport: String,
    pub share_commitment: ShareShareCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason_code: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json`.
pub type RecoverySession = RecoverySessionState;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/challenge`.
pub type Challenge = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/generic_recovery_transcript`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericRecoveryTranscript {
    pub r#type: String,
    pub kind: String,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub ssk_generation: u64,
    pub challenge: Challenge,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub proof_body: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/principal_signing_transcript`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSigningTranscript {
    pub r#type: String,
    pub kind: String,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub ssk_generation: u64,
    pub challenge: Challenge,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/proof_summary`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProofSummary {
    pub kind: RecoveryProofKind,
    pub proof_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_policy_ref`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyRef {
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_complete_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCompleteOutcome {
    pub ok: bool,
    pub recovery_session_id: RecoverySessionId,
    pub state: SessionState,
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    pub device_list_update_event_id: EventId,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_complete_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCompleteRequestBody {
    pub authorization_event_id: EventId,
    pub device_list_update_event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_create_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCreateRequestBody {
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub ssk_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_recovery_policy_ref: Option<RecoveryPolicyRef>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_proof_submit_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitOutcome {
    pub recovery_session_id: RecoverySessionId,
    pub state: SessionState,
    pub verification: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_summary: Option<ProofSummary>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_proof_submit_request_body`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitRequestBody {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub proof: RecoverySessionProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryPrincipalSigningProofKind {
    #[serde(rename = "principal_signing")]
    PrincipalSigning,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPrincipalSigningProof {
    pub kind: RecoveryPrincipalSigningProofKind,
    pub challenge: Challenge,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoverySessionUnlockProofKind {
    #[serde(rename = "recovery_unlock")]
    RecoveryUnlock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionUnlockProof {
    pub kind: RecoverySessionUnlockProofKind,
    pub challenge: Challenge,
    pub recovery_secret_ref: NonEmptyString,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub unlock_commitment: Hash,
    pub signature: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeviceQuorumSignature {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryDeviceQuorumProofKind {
    #[serde(rename = "device_quorum")]
    DeviceQuorum,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeviceQuorumProof {
    pub kind: RecoveryDeviceQuorumProofKind,
    pub challenge: Challenge,
    #[serde(deserialize_with = "deserialize_minimum_two")]
    pub threshold: u64,
    pub signatures: Vec<RecoveryDeviceQuorumSignature>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustedRecoveryServiceSessionProofKind {
    #[serde(rename = "trusted_recovery_service")]
    TrustedRecoveryService,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceSessionProof {
    pub kind: TrustedRecoveryServiceSessionProofKind,
    pub challenge: Challenge,
    pub service_id: Did,
    pub audience: NonEmptyString,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<NonEmptyString>,
    pub signature: Base64UrlString,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoverySessionProof {
    PrincipalSigning(RecoveryPrincipalSigningProof),
    RecoveryUnlock(RecoverySessionUnlockProof),
    DeviceQuorum(RecoveryDeviceQuorumProof),
    TrustedRecoveryService(TrustedRecoveryServiceSessionProof),
    ThresholdRecovery(ThresholdRecoveryProof),
}

fn deserialize_minimum_two<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if value < 2 {
        return Err(serde::de::Error::custom("value must be at least two"));
    }
    Ok(value)
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_state`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionState {
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub ssk_generation: u64,
    pub challenge: Challenge,
    pub state: SessionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_summary: Option<ProofSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason_code: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/session_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Pending,
    Verified,
    Completed,
    Rejected,
    Expired,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/threshold_recovery_proof`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProofShareReleasesItem {
    pub share_id: NonEmptyString,
    pub holder: Did,
    pub transcript_digest: Hash,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdRecoveryProofKind {
    #[serde(rename = "threshold_recovery")]
    ThresholdRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProof {
    pub kind: ThresholdRecoveryProofKind,
    pub challenge: Challenge,
    #[serde(deserialize_with = "deserialize_minimum_two")]
    pub threshold: u64,
    pub share_releases: Vec<ThresholdRecoveryProofShareReleasesItem>,
}
