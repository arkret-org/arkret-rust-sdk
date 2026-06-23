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
    pub extra: BTreeMap<String, Value>,
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
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockProofAuthData {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub verification_method: Value,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyBackupUnlockProof {
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub principal_id: Did,
    pub requesting_device_id: String,
    pub backup_id: BackupId,
    pub backup_class: BackupClass,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
    pub proof_kind: ProofKind,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub proof_digest: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupUnlockProofAuthData,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json#/$defs/proof_kind`.
pub type ProofKind = String;

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeypackageOperations {
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
pub struct Signature2 {
    pub kid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeypackageClaimRecord {
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
    pub device_signature: Signature2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_ref_array`.
pub type KeypackageRefArray = Vec<ObjectRef>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_upload_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature3 {
    pub kid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeypackageUploadEntry {
    pub keypackage_id: String,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub key_package: Value,
    pub cipher_suites: Vec<String>,
    pub capabilities: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<Signature3>,
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
pub type AlgorithmCounts = BTreeMap<String, u64>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_key_records`.
pub type AlgorithmKeyRecords = BTreeMap<String, KeyRecord>;

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
pub type DeviceAlgorithmMap = BTreeMap<String, NonEmptyString>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/device_key_records`.
pub type DeviceKeyRecords = BTreeMap<String, AlgorithmKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/key_record`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature4 {
    pub kid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key: String,
    pub algorithm: String,
    pub signature: Signature4,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
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
pub type PrincipalDeviceAlgorithmMap = BTreeMap<String, DeviceAlgorithmMap>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_key_records`.
pub type PrincipalDeviceKeyRecords = BTreeMap<String, DeviceKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/query_device_map`.
pub type QueryDeviceMap = BTreeMap<String, Vec<DeviceId>>;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-policy.schema.json#/$defs/share`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareShareCommitment {
    pub algorithm: String,
    pub commitment_b64u: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub share_id: String,
    pub holder: Value,
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
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/device_authorize_material`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizeMaterialCrossSigningBinding {
    pub verification_method: Did,
    pub alg: String,
    pub ssk_generation: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceAuthorizeMaterial {
    pub principal_id: Did,
    pub device_id: String,
    pub device_public_key: String,
    pub authorized_by: String,
    pub not_before: DateTime<Utc>,
    pub device_signature: String,
    pub recovery_session_id: RecoverySessionId,
    pub cross_signing_binding: DeviceAuthorizeMaterialCrossSigningBinding,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/generic_recovery_transcript`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericRecoveryTranscript {
    pub r#type: String,
    pub kind: String,
    pub principal_id: Did,
    pub requesting_device_id: String,
    pub trust_domain: String,
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
    pub requesting_device_id: String,
    pub trust_domain: String,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub ssk_generation: u64,
    pub challenge: Challenge,
    pub expires_at: DateTime<Utc>,
    pub created_at: Value,
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
    pub proof: Value,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProofShareReleasesItem {
    pub share_id: String,
    pub holder: Did,
    pub transcript_digest: Value,
    pub verification_method: Did,
    pub alg: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecoveryProof {
    pub kind: String,
    pub challenge: Challenge,
    pub threshold: u64,
    pub share_releases: Vec<ThresholdRecoveryProofShareReleasesItem>,
}
