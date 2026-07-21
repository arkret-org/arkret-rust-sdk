//! Key management and recovery schema artifact counterparts.

use std::collections::BTreeMap;

use arkret_wire::{
    BackupId, BackupSeriesId, Base64UrlString, DeviceId, Did, DidUrl, Error, EventId, Hash,
    NonEmptyString, PolicyId, RealmId, ReceiptId, RecoverySessionId, Result, SealBasis,
    TypedTrustDomainId, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::key_backup::{
    BackupClass, KeyBackupSignatureAlgorithm, KeysBackupsDeleteOutcome,
    KeysBackupsDeleteRequestBody, KeysBackupsList, KeysBackupsReplaceOutcome,
    ManagedPrincipalBinding, RecoveryProofKind,
};
use crate::keys::{
    DeviceGenerationStatus, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody,
};

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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockProofAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub signed_fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupUnlockProofAuthData,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json#/$defs/proof_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyOperationSignature {
    pub kid: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<NonEmptyString>,
    pub sig: Base64UrlString,
}

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/failure`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Failure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_claim_record`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyPackageClaimRecord {
    pub claim_id: String,
    pub keypackage_ref: String,
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub device_signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_ref_array`.
pub type KeyPackageRefArray = Vec<String>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_upload_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyPackageUploadEntry {
    pub keypackage_id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: Hash,
    pub key_package: Base64UrlString,
    pub cipher_suites: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ShareShareCommitment {
    pub algorithm: RecoveryShareCommitmentAlgorithm,
    pub commitment_b64u: Base64UrlString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason_code: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/challenge`.
pub type Challenge = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/generic_recovery_transcript`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoveryModelGenerationRef {
    CrossSigning(std::num::NonZeroU64),
    EnrollmentAuthority(NonEmptyString),
}

impl RecoveryModelGenerationRef {
    pub fn validate_for(&self, identity_model: RecoveryIdentityModel) -> Result<()> {
        let valid = match (identity_model, self) {
            (RecoveryIdentityModel::CrossSigning, Self::CrossSigning(_)) => true,
            (RecoveryIdentityModel::EnrollmentAuthority, Self::EnrollmentAuthority(version)) => {
                valid_did_version_id(version.as_str())
            }
            _ => false,
        };
        valid.then_some(()).ok_or_else(|| {
            Error::Protocol(
                "recovery transcript model_generation_ref does not match identity_model".to_owned(),
            )
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "GenericRecoveryTranscriptWire")]
pub struct GenericRecoveryTranscript {
    pub r#type: String,
    pub kind: RecoveryProofKind,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    pub model_generation_ref: RecoveryModelGenerationRef,
    pub challenge: Challenge,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    pub proof_body: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericRecoveryTranscriptWire {
    r#type: String,
    kind: RecoveryProofKind,
    principal_id: Did,
    requesting_device_id: DeviceId,
    trust_domain: TypedTrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: RecoveryModelGenerationRef,
    challenge: Challenge,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    proof_body: BTreeMap<String, Value>,
}

impl TryFrom<GenericRecoveryTranscriptWire> for GenericRecoveryTranscript {
    type Error = String;

    fn try_from(wire: GenericRecoveryTranscriptWire) -> std::result::Result<Self, Self::Error> {
        let transcript = Self {
            r#type: wire.r#type,
            kind: wire.kind,
            principal_id: wire.principal_id,
            requesting_device_id: wire.requesting_device_id,
            trust_domain: wire.trust_domain,
            policy_id: wire.policy_id,
            policy_version: wire.policy_version,
            recovery_session_id: wire.recovery_session_id,
            identity_model: wire.identity_model,
            model_generation_ref: wire.model_generation_ref,
            challenge: wire.challenge,
            expires_at: wire.expires_at,
            created_at: wire.created_at,
            proof_body: wire.proof_body,
        };
        transcript.validate().map_err(|error| error.to_string())?;
        Ok(transcript)
    }
}

impl GenericRecoveryTranscript {
    pub fn validate(&self) -> Result<()> {
        if self.r#type != "ak.identity.recovery_proof.v1" || self.policy_version < 1 {
            return Err(Error::Protocol(
                "generic recovery transcript has an invalid type or policy_version".to_owned(),
            ));
        }
        self.model_generation_ref.validate_for(self.identity_model)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/principal_signing_transcript`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "PrincipalSigningTranscriptWire")]
pub struct PrincipalSigningTranscript {
    pub r#type: String,
    pub kind: RecoveryProofKind,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub recovery_session_id: RecoverySessionId,
    pub identity_model: RecoveryIdentityModel,
    pub model_generation_ref: RecoveryModelGenerationRef,
    pub challenge: Challenge,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalSigningTranscriptWire {
    r#type: String,
    kind: RecoveryProofKind,
    principal_id: Did,
    requesting_device_id: DeviceId,
    trust_domain: TypedTrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: RecoveryModelGenerationRef,
    challenge: Challenge,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

impl TryFrom<PrincipalSigningTranscriptWire> for PrincipalSigningTranscript {
    type Error = String;

    fn try_from(wire: PrincipalSigningTranscriptWire) -> std::result::Result<Self, Self::Error> {
        let transcript = Self {
            r#type: wire.r#type,
            kind: wire.kind,
            principal_id: wire.principal_id,
            requesting_device_id: wire.requesting_device_id,
            trust_domain: wire.trust_domain,
            policy_id: wire.policy_id,
            policy_version: wire.policy_version,
            recovery_session_id: wire.recovery_session_id,
            identity_model: wire.identity_model,
            model_generation_ref: wire.model_generation_ref,
            challenge: wire.challenge,
            expires_at: wire.expires_at,
            created_at: wire.created_at,
        };
        transcript.validate().map_err(|error| error.to_string())?;
        Ok(transcript)
    }
}

impl PrincipalSigningTranscript {
    pub fn validate(&self) -> Result<()> {
        if self.r#type != "ak.identity.recovery_proof.v1"
            || self.kind != RecoveryProofKind::PrincipalSigning
            || self.policy_version < 1
        {
            return Err(Error::Protocol(
                "principal signing transcript has an invalid fixed field".to_owned(),
            ));
        }
        self.model_generation_ref.validate_for(self.identity_model)
    }
}

fn valid_did_version_id(value: &str) -> bool {
    let Some((sequence, suffix)) = value.split_once('-') else {
        return false;
    };
    !sequence.is_empty()
        && !sequence.starts_with('0')
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && !suffix.is_empty()
        && !suffix.chars().any(char::is_whitespace)
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/proof_summary`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyRef {
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_complete_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCompleteOutcome {
    pub ok: bool,
    pub recovery_session_id: RecoverySessionId,
    pub state: SessionState,
    pub device_id: DeviceId,
    pub identity_model: RecoveryIdentityModel,
    pub authorization_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_list_update_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reanchor_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reanchor_batch_receipt_id: Option<ReceiptId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecoveryIdentityModel {
    CrossSigning,
    EnrollmentAuthority,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverySessionCompleteOutcomeWire {
    ok: bool,
    recovery_session_id: RecoverySessionId,
    state: SessionState,
    device_id: DeviceId,
    identity_model: RecoveryIdentityModel,
    authorization_event_id: EventId,
    device_list_update_event_id: Option<EventId>,
    reanchor_event_id: Option<EventId>,
    reanchor_batch_receipt_id: Option<ReceiptId>,
}

impl<'de> Deserialize<'de> for RecoverySessionCompleteOutcome {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RecoverySessionCompleteOutcomeWire::deserialize(deserializer)?;
        validate_recovery_completion_shape(
            wire.identity_model,
            wire.device_list_update_event_id.as_ref(),
            wire.reanchor_event_id.as_ref(),
            wire.reanchor_batch_receipt_id.as_ref(),
        )
        .map_err(serde::de::Error::custom)?;
        if !wire.ok || wire.state != SessionState::Completed {
            return Err(serde::de::Error::custom(
                "recovery completion outcome must have ok=true and state=completed",
            ));
        }
        Ok(Self {
            ok: wire.ok,
            recovery_session_id: wire.recovery_session_id,
            state: wire.state,
            device_id: wire.device_id,
            identity_model: wire.identity_model,
            authorization_event_id: wire.authorization_event_id,
            device_list_update_event_id: wire.device_list_update_event_id,
            reanchor_event_id: wire.reanchor_event_id,
            reanchor_batch_receipt_id: wire.reanchor_batch_receipt_id,
        })
    }
}

impl RecoverySessionCompleteOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_recovery_completion_shape(
            self.identity_model,
            self.device_list_update_event_id.as_ref(),
            self.reanchor_event_id.as_ref(),
            self.reanchor_batch_receipt_id.as_ref(),
        )
        .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        if !self.ok || self.state != SessionState::Completed {
            return Err(Error::Protocol(
                "recovery completion outcome must have ok=true and state=completed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_complete_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCompleteRequestBody {
    pub authorization_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_list_update_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reanchor_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reanchor_batch_receipt_id: Option<ReceiptId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<NonEmptyString>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverySessionCompleteRequestBodyWire {
    authorization_event_id: EventId,
    device_list_update_event_id: Option<EventId>,
    reanchor_event_id: Option<EventId>,
    reanchor_batch_receipt_id: Option<ReceiptId>,
    idempotency_key: Option<NonEmptyString>,
}

impl<'de> Deserialize<'de> for RecoverySessionCompleteRequestBody {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RecoverySessionCompleteRequestBodyWire::deserialize(deserializer)?;
        let cross_signing = wire.device_list_update_event_id.is_some()
            && wire.reanchor_event_id.is_none()
            && wire.reanchor_batch_receipt_id.is_none();
        let enrollment_authority = wire.device_list_update_event_id.is_none()
            && wire.reanchor_event_id.is_some()
            && wire.reanchor_batch_receipt_id.is_some();
        if !cross_signing && !enrollment_authority {
            return Err(serde::de::Error::custom(
                "recovery completion must reference exactly the A or B accepted artifact set",
            ));
        }
        Ok(Self {
            authorization_event_id: wire.authorization_event_id,
            device_list_update_event_id: wire.device_list_update_event_id,
            reanchor_event_id: wire.reanchor_event_id,
            reanchor_batch_receipt_id: wire.reanchor_batch_receipt_id,
            idempotency_key: wire.idempotency_key,
        })
    }
}

impl RecoverySessionCompleteRequestBody {
    pub fn identity_model(&self) -> Result<RecoveryIdentityModel> {
        let cross_signing = self.device_list_update_event_id.is_some()
            && self.reanchor_event_id.is_none()
            && self.reanchor_batch_receipt_id.is_none();
        let enrollment_authority = self.device_list_update_event_id.is_none()
            && self.reanchor_event_id.is_some()
            && self.reanchor_batch_receipt_id.is_some();
        match (cross_signing, enrollment_authority) {
            (true, false) => Ok(RecoveryIdentityModel::CrossSigning),
            (false, true) => Ok(RecoveryIdentityModel::EnrollmentAuthority),
            _ => Err(Error::Protocol(
                "recovery completion must reference exactly the A or B accepted artifact set"
                    .to_owned(),
            )),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.identity_model().map(|_| ())
    }
}

fn validate_recovery_completion_shape(
    identity_model: RecoveryIdentityModel,
    device_list_update_event_id: Option<&EventId>,
    reanchor_event_id: Option<&EventId>,
    reanchor_batch_receipt_id: Option<&ReceiptId>,
) -> std::result::Result<(), &'static str> {
    let valid = match identity_model {
        RecoveryIdentityModel::CrossSigning => {
            device_list_update_event_id.is_some()
                && reanchor_event_id.is_none()
                && reanchor_batch_receipt_id.is_none()
        }
        RecoveryIdentityModel::EnrollmentAuthority => {
            device_list_update_event_id.is_none()
                && reanchor_event_id.is_some()
                && reanchor_batch_receipt_id.is_some()
        }
    };
    valid
        .then_some(())
        .ok_or("recovery completion identity_model does not match its accepted artifact set")
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_create_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionCreateRequestBody {
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_recovery_policy_ref: Option<RecoveryPolicyRef>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/
/// recovery_session_proof_submit_outcome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionProofSubmitRequestBody {
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct RecoverySessionState {
    pub schema: String,
    pub recovery_session_id: RecoverySessionId,
    pub principal_id: Did,
    pub requesting_device_id: DeviceId,
    pub trust_domain: TypedTrustDomainId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub identity_model: RecoveryIdentityModel,
    pub ssk_generation: Option<u64>,
    pub current_device_generation_ref: Option<NonEmptyString>,
    pub device_generation_status: Option<DeviceGenerationStatus>,
    pub registry_head: Option<Hash>,
    pub accepted_seal_frontier: Option<SealBasis>,
    pub challenge: Challenge,
    pub state: SessionState,
    pub proof_summary: Option<ProofSummary>,
    pub rejection_reason_code: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Serialize for RecoverySessionState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        self.validate().map_err(serde::ser::Error::custom)?;
        let expires_at = arkret_canonical::canonical::format_timestamp_canonical(self.expires_at);
        let created_at = arkret_canonical::canonical::format_timestamp_canonical(self.created_at);
        let updated_at = arkret_canonical::canonical::format_timestamp_canonical(self.updated_at);
        let model_fields = match self.identity_model {
            RecoveryIdentityModel::CrossSigning => 1,
            RecoveryIdentityModel::EnrollmentAuthority => 4,
        };
        let mut map = serializer.serialize_map(Some(
            13 + model_fields
                + usize::from(self.proof_summary.is_some())
                + usize::from(self.rejection_reason_code.is_some()),
        ))?;
        map.serialize_entry("schema", &self.schema)?;
        map.serialize_entry("recovery_session_id", &self.recovery_session_id)?;
        map.serialize_entry("principal_id", &self.principal_id)?;
        map.serialize_entry("requesting_device_id", &self.requesting_device_id)?;
        map.serialize_entry("trust_domain", &self.trust_domain)?;
        map.serialize_entry("policy_id", &self.policy_id)?;
        map.serialize_entry("policy_version", &self.policy_version)?;
        map.serialize_entry("identity_model", &self.identity_model)?;
        match self.identity_model {
            RecoveryIdentityModel::CrossSigning => {
                map.serialize_entry("ssk_generation", &self.ssk_generation)?;
            }
            RecoveryIdentityModel::EnrollmentAuthority => {
                map.serialize_entry(
                    "current_device_generation_ref",
                    &self.current_device_generation_ref,
                )?;
                map.serialize_entry("device_generation_status", &self.device_generation_status)?;
                map.serialize_entry("registry_head", &self.registry_head)?;
                map.serialize_entry("accepted_seal_frontier", &self.accepted_seal_frontier)?;
            }
        }
        map.serialize_entry("challenge", &self.challenge)?;
        map.serialize_entry("state", &self.state)?;
        if let Some(proof_summary) = &self.proof_summary {
            map.serialize_entry("proof_summary", proof_summary)?;
        }
        if let Some(reason) = &self.rejection_reason_code {
            map.serialize_entry("rejection_reason_code", reason)?;
        }
        map.serialize_entry("expires_at", &expires_at)?;
        map.serialize_entry("created_at", &created_at)?;
        map.serialize_entry("updated_at", &updated_at)?;
        map.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverySessionStateWire {
    schema: String,
    recovery_session_id: RecoverySessionId,
    principal_id: Did,
    requesting_device_id: DeviceId,
    trust_domain: TypedTrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    identity_model: RecoveryIdentityModel,
    ssk_generation: Option<u64>,
    current_device_generation_ref: Option<NonEmptyString>,
    device_generation_status: Option<DeviceGenerationStatus>,
    registry_head: Option<Hash>,
    accepted_seal_frontier: Option<SealBasis>,
    challenge: Challenge,
    state: SessionState,
    proof_summary: Option<ProofSummary>,
    rejection_reason_code: Option<String>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    updated_at: DateTime<Utc>,
}

fn validate_recovery_session_state_shape(
    identity_model: RecoveryIdentityModel,
    ssk_generation: Option<u64>,
    current_device_generation_ref: Option<&NonEmptyString>,
    device_generation_status: Option<DeviceGenerationStatus>,
    registry_head: Option<&Hash>,
    accepted_seal_frontier_present: bool,
) -> std::result::Result<(), &'static str> {
    let valid = match identity_model {
        RecoveryIdentityModel::CrossSigning => {
            ssk_generation.is_some_and(|generation| generation >= 1)
                && current_device_generation_ref.is_none()
                && device_generation_status.is_none()
                && registry_head.is_none()
                && !accepted_seal_frontier_present
        }
        RecoveryIdentityModel::EnrollmentAuthority => {
            ssk_generation.is_none()
                && current_device_generation_ref.is_some()
                && device_generation_status.is_some()
                && registry_head.is_some()
                && accepted_seal_frontier_present
        }
    };
    valid
        .then_some(())
        .ok_or("recovery session identity_model does not match its authoritative snapshot")
}

impl<'de> Deserialize<'de> for RecoverySessionState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let accepted_seal_frontier_present = value
            .as_object()
            .is_some_and(|object| object.contains_key("accepted_seal_frontier"));
        let wire: RecoverySessionStateWire =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        validate_recovery_session_state_shape(
            wire.identity_model,
            wire.ssk_generation,
            wire.current_device_generation_ref.as_ref(),
            wire.device_generation_status,
            wire.registry_head.as_ref(),
            accepted_seal_frontier_present,
        )
        .map_err(serde::de::Error::custom)?;
        if matches!(wire.state, SessionState::Verified | SessionState::Completed)
            && wire.proof_summary.is_none()
        {
            return Err(serde::de::Error::custom(
                "verified or completed recovery session requires proof_summary",
            ));
        }
        if wire.state == SessionState::Rejected && wire.rejection_reason_code.is_none() {
            return Err(serde::de::Error::custom(
                "rejected recovery session requires rejection_reason_code",
            ));
        }
        let state = Self {
            schema: wire.schema,
            recovery_session_id: wire.recovery_session_id,
            principal_id: wire.principal_id,
            requesting_device_id: wire.requesting_device_id,
            trust_domain: wire.trust_domain,
            policy_id: wire.policy_id,
            policy_version: wire.policy_version,
            identity_model: wire.identity_model,
            ssk_generation: wire.ssk_generation,
            current_device_generation_ref: wire.current_device_generation_ref,
            device_generation_status: wire.device_generation_status,
            registry_head: wire.registry_head,
            accepted_seal_frontier: wire.accepted_seal_frontier,
            challenge: wire.challenge,
            state: wire.state,
            proof_summary: wire.proof_summary,
            rejection_reason_code: wire.rejection_reason_code,
            expires_at: wire.expires_at,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        state.validate().map_err(serde::de::Error::custom)?;
        Ok(state)
    }
}

impl RecoverySessionState {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "ak.schema.recovery_session.v1" {
            return Err(Error::Protocol(
                "recovery session schema must be ak.schema.recovery_session.v1".to_owned(),
            ));
        }
        if self.policy_version < 1 {
            return Err(Error::Protocol(
                "recovery session policy_version must be at least one".to_owned(),
            ));
        }
        validate_recovery_session_state_shape(
            self.identity_model,
            self.ssk_generation,
            self.current_device_generation_ref.as_ref(),
            self.device_generation_status,
            self.registry_head.as_ref(),
            self.identity_model == RecoveryIdentityModel::EnrollmentAuthority,
        )
        .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        if matches!(self.state, SessionState::Verified | SessionState::Completed)
            && self.proof_summary.is_none()
        {
            return Err(Error::Protocol(
                "verified or completed recovery session requires proof_summary".to_owned(),
            ));
        }
        if self.state == SessionState::Rejected && self.rejection_reason_code.is_none() {
            return Err(Error::Protocol(
                "rejected recovery session requires rejection_reason_code".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/session_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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

#[cfg(test)]
mod recovery_completion_tests {
    use serde_json::json;

    use super::*;

    fn event(suffix: &str) -> String {
        format!("ak:event:01904100-0000-7000-8000-{suffix}")
    }

    #[test]
    fn recovery_complete_request_accepts_exact_a_or_b_artifact_sets() {
        let cross_signing: RecoverySessionCompleteRequestBody = serde_json::from_value(json!({
            "authorization_event_id": event("000000000001"),
            "device_list_update_event_id": event("000000000002")
        }))
        .unwrap();
        assert_eq!(
            cross_signing.identity_model().unwrap(),
            RecoveryIdentityModel::CrossSigning
        );

        let enrollment: RecoverySessionCompleteRequestBody = serde_json::from_value(json!({
            "authorization_event_id": event("000000000001"),
            "reanchor_event_id": event("000000000003"),
            "reanchor_batch_receipt_id": "ak:receipt:01904100-0000-7000-8000-000000000004"
        }))
        .unwrap();
        assert_eq!(
            enrollment.identity_model().unwrap(),
            RecoveryIdentityModel::EnrollmentAuthority
        );

        assert!(
            serde_json::from_value::<RecoverySessionCompleteRequestBody>(json!({
                "authorization_event_id": event("000000000001"),
                "device_list_update_event_id": event("000000000002"),
                "reanchor_event_id": event("000000000003"),
                "reanchor_batch_receipt_id": "ak:receipt:01904100-0000-7000-8000-000000000004"
            }))
            .is_err()
        );
    }

    #[test]
    fn recovery_complete_outcome_enforces_model_and_terminal_constants() {
        let valid = json!({
            "ok": true,
            "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-000000000005",
            "state": "completed",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000006",
            "identity_model": "enrollment_authority",
            "authorization_event_id": event("000000000001"),
            "reanchor_event_id": event("000000000003"),
            "reanchor_batch_receipt_id": "ak:receipt:01904100-0000-7000-8000-000000000004"
        });
        let outcome: RecoverySessionCompleteOutcome =
            serde_json::from_value(valid.clone()).unwrap();
        outcome.validate().unwrap();

        let mut wrong_model = valid.clone();
        wrong_model["identity_model"] = json!("cross_signing");
        assert!(serde_json::from_value::<RecoverySessionCompleteOutcome>(wrong_model).is_err());

        let mut not_terminal = valid;
        not_terminal["ok"] = json!(false);
        assert!(serde_json::from_value::<RecoverySessionCompleteOutcome>(not_terminal).is_err());
    }

    #[test]
    fn recovery_session_state_enforces_model_specific_snapshot_presence() {
        let enrollment = json!({
            "schema": "ak.schema.recovery_session.v1",
            "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-000000000005",
            "principal_id": "did:webvh:z6mkfixture:users.example:alice",
            "requesting_device_id": "ak:device:01904100-0000-7000-8000-000000000006",
            "trust_domain": "ak:trust_domain:example.net",
            "policy_id": "ak:policy:01904100-0000-7000-8000-000000000007",
            "policy_version": 1,
            "identity_model": "enrollment_authority",
            "current_device_generation_ref": "2-zgeneration",
            "device_generation_status": "active",
            "registry_head": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "accepted_seal_frontier": null,
            "challenge": "challenge-1",
            "state": "pending",
            "expires_at": "2026-07-15T00:10:00.000Z",
            "created_at": "2026-07-15T00:00:00.000Z",
            "updated_at": "2026-07-15T00:00:00.000Z"
        });
        let state: RecoverySessionState = serde_json::from_value(enrollment.clone()).unwrap();
        assert_eq!(
            state.identity_model,
            RecoveryIdentityModel::EnrollmentAuthority
        );
        assert_eq!(
            serde_json::to_value(&state).unwrap()["accepted_seal_frontier"],
            Value::Null
        );

        let mut missing_frontier = enrollment;
        missing_frontier
            .as_object_mut()
            .unwrap()
            .remove("accepted_seal_frontier");
        assert!(serde_json::from_value::<RecoverySessionState>(missing_frontier).is_err());

        let cross_signing = json!({
            "schema": "ak.schema.recovery_session.v1",
            "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-000000000005",
            "principal_id": "did:webvh:z6mkfixture:users.example:alice",
            "requesting_device_id": "ak:device:01904100-0000-7000-8000-000000000006",
            "trust_domain": "ak:trust_domain:example.net",
            "policy_id": "ak:policy:01904100-0000-7000-8000-000000000007",
            "policy_version": 1,
            "identity_model": "cross_signing",
            "ssk_generation": 2,
            "challenge": "challenge-1",
            "state": "pending",
            "expires_at": "2026-07-15T00:10:00.000Z",
            "created_at": "2026-07-15T00:00:00.000Z",
            "updated_at": "2026-07-15T00:00:00.000Z"
        });
        assert!(serde_json::from_value::<RecoverySessionState>(cross_signing).is_ok());
    }
}

// ── Keypackage operations aggregate ──────────────────────────────────────
// Migrated from `arkret-core` (`models/artifacts/keys.rs`); a shim there
// re-exports this enum to preserve the `arkret_core::` path.

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyPackageOperations {
    KeyPackagesUploadRequestBody(crate::http_bodies::KeyPackagesUploadRequestBody),
    KeyPackagesUploadOutcome(crate::http_bodies::KeyPackagesUploadOutcome),
    KeyPackagesClaimRequestBody(crate::http_bodies::KeyPackagesClaimRequestBody),
    KeyPackagesClaimOutcome(crate::http_bodies::KeyPackagesClaimOutcome),
    PeerKeyPackagesClaimRequestBody(crate::http_bodies::PeerKeyPackagesClaimRequestBody),
    PeerKeyPackagesClaimOutcome(crate::http_bodies::PeerKeyPackagesClaimOutcome),
    PeerKeyPackagesClaimQueryRequestBody(crate::http_bodies::PeerKeyPackagesClaimQueryRequestBody),
    PeerKeyPackagesClaimQueryOutcome(crate::http_bodies::PeerKeyPackagesClaimQueryOutcome),
    KeyPackagesConsumeRequestBody(crate::http_bodies::KeyPackagesConsumeRequestBody),
    KeyPackagesConsumeOutcome(crate::http_bodies::KeyPackagesConsumeOutcome),
    KeyPackagesRevokeRequestBody(crate::http_bodies::KeyPackagesRevokeRequestBody),
    KeyPackagesRevokeOutcome(crate::http_bodies::KeyPackagesRevokeOutcome),
}
