//! Typed request and response models for the encrypted key-backup service.

use arkret_wire::{
    AccountId, ActorId, AuditReasonText, BackupId, BackupSeriesId, Base64UrlString,
    CommittedEventRef, Cursor, DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, PayloadProof,
    RecoverySessionId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{BackupKind, KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupsListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_id: Option<BackupSeriesId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_kind: Option<BackupKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupActiveSeriesPointer {
    Absent {},
    Active {
        active_series_id: BackupSeriesId,
        series_pointer_version: u64,
    },
}

impl BackupActiveSeriesPointer {
    pub fn series_id(&self) -> Option<&BackupSeriesId> {
        match self {
            Self::Absent {} => None,
            Self::Active {
                active_series_id, ..
            } => Some(active_series_id),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupActiveSeriesState {
    pub account_id: AccountId,
    pub control_realm_id: arkret_wire::RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit_ref: Option<CommittedEventRef>,
    pub secret_storage: BackupActiveSeriesPointer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupSummaryEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupSummary {
    pub backup_id: BackupId,
    pub actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_kind: BackupKind,
    pub backup_version: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub ciphertext_digest: Hash,
    pub encryption: KeyBackupSummaryEncryption,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsList {
    pub backups: Vec<KeyBackupSummary>,
    pub active_series: BackupActiveSeriesState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueUnlockChallengeRequestBody {
    pub request_id: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsUnlockChallenge {
    pub challenge_id: Base64UrlString,
    pub challenge: Base64UrlString,
    pub nonce: Base64UrlString,
    pub operation: String,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub backup_id: BackupId,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
    pub audience: NonEmptyString,
    pub service_id: DidCoreId,
    pub request_id: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyBackupUnlockAuthority {
    CurrentDevice {
        challenge_id: Base64UrlString,
        nonce: Base64UrlString,
    },
    RecoverySession {
        recovery_session_id: RecoverySessionId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockProofAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockProof {
    pub schema: String,
    #[serde(flatten)]
    pub authority: KeyBackupUnlockAuthority,
    pub account_id: AccountId,
    pub requesting_device_id: DeviceId,
    pub backup_id: BackupId,
    pub backup_kind: BackupKind,
    pub series_id: BackupSeriesId,
    pub ciphertext_digest: Hash,
    pub challenge: Base64UrlString,
    pub service_id: DidCoreId,
    pub audience: NonEmptyString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub auth_data: KeyBackupUnlockProofAuthData,
}

impl KeyBackupUnlockProof {
    pub const SCHEMA: &'static str = arkret_wire::SchemaId::KEY_BACKUP_UNLOCK_PROOF_V1;

    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.schema != Self::SCHEMA
            || self.challenge.as_str().len() != 43
            || self.expires_at <= self.issued_at
            || self.service_id != self.account_id.station_id
            || self.auth_data.signature_algorithm == KeyBackupSignatureAlgorithm::Es256
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid exact backup unlock binding".to_owned(),
            ));
        }
        if let KeyBackupUnlockAuthority::CurrentDevice {
            challenge_id,
            nonce,
        } = &self.authority
            && (!(22..=128).contains(&challenge_id.as_str().len())
                || nonce.as_str().len() < 22
                || self.expires_at - self.issued_at > chrono::Duration::seconds(300))
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid current-device unlock freshness".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn signing_payload_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        self.validate()?;
        let mut unsigned = serde_json::to_value(self)?;
        unsigned
            .get_mut("auth_data")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| arkret_wire::WireError::Protocol("missing unlock auth_data".to_owned()))?
            .remove("signature");
        arkret_canonical::canonical_json_bytes(&unsigned).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsUnlockRequestBody {
    pub proof: KeyBackupUnlockProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupPutStatus {
    Accepted,
    Duplicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsReplaceOutcome {
    pub status: KeyBackupPutStatus,
    pub backup_id: BackupId,
    pub ciphertext_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyBackupDeleteProof {
    CurrentDevice {
        proof: PayloadProof,
    },
    RecoverySession {
        recovery_session_id: RecoverySessionId,
        proof: PayloadProof,
    },
    DeviceQuorum {
        threshold: u32,
        signatures: Vec<KeyBackupDeleteQuorumSignature>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupDeleteQuorumSignature {
    pub device_id: DeviceId,
    pub proof: PayloadProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueDeleteChallengeRequestBody {
    pub request_id: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteChallenge {
    pub challenge_id: Base64UrlString,
    pub challenge: Base64UrlString,
    pub nonce: Base64UrlString,
    pub operation: String,
    pub account_id: AccountId,
    pub backup_id: BackupId,
    pub audience: NonEmptyString,
    pub service_id: DidCoreId,
    pub request_id: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteRequestBody {
    pub request_id: Base64UrlString,
    pub challenge_id: Base64UrlString,
    pub proof: KeyBackupDeleteProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteOutcome {
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<BackupId>,
}
