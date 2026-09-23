//! Typed request and response models for the encrypted key-backup service.

use arkret_wire::{
    AccountId, ActorId, AuditReasonText, BackupId, BackupSeriesId, Base64UrlString,
    CommittedEventRef, Cursor, DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, PayloadProof,
    RecoverySessionId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupActiveSeriesState {
    pub account_id: AccountId,
    pub control_realm_id: arkret_wire::RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit_ref: Option<CommittedEventRef>,
    pub secret_storage: BackupActiveSeriesPointer,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupSummaryEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsList {
    pub backups: Vec<KeyBackupSummary>,
    pub active_series: BackupActiveSeriesState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueUnlockChallengeRequestBody {
    pub request_id: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockProofAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
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

#[derive(Deserialize)]
struct KeyBackupUnlockProofFields {
    schema: String,
    #[serde(flatten)]
    authority: KeyBackupUnlockAuthority,
    account_id: AccountId,
    requesting_device_id: DeviceId,
    backup_id: BackupId,
    backup_kind: BackupKind,
    series_id: BackupSeriesId,
    ciphertext_digest: Hash,
    challenge: Base64UrlString,
    service_id: DidCoreId,
    audience: NonEmptyString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    auth_data: KeyBackupUnlockProofAuthData,
}

impl<'de> Deserialize<'de> for KeyBackupUnlockProof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("unlock proof must be an object"))?;
        const FIELDS: &[&str] = &[
            "schema",
            "kind",
            "challenge_id",
            "nonce",
            "recovery_session_id",
            "account_id",
            "requesting_device_id",
            "backup_id",
            "backup_kind",
            "series_id",
            "ciphertext_digest",
            "challenge",
            "service_id",
            "audience",
            "issued_at",
            "expires_at",
            "auth_data",
        ];
        if let Some(key) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
            return Err(D::Error::custom(format!(
                "unknown unlock proof field {key}"
            )));
        }
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("current_device")
                if object.contains_key("challenge_id")
                    && object.contains_key("nonce")
                    && !object.contains_key("recovery_session_id") => {}
            Some("recovery_session")
                if object.contains_key("recovery_session_id")
                    && !object.contains_key("challenge_id")
                    && !object.contains_key("nonce") => {}
            _ => {
                return Err(D::Error::custom(
                    "unlock proof authority branch is incomplete or mixed",
                ));
            }
        }
        let fields: KeyBackupUnlockProofFields =
            serde_json::from_value(value).map_err(D::Error::custom)?;
        let proof = Self {
            schema: fields.schema,
            authority: fields.authority,
            account_id: fields.account_id,
            requesting_device_id: fields.requesting_device_id,
            backup_id: fields.backup_id,
            backup_kind: fields.backup_kind,
            series_id: fields.series_id,
            ciphertext_digest: fields.ciphertext_digest,
            challenge: fields.challenge,
            service_id: fields.service_id,
            audience: fields.audience,
            issued_at: fields.issued_at,
            expires_at: fields.expires_at,
            auth_data: fields.auth_data,
        };
        proof.validate().map_err(D::Error::custom)?;
        Ok(proof)
    }
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsUnlockRequestBody {
    pub proof: KeyBackupUnlockProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupPutStatus {
    Accepted,
    Duplicate,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueDeleteChallengeRequestBody {
    pub request_id: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteOutcome {
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<BackupId>,
}

#[cfg(test)]
mod unlock_proof_wire_tests {
    use serde_json::{Value, json};

    use super::*;

    fn proof() -> Value {
        json!({
            "schema": KeyBackupUnlockProof::SCHEMA,
            "kind": "current_device",
            "challenge_id": "AAAAAAAAAAAAAAAAAAAAAA",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "requesting_device_id": "ak:device:0196419b-0000-7000-8000-000000000003",
            "backup_id": "ak:backup:0196419b-0000-7000-8000-000000000001",
            "backup_kind": "secret_storage",
            "series_id": "ak:backup_series:0196419b-0000-7000-8000-000000000002",
            "ciphertext_digest": format!("sha256:{}", "aa".repeat(32)),
            "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "service_id": "ak:did_core:web:station.example",
            "audience": "https://station.example",
            "issued_at": "2026-09-23T00:00:00.000Z",
            "expires_at": "2026-09-23T00:05:00.000Z",
            "auth_data": {
                "verification_method": "did:web:alice.example#key-1",
                "signature_algorithm": "Ed25519",
                "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        })
    }

    #[test]
    fn flattened_authority_round_trips_without_losing_signed_fields() {
        let value = proof();
        let parsed: KeyBackupUnlockProof = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);

        let mut recovery = proof();
        recovery["kind"] = json!("recovery_session");
        recovery.as_object_mut().unwrap().remove("challenge_id");
        recovery.as_object_mut().unwrap().remove("nonce");
        recovery["recovery_session_id"] =
            json!("ak:recovery_session:0198ff00-0000-7000-8000-00000000000c");
        let parsed: KeyBackupUnlockProof = serde_json::from_value(recovery.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), recovery);
    }

    #[test]
    fn closed_authority_rejects_unknown_mixed_and_missing_fields() {
        let mut unknown = proof();
        unknown["unregistered"] = json!(true);
        assert!(serde_json::from_value::<KeyBackupUnlockProof>(unknown).is_err());

        let mut mixed = proof();
        mixed["recovery_session_id"] =
            json!("ak:recovery_session:0198ff00-0000-7000-8000-00000000000c");
        assert!(serde_json::from_value::<KeyBackupUnlockProof>(mixed).is_err());

        let mut missing = proof();
        missing.as_object_mut().unwrap().remove("nonce");
        assert!(serde_json::from_value::<KeyBackupUnlockProof>(missing).is_err());
    }
}
