//! Typed request and response models for the encrypted key-backup service.

use arkret_wire::{
    AccountId, ActorId, AuditReasonText, BackupId, BackupSeriesId, Base64UrlString, Cursor,
    DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, RealmCommitId, RecoverySessionId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{BackupKind, KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm};

pub(crate) fn is_canonical_backup_challenge(value: &Base64UrlString) -> bool {
    let encoded = value.as_str();
    encoded.len() == 43
        && arkret_canonical::base64url_decode(encoded).is_ok_and(|bytes| {
            bytes.len() == 32 && arkret_canonical::base64url_encode(&bytes) == encoded
        })
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupsListQuery {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_id: Option<BackupSeriesId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_kind: Option<BackupKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `keys-operations.schema.json#/$defs/backup_active_series_pointer`: the
/// closed `absent` / `active` branches of one accepted backup-class pointer.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupActiveSeriesPointer {
    Absent {},
    Active {
        active_series_id: BackupSeriesId,
        /// Schema `minimum: 1`; version 0 never names an accepted pointer.
        #[serde(deserialize_with = "deserialize_series_pointer_version")]
        series_pointer_version: u64,
    },
}

fn deserialize_series_pointer_version<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u64::deserialize(deserializer)?;
    if version == 0 {
        return Err(serde::de::Error::custom(
            "series_pointer_version must be at least 1",
        ));
    }
    Ok(version)
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

#[cfg(test)]
mod active_series_state_tests {
    use serde_json::{Value, json};

    use super::BackupActiveSeriesState;

    fn state() -> Value {
        json!({
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "control_realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "authority_commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "secret_storage": {"state": "absent"}
        })
    }

    #[test]
    fn active_series_state_has_the_closed_confirmed_basis_shape() {
        let value = state();
        let parsed: BackupActiveSeriesState = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);

        for member in [
            "account_id",
            "control_realm_id",
            "authority_commit_id",
            "secret_storage",
        ] {
            let mut missing = state();
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<BackupActiveSeriesState>(missing).is_err(),
                "{member}"
            );
        }

        let mut old_alias = state();
        old_alias
            .as_object_mut()
            .unwrap()
            .remove("authority_commit_id");
        old_alias["source_commit_ref"] = json!({"realm_commit_id": value["authority_commit_id"]});
        assert!(serde_json::from_value::<BackupActiveSeriesState>(old_alias).is_err());

        let mut unknown = state();
        unknown["unregistered"] = json!(true);
        assert!(serde_json::from_value::<BackupActiveSeriesState>(unknown).is_err());

        let mut wrong_id = state();
        wrong_id["authority_commit_id"] =
            json!("ak:event:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4");
        assert!(serde_json::from_value::<BackupActiveSeriesState>(wrong_id).is_err());
    }

    #[test]
    fn secret_storage_is_the_only_backup_class() {
        let absent = json!({"state": "absent"});
        let active = json!({
            "state": "active",
            "active_series_id": "ak:backup_series:01964137-1000-7000-8000-000000000000",
            "series_pointer_version": 1
        });
        for pointer in [&absent, &active] {
            let mut accepted = state();
            accepted["secret_storage"] = pointer.clone();
            let parsed: BackupActiveSeriesState = serde_json::from_value(accepted.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), accepted);

            for class in ["mls_history", "org_example_private", "x-private"] {
                let mut extra_class = accepted.clone();
                extra_class[class] = pointer.clone();
                assert!(
                    serde_json::from_value::<BackupActiveSeriesState>(extra_class).is_err(),
                    "{class}"
                );
            }

            let mut renamed = accepted.clone();
            let moved = renamed
                .as_object_mut()
                .unwrap()
                .remove("secret_storage")
                .unwrap();
            renamed["mls_history"] = moved;
            assert!(serde_json::from_value::<BackupActiveSeriesState>(renamed).is_err());
        }

        let mut null_pointer = state();
        null_pointer["secret_storage"] = json!(null);
        assert!(serde_json::from_value::<BackupActiveSeriesState>(null_pointer).is_err());
    }

    #[test]
    fn pointer_branches_are_closed() {
        let parse =
            |pointer: Value| serde_json::from_value::<super::BackupActiveSeriesPointer>(pointer);
        let series = "ak:backup_series:01964137-1000-7000-8000-000000000000";
        assert!(parse(json!({"state": "absent"})).is_ok());
        assert!(
            parse(json!({
                "state": "active", "active_series_id": series, "series_pointer_version": 1
            }))
            .is_ok()
        );
        for rejected in [
            json!({}),
            json!({"state": "unknown"}),
            json!({"state": "absent", "active_series_id": series}),
            json!({"state": "active", "active_series_id": series}),
            json!({"state": "active", "series_pointer_version": 1}),
            json!({"state": "active", "active_series_id": series, "series_pointer_version": 0}),
            json!({"state": "active", "active_series_id": series, "series_pointer_version": -1}),
            json!({
                "state": "active", "active_series_id": series, "series_pointer_version": 1,
                "backup_kind": "secret_storage"
            }),
        ] {
            assert!(parse(rejected.clone()).is_err(), "{rejected}");
        }
    }
}

// A present optional member must carry a value: `null` is schema-invalid.

/// A present tristate member is either `null` or a value.
fn deserialize_present_nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

fn deserialize_present_timestamp<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    arkret_canonical::serde_helpers::deserialize_canonical_timestamp(deserializer).map(Some)
}

fn deserialize_tristate_canonical_timestamp<'de, D>(
    deserializer: D,
) -> Result<Option<Option<DateTime<Utc>>>, D::Error>
where
    D: Deserializer<'de>,
{
    arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp(deserializer)
        .map(Some)
}

fn serialize_tristate_canonical_timestamp<S>(
    value: &Option<Option<DateTime<Utc>>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp(
        &value.flatten(),
        serializer,
    )
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueUnlockChallengeRequestBody {
    pub request_id: Base64UrlString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub subject_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub custody_authorization_ref: Option<arkret_wire::EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub content_history: Option<crate::ContentHistoryBackupAccess>,
}

impl KeysBackupsIssueUnlockChallengeRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if !(22..=128).contains(&self.request_id.as_str().len())
            || self.subject_actor_id.is_some() != self.custody_authorization_ref.is_some()
            || self
                .subject_actor_id
                .as_ref()
                .is_some_and(|actor| actor.as_account_id().is_none())
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid unlock challenge request subject or idempotency binding".into(),
            ));
        }
        if let Some(history) = &self.content_history {
            history.validate()?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsUnlockChallenge {
    pub challenge_id: Base64UrlString,
    pub challenge: Base64UrlString,
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub subject_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub custody_authorization_ref: Option<arkret_wire::EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub content_history: Option<crate::ContentHistoryBackupAccess>,
}

impl KeysBackupsUnlockChallenge {
    pub fn validate_at(&self, now: DateTime<Utc>) -> arkret_wire::Result<()> {
        self.validate_for_request(&self.request_body(), &self.backup_id)?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(arkret_wire::WireError::Protocol(
                "backup unlock challenge is outside its server-issued window".into(),
            ));
        }
        Ok(())
    }

    /// Sign the complete received challenge projection, including immutable
    /// object/context bindings. No caller nonce or provisional signature enters
    /// the canonical proof bytes.
    pub fn sign_unlock_proof_at(
        &self,
        verification_method: DidUrl,
        now: DateTime<Utc>,
        sign: impl FnOnce(&[u8]) -> arkret_wire::Result<Vec<u8>>,
    ) -> arkret_wire::Result<KeyBackupUnlockProof> {
        self.validate_at(now)?;
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or_else(|| {
            arkret_wire::WireError::Protocol("challenge must be an object".into())
        })?;
        object.remove("operation");
        object.remove("request_id");
        object.insert(
            "schema".into(),
            serde_json::json!(KeyBackupUnlockProof::SCHEMA),
        );
        object.insert("kind".into(), serde_json::json!("current_device"));
        object.insert("backup_kind".into(), serde_json::json!("secret_storage"));
        object.insert("signature_proof".into(), serde_json::json!({"verification_method":verification_method,"signature_algorithm":"Ed25519"}));
        let signature = sign(&arkret_canonical::canonical_json_bytes(&value)?)?;
        if signature.len() != 64 {
            return Err(arkret_wire::WireError::Protocol(
                "backup unlock requires an actual Ed25519 signature".into(),
            ));
        }
        value["signature_proof"]["signature"] =
            serde_json::json!(arkret_canonical::base64url_encode(signature));
        serde_json::from_value(value).map_err(Into::into)
    }

    /// Recover the complete closed issuance request for durable idempotency.
    /// Fresh challenge bytes and issuance timestamps are server outputs.
    pub fn request_body(&self) -> KeysBackupsIssueUnlockChallengeRequestBody {
        KeysBackupsIssueUnlockChallengeRequestBody {
            request_id: self.request_id.clone(),
            subject_actor_id: self.subject_actor_id.clone(),
            custody_authorization_ref: self.custody_authorization_ref.clone(),
            content_history: self.content_history.clone(),
        }
    }

    pub fn validate_for_request(
        &self,
        request: &KeysBackupsIssueUnlockChallengeRequestBody,
        backup_id: &BackupId,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        if self.request_id != request.request_id
            || &self.backup_id != backup_id
            || self.subject_actor_id != request.subject_actor_id
            || self.custody_authorization_ref != request.custody_authorization_ref
            || self.content_history != request.content_history
            || self.operation
                != arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1
            || self.service_id != self.account_id.station_id
            || !is_canonical_backup_challenge(&self.challenge)
            || !(22..=128).contains(&self.challenge_id.as_str().len())
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::seconds(300)
        {
            return Err(arkret_wire::WireError::Protocol(
                "unlock challenge differs from exact request or freshness binding".into(),
            ));
        }
        if let Some(subject) = &self.subject_actor_id {
            let account = subject.as_account_id().ok_or_else(|| {
                arkret_wire::WireError::Protocol("custody subject must be an Account".into())
            })?;
            if account == &self.account_id || account.station_id != self.account_id.station_id {
                return Err(arkret_wire::WireError::Protocol(
                    "custody subject must be a distinct same-Station Account".into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyBackupUnlockAuthority {
    CurrentDevice {
        challenge_id: Base64UrlString,
    },
    RecoverySession {
        recovery_session_id: RecoverySessionId,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupUnlockSignatureProof {
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
    pub signature_proof: KeyBackupUnlockSignatureProof,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub subject_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub custody_authorization_ref: Option<arkret_wire::EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub content_history: Option<crate::ContentHistoryBackupAccess>,
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
    signature_proof: KeyBackupUnlockSignatureProof,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    subject_actor_id: Option<ActorId>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    custody_authorization_ref: Option<arkret_wire::EventId>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    content_history: Option<crate::ContentHistoryBackupAccess>,
}

impl<'de> Deserialize<'de> for KeyBackupUnlockProof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("unlock proof must be an object"))?;
        const FIELDS: &[&str] = &[
            "subject_actor_id",
            "custody_authorization_ref",
            "content_history",
            "schema",
            "kind",
            "challenge_id",
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
            "signature_proof",
        ];
        if let Some(key) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
            return Err(D::Error::custom(format!(
                "unknown unlock proof field {key}"
            )));
        }
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("current_device")
                if object.contains_key("challenge_id")
                    && !object.contains_key("recovery_session_id") => {}
            Some("recovery_session")
                if object.contains_key("recovery_session_id")
                    && !object.contains_key("challenge_id") => {}
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
            signature_proof: fields.signature_proof,
            subject_actor_id: fields.subject_actor_id,
            custody_authorization_ref: fields.custody_authorization_ref,
            content_history: fields.content_history,
        };
        proof.validate().map_err(D::Error::custom)?;
        Ok(proof)
    }
}

impl KeyBackupUnlockProof {
    pub const SCHEMA: &'static str = arkret_wire::SchemaId::KEY_BACKUP_UNLOCK_PROOF_V1;

    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.subject_actor_id.is_some() != self.custody_authorization_ref.is_some()
            || matches!(
                self.authority,
                KeyBackupUnlockAuthority::RecoverySession { .. }
            ) && (self.subject_actor_id.is_some() || self.content_history.is_some())
        {
            return Err(arkret_wire::WireError::Protocol(
                "unlock history/custody requires exact current-device authority".to_owned(),
            ));
        }
        if let Some(history) = &self.content_history {
            history.validate()?;
        }
        if self.schema != Self::SCHEMA
            || !is_canonical_backup_challenge(&self.challenge)
            || self.expires_at <= self.issued_at
            || self.service_id != self.account_id.station_id
            || self.signature_proof.signature_algorithm == KeyBackupSignatureAlgorithm::Es256
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid exact backup unlock binding".to_owned(),
            ));
        }
        if let KeyBackupUnlockAuthority::CurrentDevice { challenge_id } = &self.authority
            && (!(22..=128).contains(&challenge_id.as_str().len())
                || self.expires_at - self.issued_at > chrono::Duration::seconds(300))
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid current-device unlock freshness".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_challenge(
        &self,
        challenge: &KeysBackupsUnlockChallenge,
    ) -> arkret_wire::Result<()> {
        self.validate()?;
        challenge.validate_for_request(&challenge.request_body(), &challenge.backup_id)?;
        if !matches!(&self.authority, KeyBackupUnlockAuthority::CurrentDevice { challenge_id } if challenge_id == &challenge.challenge_id)
        {
            return Err(arkret_wire::WireError::Protocol(
                "unlock proof uses another challenge authority".into(),
            ));
        }
        let proof = serde_json::to_value(self)?;
        let source = serde_json::to_value(challenge)?;
        for (name, value) in source
            .as_object()
            .ok_or_else(|| arkret_wire::WireError::Protocol("challenge must be an object".into()))?
        {
            if name != "operation" && name != "request_id" && proof.get(name) != Some(value) {
                return Err(arkret_wire::WireError::Protocol(format!(
                    "unlock proof changed issued challenge member {name}"
                )));
            }
        }
        Ok(())
    }

    pub fn signing_payload_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        self.validate()?;
        let mut unsigned = serde_json::to_value(self)?;
        unsigned
            .get_mut("signature_proof")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol("missing unlock signature_proof".to_owned())
            })?
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
pub struct KeysBackupsReplaceResponseBody {
    pub status: KeyBackupPutStatus,
    pub backup_id: BackupId,
    pub ciphertext_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsIssueDeleteChallengeRequestBody {
    pub request_id: Base64UrlString,
}

impl KeysBackupsIssueDeleteChallengeRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if !(22..=128).contains(&self.request_id.as_str().len()) {
            return Err(arkret_wire::WireError::Protocol(
                "backup delete request_id must contain 22 to 128 base64url characters".into(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteChallenge {
    pub challenge_id: Base64UrlString,
    pub challenge: Base64UrlString,
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

impl KeysBackupsDeleteChallenge {
    pub fn validate_for_request(
        &self,
        request: &KeysBackupsIssueDeleteChallengeRequestBody,
        backup_id: &BackupId,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id || self.backup_id != *backup_id {
            return Err(arkret_wire::WireError::Protocol(
                "delete challenge differs from its exact issuance request/backup".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> arkret_wire::Result<()> {
        self.validate()?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(arkret_wire::WireError::Protocol(
                "backup delete challenge is outside its server-issued window".into(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.operation != arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE_V1
            || self.service_id != self.account_id.station_id
            || !is_canonical_backup_challenge(&self.challenge)
            || !(22..=128).contains(&self.challenge_id.as_str().len())
            || !(22..=128).contains(&self.request_id.as_str().len())
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::seconds(300)
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid exact backup delete challenge binding".into(),
            ));
        }
        Ok(())
    }

    /// The single signed transcript for every high-risk backup-delete proof
    /// branch (key-management.md §7.8.1). A missing reason is an explicit null.
    pub fn delete_intent_transcript(&self, reason: Option<&str>) -> serde_json::Value {
        let mut transcript = serde_json::to_value(self)
            .expect("typed backup-delete challenge always serializes")
            .as_object()
            .expect("backup-delete challenge serializes as an object")
            .clone();
        transcript.insert(
            "context".to_owned(),
            serde_json::Value::String(
                arkret_wire::ProofContextId::KEY_BACKUP_DELETE_PROOF_V1.to_owned(),
            ),
        );
        transcript.insert(
            "reason".to_owned(),
            reason.map_or(serde_json::Value::Null, |value| {
                serde_json::Value::String(value.to_owned())
            }),
        );
        serde_json::Value::Object(transcript)
    }

    pub fn delete_intent_digest(&self, reason: Option<&str>) -> arkret_wire::Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical_sha256(
            &self.delete_intent_transcript(reason),
        )?)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsDeleteRequestBody {
    pub request_id: Base64UrlString,
    pub challenge_id: Base64UrlString,
    pub proof: crate::HighRiskAuthorityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
}

impl KeysBackupsDeleteRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if !(22..=128).contains(&self.request_id.as_str().len()) {
            return Err(arkret_wire::WireError::Protocol(
                "backup delete request_id must contain 22 to 128 base64url characters".into(),
            ));
        }
        if !(22..=128).contains(&self.challenge_id.as_str().len()) {
            return Err(arkret_wire::WireError::Protocol(
                "backup delete challenge_id must contain 22 to 128 base64url characters".into(),
            ));
        }
        self.proof.validate_shape()
    }
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
            "signature_proof": {
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
        missing.as_object_mut().unwrap().remove("challenge_id");
        assert!(serde_json::from_value::<KeyBackupUnlockProof>(missing).is_err());

        let mut retired_nonce = proof();
        retired_nonce["nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAA");
        assert!(serde_json::from_value::<KeyBackupUnlockProof>(retired_nonce).is_err());

        for challenge in [
            "A".repeat(42),
            format!("{}B", "A".repeat(42)),
            format!("{}=", "A".repeat(43)),
        ] {
            let mut malformed = proof();
            malformed["challenge"] = json!(challenge);
            assert!(serde_json::from_value::<KeyBackupUnlockProof>(malformed).is_err());
        }
    }
}

include!("generated/key_backup_operations_contracts.rs");
