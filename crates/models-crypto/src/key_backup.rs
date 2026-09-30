//! End-to-end encrypted `secret_storage` backup models.
//!
//! Backup records are bound to current authority commits and local encryption
//! material; they do not carry producer ordering coordinates.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, BackupId, BackupSeriesId, Base64UrlString, DeviceId, DidUrl, EventId,
    HPKE_SUITE_X25519_CHACHA20POLY1305_V1, HPKE_SUITES, Hash, RealmCommitId, ReasonCode, Result,
    SchemaId, WireError, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::RecoveryPolicyRef;

fn is_false(value: &bool) -> bool {
    !*value
}

fn serialize_nonempty_contents<S>(
    contents: &[SecretStorageContentIndex],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if contents.is_empty() {
        return Err(S::Error::custom("key backup contents must be non-empty"));
    }
    contents.serialize(serializer)
}

fn deserialize_nonempty_contents<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<SecretStorageContentIndex>, D::Error>
where
    D: Deserializer<'de>,
{
    let contents = Vec::<SecretStorageContentIndex>::deserialize(deserializer)?;
    if contents.is_empty() {
        return Err(D::Error::custom("key backup contents must be non-empty"));
    }
    Ok(contents)
}

/// The only backup class in the authority-commit core.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupKind {
    SecretStorage,
}

impl BackupKind {
    pub const fn as_str(self) -> &'static str {
        "secret_storage"
    }
    pub fn hkdf_info(self, subdomain: &str) -> String {
        format!("arkret-key-backup/secret_storage/{subdomain}/v1")
    }
}

impl TryFrom<&str> for BackupKind {
    type Error = String;
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "secret_storage" => Ok(Self::SecretStorage),
            other => Err(format!("unsupported backup_kind {other}")),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupSourceCommitRef {
    pub realm_commit_id: RealmCommitId,
    pub device_generation_ref: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackup {
    pub backup_id: BackupId,
    pub actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_kind: BackupKind,
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_secret_storage: bool,
    pub backup_version: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    pub encryption: KeyBackupEncryption,
    pub domain_separation: KeyBackupDomainSeparation,
    #[serde(
        serialize_with = "serialize_nonempty_contents",
        deserialize_with = "deserialize_nonempty_contents"
    )]
    pub contents: Vec<SecretStorageContentIndex>,
    pub ciphertext: Base64UrlString,
    pub ciphertext_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_commitment: Option<Hash>,
    pub auth_data: KeyBackupAuthData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<KeyBackupRetention>,
    pub series_id: BackupSeriesId,
    pub series_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_id: Option<BackupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit_ref: Option<KeyBackupSourceCommitRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl KeyBackup {
    pub const SCHEMA: &'static str = SchemaId::KEY_BACKUP_V1;

    pub fn validate(&self) -> Result<()> {
        if self.contents.is_empty() {
            return protocol("key backup contents must be non-empty");
        }
        if !self.backup_version.starts_with("kb_") || self.backup_version.len() < 4 {
            return protocol("key backup backup_version must use the kb_ profile");
        }
        match self.series_seq {
            0 if self.supersedes_id.is_some() || self.supersedes_digest.is_some() => {
                return protocol("key backup genesis must not carry supersession fields");
            }
            1.. if self.supersedes_id.is_none() || self.supersedes_digest.is_none() => {
                return protocol("key backup successor requires prior backup id and digest");
            }
            _ => {}
        }
        if self
            .source_commit_ref
            .as_ref()
            .is_some_and(|source| source.device_generation_ref == 0)
        {
            return protocol("key backup source_commit_ref generation must be positive");
        }
        if self
            .recovery_policy_ref
            .as_ref()
            .is_some_and(|reference| reference.policy_version == 0)
        {
            return protocol("key backup recovery_policy_ref version must be positive");
        }
        if self.encryption.recipient_method == KeyBackupRecipientMethod::RecoveryPublicKey
            && self.recovery_policy_ref.is_none()
        {
            return protocol("recovery_public_key key backup requires recovery_policy_ref");
        }
        if self
            .device_id
            .as_ref()
            .is_some_and(|id| id != &self.auth_data.device_id)
        {
            return protocol("key backup signer device does not match device_id");
        }
        if self.auth_data.signature_algorithm == KeyBackupSignatureAlgorithm::Es256 {
            return protocol("ES256 is not an active key backup signature algorithm");
        }
        if self
            .expires_at
            .is_some_and(|expires| expires <= self.created_at)
            || self
                .updated_at
                .is_some_and(|updated| updated < self.created_at)
        {
            return protocol("key backup timestamps are inconsistent");
        }
        self.encryption.validate()?;
        self.domain_separation.validate()?;
        for item in &self.contents {
            item.validate()?;
        }
        Ok(())
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value
            .get_mut("auth_data")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| WireError::Protocol("missing key backup auth_data".to_owned()))?
            .remove("signature");
        Ok(arkret_canonical::canonical_json_bytes(&value)?)
    }
}

#[cfg(test)]
mod key_backup_extension_tests {
    use serde_json::{Value, json};

    use super::KeyBackup;

    #[test]
    fn envelope_accepts_only_registered_extension_keys() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../arkret-spec/spec/v1/artifacts/fixtures/key-backup-hardening-fixture.json"
        ))
        .unwrap();
        let mut envelope = fixture["cases"][1]["envelope"].clone();
        envelope["x_vendor_hint"] = json!({"display_only": true});
        let backup: KeyBackup = serde_json::from_value(envelope.clone()).unwrap();
        assert_eq!(serde_json::to_value(backup).unwrap(), envelope);

        for key in ["vendor_hint", "x_Vendor", "x_"] {
            let mut invalid = envelope.clone();
            invalid.as_object_mut().unwrap().remove("x_vendor_hint");
            invalid[key] = json!(true);
            assert!(
                serde_json::from_value::<KeyBackup>(invalid).is_err(),
                "{key}"
            );
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupRecipientMethod {
    PassphraseKdf,
    RecoveryPublicKey,
    SecretStorageKey,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpke_suite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KeyBackupKdf>,
    pub aead: KeyBackupAead,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<Hash>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl KeyBackupEncryption {
    pub fn validate(&self) -> Result<()> {
        self.aead
            .validate_aead_profile()
            .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
        match self.recipient_method {
            KeyBackupRecipientMethod::PassphraseKdf => {
                let Some(kdf) = &self.kdf else {
                    return protocol("passphrase_kdf requires kdf");
                };
                kdf.validate().map_err(WireError::Protocol)?;
                if self.recipient_key_ref.is_some()
                    || self.hpke_suite.is_some()
                    || self.aead.nonce.is_none()
                    || self.aead.nonce_salt.is_none()
                    || self.aead.name != KeyBackupAeadName::Xchacha20Poly1305
                    || self.key_commitment.is_none()
                    || self
                        .key_commitment
                        .as_ref()
                        .is_some_and(|hash| !hash.as_str().starts_with("sha256:"))
                {
                    return protocol("passphrase_kdf has inconsistent encryption fields");
                }
                if self.aead.nonce.as_ref().is_none_or(|nonce| {
                    arkret_canonical::base64url_decode(nonce.as_str()).map_or(true, |bytes| {
                        bytes.len() != 24
                            || arkret_canonical::base64url_encode(&bytes) != nonce.as_str()
                    })
                }) || self.aead.nonce_salt.as_ref().is_none_or(|salt| {
                    arkret_canonical::base64url_decode(salt.as_str()).map_or(true, |bytes| {
                        bytes.len() < 16
                            || arkret_canonical::base64url_encode(&bytes) != salt.as_str()
                    })
                }) {
                    return protocol("passphrase_kdf nonce length is invalid");
                }
            }
            KeyBackupRecipientMethod::SecretStorageKey => {
                if self.kdf.is_some()
                    || self.hpke_suite.is_some()
                    || self.recipient_key_ref.as_deref().is_none_or(str::is_empty)
                    || self.aead.nonce.is_none()
                {
                    return protocol("secret_storage_key has inconsistent encryption fields");
                }
            }
            KeyBackupRecipientMethod::RecoveryPublicKey => {
                if self.kdf.is_some()
                    || self.recipient_key_ref.as_deref().is_none_or(str::is_empty)
                    || self.aead.enc.is_none()
                {
                    return protocol("recovery_public_key has inconsistent encryption fields");
                }
                let suite = self
                    .hpke_suite
                    .as_deref()
                    .unwrap_or(HPKE_SUITE_X25519_CHACHA20POLY1305_V1);
                if !HPKE_SUITES
                    .iter()
                    .any(|row| row.canonical_id == suite && row.status == "active")
                {
                    return protocol("unsupported key backup HPKE suite");
                }
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupDomainSeparation {
    pub subdomain: String,
    #[serde(default, skip_serializing_if = "XExtensionMap::is_empty")]
    pub aead_aad_extensions: XExtensionMap,
}

impl KeyBackupDomainSeparation {
    pub fn validate(&self) -> Result<()> {
        if self.subdomain.is_empty()
            || self.subdomain.len() > 64
            || !self.subdomain.bytes().enumerate().all(|(i, b)| {
                b.is_ascii_lowercase() || (i > 0 && (b.is_ascii_digit() || b == b'_'))
            })
        {
            return protocol("invalid key backup subdomain");
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupKdfName {
    Argon2id,
    Pbkdf2,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyBackupKdfDigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupKdfParams {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_kdf_parameter"
    )]
    pub memory_kib: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_kdf_parameter"
    )]
    pub iterations: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_kdf_parameter"
    )]
    pub parallelism: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_kdf_parameter"
    )]
    pub digest_algorithm: Option<KeyBackupKdfDigestAlgorithm>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

fn deserialize_present_kdf_parameter<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod kdf_parameter_tests {
    use super::*;

    #[test]
    fn argon2_parameters_preserve_absent_digest_in_the_signed_value() {
        let value = serde_json::json!({"memory_kib": 65536, "iterations": 3, "parallelism": 1});
        let params: KeyBackupKdfParams = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(params).unwrap(), value);
    }

    #[test]
    fn pbkdf2_parameters_do_not_emit_argon2_null_members() {
        let value = serde_json::json!({"iterations": 600000, "digest_algorithm": "sha256"});
        let params: KeyBackupKdfParams = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(params).unwrap(), value);
    }

    #[test]
    fn explicit_null_parameters_are_rejected_before_signature_verification() {
        for member in [
            "memory_kib",
            "iterations",
            "parallelism",
            "digest_algorithm",
        ] {
            let mut value = serde_json::json!({});
            value[member] = Value::Null;
            assert!(
                serde_json::from_value::<KeyBackupKdfParams>(value).is_err(),
                "{member}"
            );
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupKdf {
    pub name: KeyBackupKdfName,
    pub salt: Base64UrlString,
    #[serde(default)]
    pub params: KeyBackupKdfParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_profile_reason: Option<String>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl KeyBackupKdf {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if arkret_canonical::base64url_decode(self.salt.as_str()).map_or(true, |bytes| {
            bytes.len() != 16 || arkret_canonical::base64url_encode(&bytes) != self.salt.as_str()
        }) {
            return Err("passphrase KDF salt must be exactly 16 bytes".to_owned());
        }
        match self.name {
            KeyBackupKdfName::Argon2id
                if self.params.memory_kib.is_none_or(|v| v < 65_536)
                    || self.params.iterations.is_none_or(|v| v < 3)
                    || self.params.parallelism.is_none_or(|v| v < 1) =>
            {
                Err("argon2id parameters are below the v1 floor".to_owned())
            }
            KeyBackupKdfName::Argon2id
                if self.params.digest_algorithm.is_some()
                    || self.degraded_profile_reason.is_some() =>
            {
                Err("argon2id has PBKDF2-only fields".to_owned())
            }
            KeyBackupKdfName::Pbkdf2
                if self.params.iterations.is_none_or(|v| v < 600_000)
                    || self.params.digest_algorithm.is_none()
                    || self
                        .degraded_profile_reason
                        .as_deref()
                        .is_none_or(str::is_empty) =>
            {
                Err("pbkdf2 requires the degraded profile floor and reason".to_owned())
            }
            KeyBackupKdfName::Pbkdf2
                if self.params.memory_kib.is_some() || self.params.parallelism.is_some() =>
            {
                Err("pbkdf2 has Argon2id-only parameters".to_owned())
            }
            _ => Ok(()),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupAeadName {
    Xchacha20Poly1305,
    Aes256Gcm,
    Chacha20Poly1305,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupAead {
    #[serde(rename = "name")]
    pub name: KeyBackupAeadName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_salt: Option<Base64UrlString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Base64UrlString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<Base64UrlString>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl KeyBackupAead {
    pub fn validate_aead_profile(&self) -> std::result::Result<(), &'static str> {
        let Some(profile) = self.aead_profile.as_deref() else {
            return Ok(());
        };
        let expected = match arkret_wire::AeadProfileId::from_wire(profile)
            .ok_or(ReasonCode::UNSUPPORTED_AEAD_PROFILE)?
        {
            arkret_wire::AeadProfileId::Chacha20Poly1305V1 => KeyBackupAeadName::Chacha20Poly1305,
            arkret_wire::AeadProfileId::Xchacha20Poly1305V1 => KeyBackupAeadName::Xchacha20Poly1305,
        };
        (expected == self.name)
            .then_some(())
            .ok_or(ReasonCode::UNSUPPORTED_AEAD_PROFILE)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStorageItemKind {
    RecoveryKeyShare,
    AccountDataNamespaceKey,
    MlsAccountSecret,
    MlsPrivatePlaintext,
    MlsGroupSecretsBackupKey,
    PrivateAccountState,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretStorageContentIndex {
    pub item_kind: SecretStorageItemKind,
    pub secret_id: String,
}

impl SecretStorageContentIndex {
    pub fn validate(&self) -> Result<()> {
        if self.secret_id.is_empty()
            || !self
                .secret_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return protocol("secret storage content secret_id is invalid");
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupAuthData {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub device_authorize_event_id: EventId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyBackupSignatureAlgorithm {
    Ed25519,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupRetention {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub delete_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
    #[serde(default, flatten)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

fn protocol<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(message.to_owned()))
}
