//! Key-operation artifacts and decrypted `secret_storage` keybags.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DeviceId, DidCoreId, DidUrl, EventId, Hash,
    KeypackageClaimId, NonEmptyString, ReasonCode, Result, WireError, XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{SecretStorageContentIndex, SecretStorageItemKind};

/// Decrypted payload of a `secret_storage` key-backup envelope.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupPlaintext {
    pub backup_kind: crate::BackupKind,
    pub items: Vec<SecretStorageSecret>,
}

impl KeyBackupPlaintext {
    pub fn validate_against(&self, contents: &[SecretStorageContentIndex]) -> Result<()> {
        if self.items.len() != contents.len() {
            return protocol("secret_storage keybag does not match its public content index");
        }
        for (secret, index) in self.items.iter().zip(contents) {
            secret.validate()?;
            if secret.item_kind != index.item_kind || index.secret_id != secret.secret_id {
                return protocol("secret_storage keybag metadata differs from its public index");
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretStorageSecret {
    pub item_kind: SecretStorageItemKind,
    pub secret_id: String,
    pub secret_b64u: Base64UrlString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_generation: Option<u64>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl SecretStorageSecret {
    pub fn validate(&self) -> Result<()> {
        if self.secret_id.is_empty()
            || !self
                .secret_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return protocol("secret_storage secret_id is invalid");
        }
        if self.secret_b64u.as_str().is_empty() {
            return protocol("secret_storage secret bytes must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod secret_storage_extension_tests {
    use serde_json::json;

    use super::SecretStorageSecret;

    #[test]
    fn secret_storage_item_accepts_only_registered_extension_keys() {
        let value = json!({
            "item_kind": "private_account_state",
            "secret_id": "account.state",
            "secret_b64u": "YQ",
            "secret_generation": 3,
            "x_vendor_hint": {"key": true}
        });
        let item: SecretStorageSecret = serde_json::from_value(value.clone()).unwrap();
        item.validate().unwrap();
        assert_eq!(serde_json::to_value(item).unwrap(), value);

        for key in ["vendor_hint", "x_Vendor", "x_"] {
            let mut invalid = value.clone();
            invalid.as_object_mut().unwrap().remove("x_vendor_hint");
            invalid[key] = json!(true);
            assert!(
                serde_json::from_value::<SecretStorageSecret>(invalid).is_err(),
                "{key}"
            );
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyOperationSignature {
    pub kid: NonEmptyString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub signature_algorithm: Option<NonEmptyString>,
    pub sig: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub keypackage_ref: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub device_id: Option<String>,
    pub reason_code: ReasonCode,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::http_bodies::deserialize_keypackage_positive_millis"
    )]
    pub retry_after_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize)]
pub struct KeyPackageClaimRecord {
    pub claim_id: String,
    pub keypackage_ref: String,
    pub actor_id: ActorId,
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_verification_method: Option<DidUrl>,
    pub keypackage: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_authorize_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPackageClaimRecordWire {
    claim_id: String,
    keypackage_ref: String,
    actor_id: ActorId,
    principal_id: DidCoreId,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_id: Option<DeviceId>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    agent_id: Option<DidCoreId>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    agent_verification_method: Option<DidUrl>,
    keypackage: String,
    capabilities: Vec<String>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    device_authorize_event_id: Option<EventId>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    agent_key_authorize_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    revocation_status: Option<String>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    last_resort: Option<bool>,
}

impl<'de> Deserialize<'de> for KeyPackageClaimRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyPackageClaimRecordWire::deserialize(deserializer)?;
        let record = Self {
            claim_id: wire.claim_id,
            keypackage_ref: wire.keypackage_ref,
            actor_id: wire.actor_id,
            principal_id: wire.principal_id,
            device_id: wire.device_id,
            agent_id: wire.agent_id,
            agent_verification_method: wire.agent_verification_method,
            keypackage: wire.keypackage,
            capabilities: wire.capabilities,
            device_authorize_event_id: wire.device_authorize_event_id,
            agent_key_authorize_event_id: wire.agent_key_authorize_event_id,
            expires_at: wire.expires_at,
            revocation_status: wire.revocation_status,
            last_resort: wire.last_resort,
        };
        record.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

impl KeyPackageClaimRecord {
    pub fn validate_shape(&self) -> std::result::Result<(), &'static str> {
        KeypackageClaimId::new(self.claim_id.clone())
            .map_err(|_| "claim_id must be a KeypackageClaimId")?;
        NonEmptyString::new(self.keypackage_ref.clone())?;
        Base64UrlString::new(self.keypackage.clone())?;
        self.actor_id
            .validate()
            .map_err(|_| "KeyPackage claim actor_id is invalid")?;
        let Some(account_id) = self.actor_id.as_account_id() else {
            return Err("KeyPackage claim actor_id must be an account ActorId");
        };
        if account_id.principal_id != self.principal_id {
            return Err("KeyPackage claim actor_id principal differs from principal_id");
        }
        let capabilities = self.capabilities.iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty()
            || capabilities.len() != self.capabilities.len()
            || self.capabilities.iter().any(String::is_empty)
        {
            return Err("claim capabilities must be non-empty and unique");
        }
        if self.revocation_status.as_deref().is_some_and(|s| {
            !matches!(
                s,
                "active" | "expired" | "revoked" | "principal_deactivated" | "device_revoked"
            )
        }) {
            return Err("claim revocation_status is not registered");
        }
        match (
            &self.device_id,
            &self.device_authorize_event_id,
            &self.agent_id,
            &self.agent_verification_method,
            &self.agent_key_authorize_event_id,
        ) {
            (Some(_), Some(_), None, None, None) => Ok(()),
            (None, None, Some(agent), Some(_), Some(_))
                if agent.as_core_id() == self.principal_id.as_core_id() =>
            {
                Ok(())
            }
            _ => Err("claim must select exactly one endpoint authority branch"),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageUploadEntry {
    #[serde(deserialize_with = "deserialize_mls_keypackage_identity")]
    pub keypackage_id: String,
    pub keypackage_ref: String,
    pub keypackage: Base64UrlString,
    #[serde(deserialize_with = "crate::http_bodies::deserialize_keypackage_string_list")]
    pub cipher_suites: Vec<String>,
    #[serde(deserialize_with = "crate::http_bodies::deserialize_keypackage_string_list")]
    pub capabilities: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_upload_last_resort"
    )]
    pub last_resort: Option<bool>,
}

pub(crate) fn validate_mls_keypackage_identity(
    value: &str,
) -> std::result::Result<(), &'static str> {
    let Some(suffix) = value.strip_prefix("ak:mls:kp:") else {
        return Err("KeyPackage identity must use ak:mls:kp:<canonical UUIDv7>");
    };
    let bytes = suffix.as_bytes();
    if bytes.len() != 36
        || bytes[14] != b'7'
        || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        || !bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f')
            }
        })
    {
        return Err("KeyPackage identity must use ak:mls:kp:<canonical UUIDv7>");
    }
    Ok(())
}

fn deserialize_mls_keypackage_identity<'de, D>(
    deserializer: D,
) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_mls_keypackage_identity(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_upload_last_resort<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bool::deserialize(deserializer).map(Some)
}

pub type AlgorithmCounts = BTreeMap<NonEmptyString, u64>;
pub type AlgorithmKeyRecords = BTreeMap<NonEmptyString, KeyRecord>;
pub type DeviceAlgorithmMap = BTreeMap<DeviceId, NonEmptyString>;
pub type DeviceKeyRecords = BTreeMap<DeviceId, AlgorithmKeyRecords>;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key: Base64UrlString,
    pub algorithm: NonEmptyString,
    pub signature: KeyOperationSignature,
    pub key_id: Option<NonEmptyString>,
    pub key_digest: Option<Hash>,
    pub fallback: Option<bool>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeviceAlgorithmEntry {
    pub account_id: AccountId,
    pub device_algorithms: DeviceAlgorithmMap,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeviceKeyEntry {
    pub account_id: AccountId,
    pub device_keys: DeviceKeyRecords,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAccountDeviceSelector {
    pub account_id: AccountId,
    #[serde(deserialize_with = "deserialize_device_ids")]
    pub device_ids: Vec<DeviceId>,
}

pub const MAX_SELECTED_DEVICES_PER_ACCOUNT: usize = 32;

fn validate_selected_device_ids(ids: &[DeviceId]) -> std::result::Result<(), &'static str> {
    let unique = ids.iter().collect::<BTreeSet<_>>();
    if ids.is_empty() || ids.len() > MAX_SELECTED_DEVICES_PER_ACCOUNT || unique.len() != ids.len() {
        return Err("device_ids must contain 1..=32 unique values");
    }
    Ok(())
}

fn deserialize_device_ids<'de, D>(deserializer: D) -> std::result::Result<Vec<DeviceId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ids = Vec::<DeviceId>::deserialize(deserializer)?;
    validate_selected_device_ids(&ids).map_err(serde::de::Error::custom)?;
    Ok(ids)
}

impl arkret_wire::CanonicalIdentityEntry for AccountDeviceAlgorithmEntry {
    type Identity = AccountId;
    fn identity(&self) -> &AccountId {
        &self.account_id
    }
}
impl arkret_wire::CanonicalIdentityEntry for AccountDeviceKeyEntry {
    type Identity = AccountId;
    fn identity(&self) -> &AccountId {
        &self.account_id
    }
}
impl arkret_wire::CanonicalIdentityEntry for QueryAccountDeviceSelector {
    type Identity = AccountId;
    fn identity(&self) -> &AccountId {
        &self.account_id
    }
    fn validate_entry(&self) -> Result<()> {
        validate_selected_device_ids(&self.device_ids)
            .map_err(|e| WireError::Protocol(e.to_owned()))
    }
}

fn protocol<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(message.to_owned()))
}
