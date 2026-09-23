//! Key-operation artifacts and decrypted `secret_storage` keybags.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DeviceId, DidCoreId, DidUrl, EventId, Hash,
    NonEmptyString, ReasonCode, Result, WireError, XExtensionMap,
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
#[serde(deny_unknown_fields)]
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyOperationSignature {
    pub kid: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<NonEmptyString>,
    pub sig: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairwise_verification_method: Option<DidUrl>,
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
    #[serde(default)]
    device_id: Option<DeviceId>,
    #[serde(default)]
    agent_id: Option<DidCoreId>,
    #[serde(default)]
    agent_verification_method: Option<DidUrl>,
    #[serde(default)]
    pairwise_verification_method: Option<DidUrl>,
    keypackage: String,
    capabilities: Vec<String>,
    #[serde(default)]
    device_authorize_event_id: Option<EventId>,
    #[serde(default)]
    agent_key_authorize_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(default)]
    revocation_status: Option<String>,
    #[serde(default)]
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
            pairwise_verification_method: wire.pairwise_verification_method,
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
        NonEmptyString::new(self.claim_id.clone())?;
        if self.claim_id.starts_with("ak:") {
            return Err("claim_id must not use the ak namespace");
        }
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
            &self.pairwise_verification_method,
        ) {
            (Some(_), Some(_), None, None, None, None) => Ok(()),
            (None, None, Some(agent), Some(_), Some(_), None)
                if agent.as_core_id() == self.principal_id.as_core_id() =>
            {
                Ok(())
            }
            (None, None, None, None, None, Some(method)) => {
                crate::MlsEndpointIdentity::minimal_metadata_pairwise(
                    self.principal_id.clone(),
                    method.clone(),
                )
                .map(|_| ())
                .map_err(|_| "pairwise endpoint binding is invalid")
            }
            _ => Err("claim must select exactly one endpoint authority branch"),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageUploadEntry {
    pub keypackage_id: String,
    pub keypackage_ref: String,
    pub keypackage: Base64UrlString,
    pub cipher_suites: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort: Option<bool>,
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
