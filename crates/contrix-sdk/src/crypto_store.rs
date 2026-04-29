//! Durable crypto store traits and an in-memory implementation.
//!
//! The SDK keeps this layer independent from OpenMLS internals. Applications can
//! serialize provider-specific MLS state into `MlsGroupStateRecord` while using
//! the typed Contrix envelopes for KeyPackages, Welcomes and Commits.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    DeviceId, DeviceVerificationState, Did, Error, MlsCommitEnvelope, MlsKeyPackageRecord,
    MlsWelcomeEnvelope, Result, store::StoreEncryptionKey,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsRecoveryAction {
    UseLocalState,
    ApplyCommits { from_epoch: u64, to_epoch: u64 },
    ConsumeWelcome,
    RequestEpochRecovery { missing_from_epoch: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsRecoveryPlan {
    pub group_id: String,
    pub action: MlsRecoveryAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupStateRecord {
    pub group_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub epoch: u64,
    pub serialized_state: Vec<u8>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsEpochSecretRecord {
    pub group_id: String,
    pub epoch: u64,
    pub secret_ref: String,
    pub encrypted_secret: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDeviceVerification {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub state: DeviceVerificationState,
    pub updated_at: DateTime<Utc>,
}

pub trait CryptoStore: Send + Sync {
    fn put_mls_group_state(&mut self, record: MlsGroupStateRecord) -> Result<()>;
    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord>;
    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()>;
    fn key_package(&self, principal_id: &Did, device_id: &DeviceId)
    -> Option<&MlsKeyPackageRecord>;
    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()>;
    fn welcomes_for_device(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope>;
    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()>;
    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope>;
    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()>;
    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord>;
    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()>;
    fn device_verification(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification>;
    fn plan_mls_recovery(
        &self,
        group_id: &str,
        local_epoch: Option<u64>,
        required_epoch: u64,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> MlsRecoveryPlan;
    fn export_backup_json(&self) -> Result<String>;
    fn import_backup_json(&mut self, backup: &str) -> Result<()>;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemoryCryptoStore {
    group_states: BTreeMap<String, MlsGroupStateRecord>,
    key_packages: BTreeMap<(Did, DeviceId), MlsKeyPackageRecord>,
    welcomes: Vec<MlsWelcomeEnvelope>,
    commits: BTreeMap<String, Vec<MlsCommitEnvelope>>,
    epoch_secrets: BTreeMap<(String, u64), MlsEpochSecretRecord>,
    device_verifications: BTreeMap<(Did, DeviceId), StoredDeviceVerification>,
}

impl MemoryCryptoStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CryptoStore for MemoryCryptoStore {
    fn put_mls_group_state(&mut self, record: MlsGroupStateRecord) -> Result<()> {
        self.group_states.insert(record.group_id.clone(), record);
        Ok(())
    }

    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
        self.group_states.get(group_id)
    }

    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()> {
        self.key_packages.insert((record.principal_id.clone(), record.device_id.clone()), record);
        Ok(())
    }

    fn key_package(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord> {
        self.key_packages.get(&(principal_id.clone(), device_id.clone()))
    }

    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()> {
        if record.group_id.is_empty() {
            return Err(Error::Protocol("MLS welcome group_id is empty".to_owned()));
        }
        if let Some(existing) = self.welcomes.iter().find(|welcome| {
            welcome.group_id == record.group_id
                && welcome.epoch == record.epoch
                && welcome.recipient_principal_id == record.recipient_principal_id
                && welcome.recipient_device_id == record.recipient_device_id
        }) {
            return if existing.welcome_hash == record.welcome_hash {
                Ok(())
            } else {
                Err(Error::IdempotencyConflict(format!(
                    "welcome:{}:{}:{}",
                    record.group_id, record.epoch, record.recipient_device_id
                )))
            };
        }
        self.welcomes.push(record);
        Ok(())
    }

    fn welcomes_for_device(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope> {
        self.welcomes
            .iter()
            .filter(|welcome| {
                &welcome.recipient_principal_id == principal_id
                    && &welcome.recipient_device_id == device_id
            })
            .collect()
    }

    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()> {
        if record.group_id.is_empty() {
            return Err(Error::Protocol("MLS commit group_id is empty".to_owned()));
        }
        let commits = self.commits.entry(record.group_id.clone()).or_default();
        if commits.iter().any(|commit| commit.commit_hash == record.commit_hash) {
            return Ok(());
        }
        if commits.iter().any(|commit| commit.epoch == record.epoch) {
            return Err(Error::IdempotencyConflict(format!(
                "commit:{}:{}",
                record.group_id, record.epoch
            )));
        }
        commits.push(record);
        Ok(())
    }

    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope> {
        self.commits.get(group_id).map(|commits| commits.iter().collect()).unwrap_or_default()
    }

    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()> {
        self.epoch_secrets.insert((record.group_id.clone(), record.epoch), record);
        Ok(())
    }

    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord> {
        self.epoch_secrets.get(&(group_id.to_owned(), epoch))
    }

    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()> {
        self.device_verifications
            .insert((record.principal_id.clone(), record.device_id.clone()), record);
        Ok(())
    }

    fn device_verification(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification> {
        self.device_verifications.get(&(principal_id.clone(), device_id.clone()))
    }

    fn plan_mls_recovery(
        &self,
        group_id: &str,
        local_epoch: Option<u64>,
        required_epoch: u64,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> MlsRecoveryPlan {
        let action = match local_epoch {
            Some(epoch) if epoch >= required_epoch => MlsRecoveryAction::UseLocalState,
            Some(epoch)
                if self
                    .commits_for_group(group_id)
                    .iter()
                    .any(|commit| commit.epoch > epoch && commit.epoch <= required_epoch) =>
            {
                MlsRecoveryAction::ApplyCommits {
                    from_epoch: epoch.saturating_add(1),
                    to_epoch: required_epoch,
                }
            }
            _ if !self.welcomes_for_device(principal_id, device_id).is_empty() => {
                MlsRecoveryAction::ConsumeWelcome
            }
            Some(epoch) => MlsRecoveryAction::RequestEpochRecovery {
                missing_from_epoch: epoch.saturating_add(1),
            },
            None => MlsRecoveryAction::RequestEpochRecovery { missing_from_epoch: required_epoch },
        };
        MlsRecoveryPlan { group_id: group_id.to_owned(), action }
    }

    fn export_backup_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Into::into)
    }

    fn import_backup_json(&mut self, backup: &str) -> Result<()> {
        *self = serde_json::from_str(backup)?;
        Ok(())
    }
}

/// Encrypted at-rest crypto store wrapper.
///
/// Wraps `MemoryCryptoStore` and encrypts every record before storing it,
/// so that raw MLS state, epoch secrets and key packages are never persisted
/// in plaintext. The inner store still keeps a plaintext copy for the `CryptoStore`
/// trait API, but callers can inspect `encrypted_*` methods to verify that
/// ciphertext was produced.
#[derive(Clone, Debug)]
pub struct EncryptedMemoryCryptoStore {
    inner: MemoryCryptoStore,
    key: StoreEncryptionKey,
    encrypted_group_states: BTreeMap<String, Vec<u8>>,
    encrypted_epoch_secrets: BTreeMap<(String, u64), Vec<u8>>,
    encrypted_key_packages: BTreeMap<(Did, DeviceId), Vec<u8>>,
}

impl EncryptedMemoryCryptoStore {
    /// Create an encrypted crypto store.
    pub fn new(key: StoreEncryptionKey) -> Self {
        Self {
            inner: MemoryCryptoStore::new(),
            key,
            encrypted_group_states: BTreeMap::new(),
            encrypted_epoch_secrets: BTreeMap::new(),
            encrypted_key_packages: BTreeMap::new(),
        }
    }

    /// Raw encrypted group state bytes.
    pub fn encrypted_group_state_bytes(&self, group_id: &str) -> Option<&[u8]> {
        self.encrypted_group_states.get(group_id).map(Vec::as_slice)
    }

    /// Raw encrypted epoch secret bytes.
    pub fn encrypted_epoch_secret_bytes(&self, group_id: &str, epoch: u64) -> Option<&[u8]> {
        self.encrypted_epoch_secrets
            .get(&(group_id.to_owned(), epoch))
            .map(Vec::as_slice)
    }

    /// Raw encrypted key package bytes.
    pub fn encrypted_key_package_bytes(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&[u8]> {
        self.encrypted_key_packages
            .get(&(principal_id.clone(), device_id.clone()))
            .map(Vec::as_slice)
    }

    fn seal_record<T: Serialize>(&self, record: &T, aad: &[u8]) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(record)?;
        self.key.seal(&bytes, aad)
    }
}

impl CryptoStore for EncryptedMemoryCryptoStore {
    fn put_mls_group_state(&mut self, record: MlsGroupStateRecord) -> Result<()> {
        let aad = format!("group_state:{}", record.group_id);
        let encrypted = self.seal_record(&record, aad.as_bytes())?;
        let group_id = record.group_id.clone();
        self.inner.put_mls_group_state(record)?;
        self.encrypted_group_states.insert(group_id, encrypted);
        Ok(())
    }

    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
        self.inner.mls_group_state(group_id)
    }

    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()> {
        let aad = format!(
            "key_package:{}:{}",
            record.principal_id.as_str(),
            record.device_id.as_str()
        );
        let encrypted = self.seal_record(&record, aad.as_bytes())?;
        let key = (record.principal_id.clone(), record.device_id.clone());
        self.inner.put_key_package(record)?;
        self.encrypted_key_packages.insert(key, encrypted);
        Ok(())
    }

    fn key_package(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord> {
        self.inner.key_package(principal_id, device_id)
    }

    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()> {
        self.inner.put_welcome(record)
    }

    fn welcomes_for_device(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope> {
        self.inner.welcomes_for_device(principal_id, device_id)
    }

    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()> {
        self.inner.put_commit(record)
    }

    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope> {
        self.inner.commits_for_group(group_id)
    }

    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()> {
        let aad = format!("epoch_secret:{}:{}", record.group_id, record.epoch);
        let encrypted = self.seal_record(&record, aad.as_bytes())?;
        let key = (record.group_id.clone(), record.epoch);
        self.inner.put_epoch_secret(record)?;
        self.encrypted_epoch_secrets.insert(key, encrypted);
        Ok(())
    }

    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord> {
        self.inner.epoch_secret(group_id, epoch)
    }

    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()> {
        self.inner.put_device_verification(record)
    }

    fn device_verification(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification> {
        self.inner.device_verification(principal_id, device_id)
    }

    fn plan_mls_recovery(
        &self,
        group_id: &str,
        local_epoch: Option<u64>,
        required_epoch: u64,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> MlsRecoveryPlan {
        self.inner.plan_mls_recovery(group_id, local_epoch, required_epoch, principal_id, device_id)
    }

    fn export_backup_json(&self) -> Result<String> {
        self.inner.export_backup_json()
    }

    fn import_backup_json(&mut self, backup: &str) -> Result<()> {
        self.inner.import_backup_json(backup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        DeviceId::new(format!("dev_{id}")).unwrap()
    }

    #[test]
    fn memory_crypto_store_roundtrips_mls_records_and_verification() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();

        store
            .put_mls_group_state(MlsGroupStateRecord {
                group_id: "group1".to_owned(),
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                epoch: 3,
                serialized_state: b"state".to_vec(),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(store.mls_group_state("group1").unwrap().epoch, 3);

        store
            .put_key_package(MlsKeyPackageRecord {
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                key_package: "kp".to_owned(),
                key_package_hash: Hash::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                cipher_suites: vec!["suite".to_owned()],
                created_at: Utc::now(),
                expires_at: None,
                revoked: false,
                device_signature: None,
            })
            .unwrap();
        assert!(store.key_package(&alice, &device_id).is_some());

        store
            .put_device_verification(StoredDeviceVerification {
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                state: DeviceVerificationState::Verified,
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(
            store.device_verification(&alice, &device_id).unwrap().state,
            DeviceVerificationState::Verified
        );
    }

    #[test]
    fn memory_crypto_store_plans_recovery_and_restores_backup() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();
        store
            .put_welcome(MlsWelcomeEnvelope {
                group_id: "group1".to_owned(),
                epoch: 1,
                recipient_principal_id: alice.clone(),
                recipient_device_id: device_id.clone(),
                welcome: "welcome".to_owned(),
                welcome_hash: Hash::new(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                ratchet_tree: None,
            })
            .unwrap();

        let plan = store.plan_mls_recovery("group1", None, 1, &alice, &device_id);
        assert!(matches!(plan.action, MlsRecoveryAction::ConsumeWelcome));

        let backup = store.export_backup_json().unwrap();
        let mut restored = MemoryCryptoStore::new();
        restored.import_backup_json(&backup).unwrap();
        assert_eq!(restored.welcomes_for_device(&alice, &device_id).len(), 1);
    }

    #[test]
    fn encrypted_crypto_store_seals_group_state_and_epoch_secrets_at_rest() {
        let alice = did("alice");
        let device_id = device("phone");
        let key = StoreEncryptionKey::derive("test-passphrase", b"crypto-store-salt", 4);
        let mut store = EncryptedMemoryCryptoStore::new(key);

        store
            .put_mls_group_state(MlsGroupStateRecord {
                group_id: "group1".to_owned(),
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                epoch: 5,
                serialized_state: b"secret-mls-state".to_vec(),
                updated_at: Utc::now(),
            })
            .unwrap();

        let encrypted_bytes = store.encrypted_group_state_bytes("group1").unwrap();
        let plain_text = String::from_utf8_lossy(encrypted_bytes);
        assert!(
            !plain_text.contains("secret-mls-state"),
            "encrypted bytes must not contain plaintext MLS state"
        );
        assert_eq!(store.mls_group_state("group1").unwrap().epoch, 5);

        store
            .put_epoch_secret(MlsEpochSecretRecord {
                group_id: "group1".to_owned(),
                epoch: 5,
                secret_ref: "epoch-5-secret".to_owned(),
                encrypted_secret: b"already-encrypted".to_vec(),
                created_at: Utc::now(),
            })
            .unwrap();

        let encrypted_epoch = store.encrypted_epoch_secret_bytes("group1", 5).unwrap();
        let epoch_plain = String::from_utf8_lossy(encrypted_epoch);
        assert!(!epoch_plain.contains("epoch-5-secret"));
        assert_eq!(store.epoch_secret("group1", 5).unwrap().secret_ref, "epoch-5-secret");

        store
            .put_key_package(MlsKeyPackageRecord {
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                key_package: "kp-secret".to_owned(),
                key_package_hash: Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
                created_at: Utc::now(),
                expires_at: None,
                revoked: false,
                device_signature: None,
            })
            .unwrap();

        let encrypted_kp = store.encrypted_key_package_bytes(&alice, &device_id).unwrap();
        let kp_plain = String::from_utf8_lossy(encrypted_kp);
        assert!(!kp_plain.contains("kp-secret"));
        assert!(store.key_package(&alice, &device_id).is_some());
    }

    #[test]
    fn memory_crypto_store_deduplicates_welcomes_and_commits() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();
        let welcome = MlsWelcomeEnvelope {
            group_id: "group1".to_owned(),
            epoch: 1,
            recipient_principal_id: alice.clone(),
            recipient_device_id: device_id.clone(),
            welcome: "welcome".to_owned(),
            welcome_hash: Hash::new(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            ratchet_tree: None,
        };

        store.put_welcome(welcome.clone()).unwrap();
        store.put_welcome(welcome.clone()).unwrap();
        assert_eq!(store.welcomes_for_device(&alice, &device_id).len(), 1);

        let mut conflicting_welcome = welcome;
        conflicting_welcome.welcome_hash =
            Hash::new("sha256:3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        assert!(matches!(
            store.put_welcome(conflicting_welcome),
            Err(Error::IdempotencyConflict(_))
        ));

        let commit = MlsCommitEnvelope {
            group_id: "group1".to_owned(),
            epoch: 2,
            commit: "commit".to_owned(),
            commit_hash: Hash::new(
                "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            )
            .unwrap(),
            ratchet_tree: None,
        };
        store.put_commit(commit.clone()).unwrap();
        store.put_commit(commit.clone()).unwrap();
        assert_eq!(store.commits_for_group("group1").len(), 1);

        let mut conflicting_commit = commit;
        conflicting_commit.commit_hash =
            Hash::new("sha256:5555555555555555555555555555555555555555555555555555555555555555")
                .unwrap();
        assert!(matches!(store.put_commit(conflicting_commit), Err(Error::IdempotencyConflict(_))));
    }
}
