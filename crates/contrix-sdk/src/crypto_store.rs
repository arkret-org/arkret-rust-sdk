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
    MlsWelcomeEnvelope, Result,
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

pub trait CryptoStore {
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
        self.commits.entry(record.group_id.clone()).or_default().push(record);
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
}
