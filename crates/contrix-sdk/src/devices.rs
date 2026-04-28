//! Device list, to-device messaging, verification and key backup helpers.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DeviceId, Did, Error, Result};

/// User-visible device metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMetadata {
    /// Device display name.
    pub name: Option<String>,
    /// Hardware model.
    pub model: Option<String>,
    /// Operating system name/version.
    pub os: Option<String>,
    /// Last seen time.
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Verification state for a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceVerificationState {
    /// Device has not been verified.
    Unverified,
    /// Verification is in progress.
    VerificationStarted,
    /// Device has been verified.
    Verified,
    /// Device is blocked.
    Blocked,
    /// Device was deleted locally.
    Deleted,
}

/// Device record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Owning user.
    pub user_id: Did,
    /// Device ID.
    pub device_id: DeviceId,
    /// Metadata.
    pub metadata: DeviceMetadata,
    /// Verification state.
    pub verification: DeviceVerificationState,
    /// Cross-signing key or signature material.
    pub cross_signing_key: Option<String>,
    /// Last local update time.
    pub updated_at: DateTime<Utc>,
}

/// Device-list change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceChange {
    /// Changed user.
    pub user_id: Did,
    /// Changed device.
    pub device_id: DeviceId,
    /// True when the device was removed.
    pub removed: bool,
}

/// To-device message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceEnvelope {
    /// Sender user.
    pub sender: Did,
    /// Recipient user.
    pub recipient: Did,
    /// Recipient device.
    pub device_id: DeviceId,
    /// Message type.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Message body.
    pub content: Value,
    /// Local receive/enqueue time.
    pub queued_at: DateTime<Utc>,
}

/// Key backup record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackup {
    /// Backup version.
    pub version: String,
    /// Backup algorithm.
    pub algorithm: String,
    /// Opaque encrypted backup payload.
    pub payload: Value,
    /// Upload time.
    pub uploaded_at: DateTime<Utc>,
}

/// In-memory device manager.
#[derive(Clone, Debug, Default)]
pub struct DeviceManager {
    devices: BTreeMap<Did, BTreeMap<DeviceId, Device>>,
    changes: Vec<DeviceChange>,
    to_device_queue: VecDeque<ToDeviceEnvelope>,
    key_backups: BTreeMap<String, KeyBackup>,
}

impl DeviceManager {
    /// Create an empty device manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a device.
    pub fn upsert_device(&mut self, user_id: Did, device_id: DeviceId, metadata: DeviceMetadata) {
        let entry = self.devices.entry(user_id.clone()).or_default();
        let verification = entry
            .get(&device_id)
            .map(|device| device.verification)
            .unwrap_or(DeviceVerificationState::Unverified);
        entry.insert(
            device_id.clone(),
            Device {
                user_id: user_id.clone(),
                device_id: device_id.clone(),
                metadata,
                verification,
                cross_signing_key: None,
                updated_at: Utc::now(),
            },
        );
        self.changes.push(DeviceChange { user_id, device_id, removed: false });
    }

    /// Get all devices for a user.
    pub fn user_devices(&self, user_id: &Did) -> Vec<&Device> {
        self.devices.get(user_id).map(|devices| devices.values().collect()).unwrap_or_default()
    }

    /// Get one device.
    pub fn device(&self, user_id: &Did, device_id: &DeviceId) -> Option<&Device> {
        self.devices.get(user_id).and_then(|devices| devices.get(device_id))
    }

    /// Drain tracked device-list changes.
    pub fn drain_changes(&mut self) -> Vec<DeviceChange> {
        self.changes.drain(..).collect()
    }

    /// Delete a device and track removal.
    pub fn delete_device(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        let devices = self
            .devices
            .get_mut(user_id)
            .ok_or_else(|| Error::Protocol("user device list not found".to_owned()))?;
        let mut device = devices
            .remove(device_id)
            .ok_or_else(|| Error::Protocol("device not found".to_owned()))?;
        device.verification = DeviceVerificationState::Deleted;
        self.changes.push(DeviceChange {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            removed: true,
        });
        Ok(())
    }

    /// Queue an outgoing to-device message.
    pub fn send_to_device(
        &mut self,
        sender: Did,
        recipient: Did,
        device_id: DeviceId,
        message_type: impl Into<String>,
        content: Value,
    ) {
        self.to_device_queue.push_back(ToDeviceEnvelope {
            sender,
            recipient,
            device_id,
            message_type: message_type.into(),
            content,
            queued_at: Utc::now(),
        });
    }

    /// Receive an incoming to-device message into the local queue.
    pub fn receive_to_device(&mut self, message: ToDeviceEnvelope) {
        self.to_device_queue.push_back(message);
    }

    /// Drain queued to-device messages.
    pub fn drain_to_device(&mut self) -> Vec<ToDeviceEnvelope> {
        self.to_device_queue.drain(..).collect()
    }

    /// Start device verification.
    pub fn start_verification(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        self.set_verification(user_id, device_id, DeviceVerificationState::VerificationStarted)
    }

    /// Mark a device verified with cross-signing material.
    pub fn verify_device(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        cross_signing_key: Option<String>,
    ) -> Result<()> {
        let device = self.device_mut(user_id, device_id)?;
        device.verification = DeviceVerificationState::Verified;
        device.cross_signing_key = cross_signing_key;
        device.updated_at = Utc::now();
        Ok(())
    }

    /// Block a device.
    pub fn block_device(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        self.set_verification(user_id, device_id, DeviceVerificationState::Blocked)
    }

    /// Upload or replace a key backup.
    pub fn upload_key_backup(
        &mut self,
        version: impl Into<String>,
        algorithm: impl Into<String>,
        payload: Value,
    ) -> KeyBackup {
        let backup = KeyBackup {
            version: version.into(),
            algorithm: algorithm.into(),
            payload,
            uploaded_at: Utc::now(),
        };
        self.key_backups.insert(backup.version.clone(), backup.clone());
        backup
    }

    /// Download a key backup by version.
    pub fn download_key_backup(&self, version: &str) -> Option<&KeyBackup> {
        self.key_backups.get(version)
    }

    /// Restore a key backup payload.
    pub fn restore_key_backup(&self, version: &str) -> Result<Value> {
        self.key_backups
            .get(version)
            .map(|backup| backup.payload.clone())
            .ok_or_else(|| Error::Protocol("key backup not found".to_owned()))
    }

    fn set_verification(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        state: DeviceVerificationState,
    ) -> Result<()> {
        let device = self.device_mut(user_id, device_id)?;
        device.verification = state;
        device.updated_at = Utc::now();
        Ok(())
    }

    fn device_mut(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<&mut Device> {
        self.devices
            .get_mut(user_id)
            .and_then(|devices| devices.get_mut(device_id))
            .ok_or_else(|| Error::Protocol("device not found".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        DeviceId::new(format!("dev_{id}")).unwrap()
    }

    #[test]
    fn devices_tracks_lists_metadata_and_changes() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut manager = DeviceManager::new();

        manager.upsert_device(
            alice.clone(),
            device_id.clone(),
            DeviceMetadata {
                name: Some("Phone".to_owned()),
                model: Some("Pixel".to_owned()),
                os: Some("Android".to_owned()),
                last_seen_at: None,
            },
        );

        assert_eq!(manager.user_devices(&alice).len(), 1);
        assert_eq!(
            manager.device(&alice, &device_id).unwrap().metadata.name,
            Some("Phone".to_owned())
        );
        assert_eq!(manager.drain_changes().len(), 1);
    }

    #[test]
    fn devices_queues_to_device_messages() {
        let alice = did("alice");
        let bob = did("bob");
        let device_id = device("laptop");
        let mut manager = DeviceManager::new();

        manager.send_to_device(alice, bob, device_id, "m.room_key", json!({"session":"abc"}));

        let messages = manager.drain_to_device();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_type, "m.room_key");
        assert!(manager.drain_to_device().is_empty());
    }

    #[test]
    fn devices_verifies_blocks_and_deletes() {
        let alice = did("alice");
        let device_id = device("tablet");
        let mut manager = DeviceManager::new();
        manager.upsert_device(
            alice.clone(),
            device_id.clone(),
            DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        );

        manager.start_verification(&alice, &device_id).unwrap();
        assert_eq!(
            manager.device(&alice, &device_id).unwrap().verification,
            DeviceVerificationState::VerificationStarted
        );
        manager.verify_device(&alice, &device_id, Some("master-key".to_owned())).unwrap();
        assert_eq!(
            manager.device(&alice, &device_id).unwrap().verification,
            DeviceVerificationState::Verified
        );
        manager.block_device(&alice, &device_id).unwrap();
        manager.delete_device(&alice, &device_id).unwrap();
        assert!(manager.device(&alice, &device_id).is_none());
    }

    #[test]
    fn devices_uploads_downloads_and_restores_key_backup() {
        let mut manager = DeviceManager::new();
        manager.upload_key_backup("1", "m.megolm_backup.v1", json!({"ciphertext":"abc"}));

        assert!(manager.download_key_backup("1").is_some());
        assert_eq!(manager.restore_key_backup("1").unwrap(), json!({"ciphertext":"abc"}));
        assert!(manager.restore_key_backup("missing").is_err());
    }
}
