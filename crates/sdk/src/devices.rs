//! Device list, to-device messaging, verification and key backup helpers.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{DeviceId, DeviceVerificationState, Did, Error, Result, canonical};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerificationChallenge {
    pub transaction_id: String,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub method: String,
    pub challenge: String,
    pub commitment: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// QR payload shown to scanners during device verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QrVerificationPayload {
    pub version: u32,
    pub transaction_id: String,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub method: String,
    pub commitment: String,
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

/// Spec-aligned device message envelope facade from `cx.schema.device_message.v1`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessageEnvelope {
    pub kind: String,
    pub txn_id: String,
    pub sender_principal_id: Did,
    pub sender_device_id: DeviceId,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub sent_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
}

/// Known `cx.key.verification.*` device message kinds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceVerificationMessageKind {
    Request,
    Ready,
    Start,
    Accept,
    Key,
    Mac,
    Done,
    Cancel,
}

impl DeviceVerificationMessageKind {
    pub fn as_event_kind(&self) -> &'static str {
        match self {
            Self::Request => "cx.key.verification.request",
            Self::Ready => "cx.key.verification.ready",
            Self::Start => "cx.key.verification.start",
            Self::Accept => "cx.key.verification.accept",
            Self::Key => "cx.key.verification.key",
            Self::Mac => "cx.key.verification.mac",
            Self::Done => "cx.key.verification.done",
            Self::Cancel => "cx.key.verification.cancel",
        }
    }
}

/// Schema-aligned verification message content scaffold.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceVerificationMessageContent {
    pub transaction_id: String,
    pub from_device: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement_protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub message_authentication_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub short_authentication_string: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Key backup record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackup {
    /// Backup version.
    pub version: String,
    /// Backup algorithm.
    pub algorithm: String,
    /// Sender that uploaded the backup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<Did>,
    /// Previous version, if this backup rotates a prior one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    /// Opaque encrypted backup payload.
    pub payload: Value,
    /// Canonical payload digest.
    pub payload_sha256: String,
    /// Upload time.
    pub uploaded_at: DateTime<Utc>,
}

/// Schema-aligned encrypted key backup class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupClass {
    DidRecovery,
    SecretStorage,
    MlsHistory,
}

/// Schema-aligned backup encryption descriptor scaffold.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupEncryption {
    pub recipient_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_key_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Value>,
    pub aead: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<String>,
}

/// Schema-aligned backup content item scaffold.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupContentItem {
    pub item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub extra: Value,
}

/// Schema-aligned encrypted key backup facade from `cx.schema.key_backup.v1`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolKeyBackup {
    pub backup_id: String,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub backup_class: KeyBackupClass,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub encryption: KeyBackupEncryption,
    pub contents: Vec<KeyBackupContentItem>,
    pub ciphertext: String,
    pub ciphertext_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<Value>,
}

/// In-memory device manager.
#[derive(Clone, Debug, Default)]
pub struct DeviceManager {
    devices: BTreeMap<Did, BTreeMap<DeviceId, Device>>,
    changes: Vec<DeviceChange>,
    to_device_queue: VecDeque<ToDeviceEnvelope>,
    key_backups: BTreeMap<String, KeyBackup>,
    protocol_device_messages: VecDeque<DeviceMessageEnvelope>,
    protocol_key_backups: BTreeMap<String, ProtocolKeyBackup>,
    verification_challenges: BTreeMap<String, DeviceVerificationChallenge>,
    revoked_devices: BTreeMap<Did, BTreeMap<DeviceId, DateTime<Utc>>>,
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

    /// Queue a schema-aligned device message envelope.
    pub fn queue_protocol_device_message(&mut self, message: DeviceMessageEnvelope) {
        self.protocol_device_messages.push_back(message);
    }

    /// Drain schema-aligned device message envelopes.
    pub fn drain_protocol_device_messages(&mut self) -> Vec<DeviceMessageEnvelope> {
        self.protocol_device_messages.drain(..).collect()
    }

    /// Start device verification.
    pub fn start_verification(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        self.set_verification(user_id, device_id, DeviceVerificationState::VerificationStarted)
    }

    pub fn begin_verification_flow(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        method: impl Into<String>,
        challenge: impl Into<String>,
    ) -> Result<DeviceVerificationChallenge> {
        self.start_verification(user_id, device_id)?;
        let method = method.into();
        let challenge_value = challenge.into();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::minutes(10);
        let transaction_id = format!(
            "cx:verify:{}:{}:{}",
            user_id.as_str(),
            device_id.as_str(),
            created_at.timestamp_millis()
        );
        let challenge = DeviceVerificationChallenge {
            transaction_id,
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            method,
            commitment: device_verification_commitment(
                user_id,
                device_id,
                &challenge_value,
                created_at,
            )?,
            challenge: challenge_value,
            created_at,
            expires_at,
        };
        self.verification_challenges.insert(challenge.transaction_id.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Start a SAS-style verification flow with a canonical commitment.
    pub fn begin_sas_verification(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        sas_code: impl Into<String>,
    ) -> Result<DeviceVerificationChallenge> {
        self.begin_verification_flow(user_id, device_id, "sas_v1", sas_code)
    }

    /// Return a scanner-facing QR payload for a pending verification transaction.
    pub fn qr_verification_payload(&self, transaction_id: &str) -> Result<QrVerificationPayload> {
        let challenge = self
            .verification_challenges
            .get(transaction_id)
            .ok_or_else(|| Error::Protocol("verification transaction not found".to_owned()))?;
        Ok(QrVerificationPayload {
            version: 1,
            transaction_id: challenge.transaction_id.clone(),
            user_id: challenge.user_id.clone(),
            device_id: challenge.device_id.clone(),
            method: challenge.method.clone(),
            commitment: challenge.commitment.clone(),
        })
    }

    /// Validate a scanned QR payload against the expected device.
    pub fn validate_qr_verification_payload(
        payload: &QrVerificationPayload,
        expected_user: &Did,
        expected_device: &DeviceId,
    ) -> Result<()> {
        if payload.version != 1 {
            return Err(Error::Protocol("unsupported verification QR version".to_owned()));
        }
        if &payload.user_id != expected_user || &payload.device_id != expected_device {
            return Err(Error::Protocol("verification QR device mismatch".to_owned()));
        }
        if payload.commitment.trim().is_empty() {
            return Err(Error::Protocol("verification QR commitment is empty".to_owned()));
        }
        Ok(())
    }

    pub fn confirm_verification_flow(
        &mut self,
        transaction_id: &str,
        response: &str,
        cross_signing_key: Option<String>,
    ) -> Result<()> {
        let challenge = self
            .verification_challenges
            .remove(transaction_id)
            .ok_or_else(|| Error::Protocol("verification transaction not found".to_owned()))?;
        if challenge.expires_at <= Utc::now() {
            self.set_verification(
                &challenge.user_id,
                &challenge.device_id,
                DeviceVerificationState::VerificationExpired,
            )?;
            return Err(Error::Protocol("verification transaction expired".to_owned()));
        }
        if challenge.challenge != response {
            self.set_verification(
                &challenge.user_id,
                &challenge.device_id,
                DeviceVerificationState::VerificationFailed,
            )?;
            return Err(Error::Protocol("verification challenge mismatch".to_owned()));
        }
        let expected = device_verification_commitment(
            &challenge.user_id,
            &challenge.device_id,
            response,
            challenge.created_at,
        )?;
        if expected != challenge.commitment {
            self.set_verification(
                &challenge.user_id,
                &challenge.device_id,
                DeviceVerificationState::VerificationFailed,
            )?;
            return Err(Error::Protocol("verification commitment mismatch".to_owned()));
        }
        self.verify_device(&challenge.user_id, &challenge.device_id, cross_signing_key)
    }

    /// Cancel a pending verification flow.
    pub fn cancel_verification_flow(&mut self, transaction_id: &str) -> Result<()> {
        let challenge = self
            .verification_challenges
            .remove(transaction_id)
            .ok_or_else(|| Error::Protocol("verification transaction not found".to_owned()))?;
        self.set_verification(
            &challenge.user_id,
            &challenge.device_id,
            DeviceVerificationState::VerificationCancelled,
        )
    }

    /// Mark all expired pending verification flows as expired.
    pub fn expire_verification_challenges(&mut self, now: DateTime<Utc>) -> Result<usize> {
        let expired = self
            .verification_challenges
            .iter()
            .filter_map(
                |(id, challenge)| {
                    if challenge.expires_at <= now { Some(id.clone()) } else { None }
                },
            )
            .collect::<Vec<_>>();
        for transaction_id in &expired {
            if let Some(challenge) = self.verification_challenges.remove(transaction_id) {
                self.set_verification(
                    &challenge.user_id,
                    &challenge.device_id,
                    DeviceVerificationState::VerificationExpired,
                )?;
            }
        }
        Ok(expired.len())
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

    /// Revoke a device, causing all future encrypted writes from it to fail closed.
    pub fn revoke_device(&mut self, user_id: &Did, device_id: &DeviceId) {
        self.revoked_devices
            .entry(user_id.clone())
            .or_default()
            .insert(device_id.clone(), Utc::now());
    }

    /// Check if a device has been revoked.
    pub fn is_device_revoked(&self, user_id: &Did, device_id: &DeviceId) -> bool {
        self.revoked_devices.get(user_id).and_then(|devices| devices.get(device_id)).is_some()
    }

    /// Get all revoked devices for a user.
    pub fn revoked_devices_for_user(&self, user_id: &Did) -> Vec<(&DeviceId, &DateTime<Utc>)> {
        self.revoked_devices
            .get(user_id)
            .map(|devices| devices.iter().collect())
            .unwrap_or_default()
    }

    /// Propagate trust from an already verified device to another device of the same user.
    pub fn propagate_trust(
        &mut self,
        user_id: &Did,
        trusted_device_id: &DeviceId,
        target_device_id: &DeviceId,
    ) -> Result<()> {
        let trusted = self
            .device(user_id, trusted_device_id)
            .ok_or_else(|| Error::Protocol("trusted device not found".to_owned()))?;
        if trusted.verification != DeviceVerificationState::Verified {
            return Err(Error::Protocol("source device is not verified".to_owned()));
        }
        let cross_signing_key = trusted
            .cross_signing_key
            .clone()
            .or_else(|| Some(format!("trusted-by:{}", trusted_device_id.as_str())));
        self.verify_device(user_id, target_device_id, cross_signing_key)
    }

    /// Upload or replace a key backup.
    pub fn upload_key_backup(
        &mut self,
        version: impl Into<String>,
        algorithm: impl Into<String>,
        payload: Value,
    ) -> KeyBackup {
        self.upload_authenticated_key_backup(version, algorithm, payload, None, None)
    }

    /// Upload a key backup with sender identity and optional rotation link.
    pub fn upload_authenticated_key_backup(
        &mut self,
        version: impl Into<String>,
        algorithm: impl Into<String>,
        payload: Value,
        sender: Option<Did>,
        previous_version: Option<String>,
    ) -> KeyBackup {
        let payload_sha256 = canonical::canonical_sha256(&payload)
            .unwrap_or_else(|_| format!("sha256:{:x}", Sha256::digest(payload.to_string())));
        let backup = KeyBackup {
            version: version.into(),
            algorithm: algorithm.into(),
            sender,
            previous_version,
            payload_sha256,
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
        let backup = self
            .key_backups
            .get(version)
            .ok_or_else(|| Error::Protocol("key backup not found".to_owned()))?;
        validate_key_backup_payload(backup)?;
        Ok(backup.payload.clone())
    }

    /// Restore a key backup only if it was uploaded by the expected sender.
    pub fn restore_key_backup_from_sender(
        &self,
        version: &str,
        expected_sender: &Did,
    ) -> Result<Value> {
        let backup = self
            .key_backups
            .get(version)
            .ok_or_else(|| Error::Protocol("key backup not found".to_owned()))?;
        validate_key_backup_payload(backup)?;
        if backup.sender.as_ref() != Some(expected_sender) {
            return Err(Error::Protocol("key backup sender mismatch".to_owned()));
        }
        Ok(backup.payload.clone())
    }

    /// Store a schema-aligned encrypted key backup scaffold.
    pub fn store_protocol_key_backup(&mut self, backup: ProtocolKeyBackup) -> Result<()> {
        if backup.backup_id.trim().is_empty() {
            return Err(Error::Protocol("protocol key backup backup_id must not be empty".to_owned()));
        }
        if backup.backup_version.trim().is_empty() {
            return Err(Error::Protocol(
                "protocol key backup backup_version must not be empty".to_owned(),
            ));
        }
        if backup.ciphertext.trim().is_empty() || backup.ciphertext_digest.trim().is_empty() {
            return Err(Error::Protocol(
                "protocol key backup ciphertext and digest must not be empty".to_owned(),
            ));
        }
        self.protocol_key_backups.insert(backup.backup_id.clone(), backup);
        Ok(())
    }

    /// Get a schema-aligned encrypted key backup scaffold.
    pub fn protocol_key_backup(&self, backup_id: &str) -> Option<&ProtocolKeyBackup> {
        self.protocol_key_backups.get(backup_id)
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

pub fn device_verification_commitment(
    user_id: &Did,
    device_id: &DeviceId,
    challenge: &str,
    created_at: DateTime<Utc>,
) -> Result<String> {
    let payload = serde_json::json!({
        "context": "contrix-device-verification-v1",
        "user_id": user_id,
        "device_id": device_id,
        "challenge": challenge,
        "created_at": created_at,
    });
    canonical::canonical_sha256(&payload)
}

fn validate_key_backup_payload(backup: &KeyBackup) -> Result<()> {
    let actual = canonical::canonical_sha256(&backup.payload)
        .unwrap_or_else(|_| format!("sha256:{:x}", Sha256::digest(backup.payload.to_string())));
    if actual == backup.payload_sha256 {
        Ok(())
    } else {
        Err(Error::Protocol("key backup payload digest mismatch".to_owned()))
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

        manager.send_to_device(alice, bob, device_id, "cx.keys.room_key", json!({"session":"abc"}));

        let messages = manager.drain_to_device();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_type, "cx.keys.room_key");
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
    fn devices_run_challenge_response_verification_flow() {
        let alice = did("alice");
        let device_id = device("desktop");
        let mut manager = DeviceManager::new();
        manager.upsert_device(
            alice.clone(),
            device_id.clone(),
            DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        );

        let challenge =
            manager.begin_verification_flow(&alice, &device_id, "sas", "123456").unwrap();
        manager
            .confirm_verification_flow(&challenge.transaction_id, "123456", Some("key".to_owned()))
            .unwrap();

        assert_eq!(
            manager.device(&alice, &device_id).unwrap().verification,
            DeviceVerificationState::Verified
        );
    }

    #[test]
    fn devices_support_sas_qr_mismatch_and_trust_propagation() {
        let alice = did("alice");
        let phone = device("phone");
        let laptop = device("laptop");
        let mut manager = DeviceManager::new();
        for device_id in [&phone, &laptop] {
            manager.upsert_device(
                alice.clone(),
                device_id.clone(),
                DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
            );
        }

        let challenge = manager.begin_sas_verification(&alice, &phone, "123456").unwrap();
        assert!(challenge.commitment.starts_with("sha256:"));
        let qr = manager.qr_verification_payload(&challenge.transaction_id).unwrap();
        DeviceManager::validate_qr_verification_payload(&qr, &alice, &phone).unwrap();
        assert!(
            manager.confirm_verification_flow(&challenge.transaction_id, "000000", None).is_err()
        );
        assert_eq!(
            manager.device(&alice, &phone).unwrap().verification,
            DeviceVerificationState::VerificationFailed
        );

        manager.start_verification(&alice, &phone).unwrap();
        manager.verify_device(&alice, &phone, Some("master-key".to_owned())).unwrap();
        manager.propagate_trust(&alice, &phone, &laptop).unwrap();
        assert_eq!(
            manager.device(&alice, &laptop).unwrap().verification,
            DeviceVerificationState::Verified
        );
    }

    #[test]
    fn devices_uploads_downloads_and_restores_key_backup() {
        let mut manager = DeviceManager::new();
        manager.upload_key_backup("1", "m.megolm_backup.v1", json!({"ciphertext":"abc"}));

        assert!(manager.download_key_backup("1").is_some());
        assert_eq!(manager.restore_key_backup("1").unwrap(), json!({"ciphertext":"abc"}));
        assert!(manager.restore_key_backup("missing").is_err());
    }

    #[test]
    fn devices_revoke_and_fail_closed() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut manager = DeviceManager::new();
        manager.upsert_device(
            alice.clone(),
            device_id.clone(),
            DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        );

        assert!(!manager.is_device_revoked(&alice, &device_id));
        manager.revoke_device(&alice, &device_id);
        assert!(manager.is_device_revoked(&alice, &device_id));
        assert_eq!(manager.revoked_devices_for_user(&alice).len(), 1);
    }

    #[test]
    fn devices_rotate_and_validate_authenticated_key_backups() {
        let alice = did("alice");
        let mut manager = DeviceManager::new();
        manager.upload_authenticated_key_backup(
            "1",
            "m.megolm_backup.v1",
            json!({"ciphertext":"abc"}),
            Some(alice.clone()),
            None,
        );
        let rotated = manager.upload_authenticated_key_backup(
            "2",
            "m.megolm_backup.v1",
            json!({"ciphertext":"def"}),
            Some(alice.clone()),
            Some("1".to_owned()),
        );

        assert_eq!(rotated.previous_version.as_deref(), Some("1"));
        assert_eq!(
            manager.restore_key_backup_from_sender("2", &alice).unwrap(),
            json!({"ciphertext":"def"})
        );
        assert!(manager.restore_key_backup_from_sender("2", &did("bob")).is_err());
    }
}
