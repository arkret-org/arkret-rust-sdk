//! E2EE state helpers for group, key, validation and audit management.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AEAD_ALGORITHM, DeviceId, Did, Error, Result, crypto};

pub const KEY_BACKUP_ALGORITHM: &str = AEAD_ALGORITHM;

/// E2EE group state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eeGroup {
    /// Group ID.
    pub group_id: String,
    /// Group members.
    pub members: BTreeSet<Did>,
    /// Current epoch.
    pub epoch: u64,
    /// Source groups if merged.
    pub merged_from: Vec<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// Key record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eeKeyRecord {
    /// Key ID.
    pub key_id: String,
    /// Group ID.
    pub group_id: String,
    /// Key version.
    pub version: u64,
    /// Raw exported key bytes.
    pub key_bytes: Vec<u8>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Encrypted key backup bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eeKeyBackup {
    /// Backup ID.
    pub backup_id: String,
    /// Backup format version.
    pub version: u32,
    /// Backup algorithm.
    pub algorithm: String,
    /// DID that created the backup.
    pub sender: Did,
    /// Optional previous backup version for rotation chains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_backup_id: Option<String>,
    /// Key IDs included in the backup.
    pub key_ids: Vec<String>,
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// Plaintext digest.
    pub plaintext_sha256: String,
    /// Ciphertext digest.
    pub ciphertext_sha256: String,
    /// Canonical AAD digest used to authenticate backup metadata.
    pub aad_sha256: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// E2EE message envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eeMessage {
    /// Message ID for replay prevention.
    pub message_id: String,
    /// Group ID.
    pub group_id: String,
    /// Epoch used to encrypt.
    pub epoch: u64,
    /// Sender DID.
    pub sender: Did,
    /// Ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// Integrity digest over envelope metadata and ciphertext.
    pub digest: String,
}

/// Audit action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    GroupCreated,
    MemberJoined,
    MemberRemoved,
    GroupMerged,
    EpochAdvanced,
    KeyRotated,
    KeyExported,
    KeyBackedUp,
    KeyRestored,
    MessageValidated,
}

/// Audit trail entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Action.
    pub action: AuditAction,
    /// Actor.
    pub actor: Option<Did>,
    /// Group ID.
    pub group_id: Option<String>,
    /// Detail string.
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct E2eeKeyBackupPlaintext {
    version: u32,
    records: Vec<E2eeKeyRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct E2eeKeyBackupAad {
    backup_id: String,
    version: u32,
    algorithm: String,
    sender: Did,
    previous_backup_id: Option<String>,
    key_ids: Vec<String>,
}

/// Structured reason for rejecting an encrypted E2EE message before decryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum E2eeMessageValidationFailure {
    UnknownGroup,
    WrongSender,
    WrongEpoch { local_epoch: u64, message_epoch: u64 },
    IntegrityMismatch,
    Replay,
}

/// Non-mutating message validation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum E2eeMessageValidation {
    Valid,
    Invalid { failure: E2eeMessageValidationFailure },
}

/// E2EE manager.
#[derive(Clone, Debug, Default)]
pub struct E2eeManager {
    groups: BTreeMap<String, E2eeGroup>,
    keys: BTreeMap<String, E2eeKeyRecord>,
    seen_messages: BTreeSet<String>,
    audit: Vec<AuditEntry>,
    /// Devices revoked from encrypted writes. Key is (principal_id, device_id).
    revoked_devices: BTreeMap<(Did, DeviceId), DateTime<Utc>>,
}

impl E2eeManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new group.
    pub fn create_group(
        &mut self,
        group_id: impl Into<String>,
        creator: Did,
        members: BTreeSet<Did>,
    ) -> E2eeGroup {
        let group_id = group_id.into();
        let mut all_members = members;
        all_members.insert(creator.clone());
        let group = E2eeGroup {
            group_id: group_id.clone(),
            members: all_members,
            epoch: 0,
            merged_from: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.groups.insert(group_id.clone(), group.clone());
        self.log(AuditAction::GroupCreated, Some(creator), Some(group_id), "group created");
        group
    }

    /// Join/add a member and advance epoch.
    pub fn join_group(&mut self, group_id: &str, member: Did) -> Result<u64> {
        let epoch = {
            let group = self.group_mut(group_id)?;
            group.members.insert(member.clone());
            group.epoch += 1;
            group.updated_at = Utc::now();
            group.epoch
        };
        self.log(
            AuditAction::MemberJoined,
            Some(member),
            Some(group_id.to_owned()),
            "member joined",
        );
        Ok(epoch)
    }

    /// Remove a member and advance epoch.
    pub fn remove_member(&mut self, group_id: &str, member: &Did) -> Result<u64> {
        let epoch = {
            let group = self.group_mut(group_id)?;
            group.members.remove(member);
            group.epoch += 1;
            group.updated_at = Utc::now();
            group.epoch
        };
        self.log(
            AuditAction::MemberRemoved,
            Some(member.clone()),
            Some(group_id.to_owned()),
            "member removed",
        );
        Ok(epoch)
    }

    /// Merge groups into a new group.
    pub fn merge_groups(
        &mut self,
        new_group_id: impl Into<String>,
        source_group_ids: Vec<String>,
        actor: Did,
    ) -> Result<E2eeGroup> {
        let new_group_id = new_group_id.into();
        let mut members = BTreeSet::new();
        let mut epoch = 0;
        for group_id in &source_group_ids {
            let group = self
                .groups
                .get(group_id)
                .ok_or_else(|| Error::Protocol("source group not found".to_owned()))?;
            members.extend(group.members.iter().cloned());
            epoch = epoch.max(group.epoch);
        }
        members.insert(actor.clone());
        let group = E2eeGroup {
            group_id: new_group_id.clone(),
            members,
            epoch: epoch + 1,
            merged_from: source_group_ids,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.groups.insert(new_group_id.clone(), group.clone());
        self.log(AuditAction::GroupMerged, Some(actor), Some(new_group_id), "groups merged");
        Ok(group)
    }

    /// Advance a group's epoch.
    pub fn advance_epoch(&mut self, group_id: &str, actor: Did) -> Result<u64> {
        let epoch = {
            let group = self.group_mut(group_id)?;
            group.epoch += 1;
            group.updated_at = Utc::now();
            group.epoch
        };
        self.log(
            AuditAction::EpochAdvanced,
            Some(actor),
            Some(group_id.to_owned()),
            "epoch advanced",
        );
        Ok(epoch)
    }

    /// Rotate a group key.
    pub fn rotate_key(
        &mut self,
        group_id: &str,
        actor: Did,
        key_bytes: Vec<u8>,
    ) -> Result<E2eeKeyRecord> {
        let version = self.advance_epoch(group_id, actor.clone())?;
        let key_id = format!("{group_id}:key:{version}");
        let record = E2eeKeyRecord {
            key_id: key_id.clone(),
            group_id: group_id.to_owned(),
            version,
            key_bytes,
            created_at: Utc::now(),
        };
        self.keys.insert(key_id, record.clone());
        self.log(AuditAction::KeyRotated, Some(actor), Some(group_id.to_owned()), "key rotated");
        Ok(record)
    }

    /// Export a key by ID.
    pub fn export_key(&mut self, key_id: &str, actor: Did) -> Result<Vec<u8>> {
        let key =
            self.keys.get(key_id).ok_or_else(|| Error::Protocol("key not found".to_owned()))?;
        let group_id = key.group_id.clone();
        let bytes = key.key_bytes.clone();
        self.log(AuditAction::KeyExported, Some(actor), Some(group_id), "key exported");
        Ok(bytes)
    }

    /// Create an authenticated encrypted backup of selected keys.
    pub fn backup_keys(
        &mut self,
        backup_id: impl Into<String>,
        key_ids: Vec<String>,
        backup_key: &[u8],
        actor: Did,
    ) -> Result<E2eeKeyBackup> {
        self.backup_keys_with_rotation(backup_id, 1, None, key_ids, backup_key, actor)
    }

    /// Create an authenticated encrypted backup and link it to a previous version.
    pub fn backup_keys_with_rotation(
        &mut self,
        backup_id: impl Into<String>,
        version: u32,
        previous_backup_id: Option<String>,
        key_ids: Vec<String>,
        backup_key: &[u8],
        actor: Did,
    ) -> Result<E2eeKeyBackup> {
        if version == 0 {
            return Err(Error::Protocol("key backup version must be non-zero".to_owned()));
        }
        let backup_id = backup_id.into();
        let mut records = Vec::new();
        for key_id in &key_ids {
            let key =
                self.keys.get(key_id).ok_or_else(|| Error::Protocol("key not found".to_owned()))?;
            records.push(key.clone());
        }
        let plaintext = serde_json::to_vec(&E2eeKeyBackupPlaintext { version, records })?;
        let aad = E2eeKeyBackupAad {
            backup_id: backup_id.clone(),
            version,
            algorithm: KEY_BACKUP_ALGORITHM.to_owned(),
            sender: actor.clone(),
            previous_backup_id,
            key_ids: key_ids.clone(),
        };
        let aad_bytes = crate::canonical::canonical_json_bytes(&aad)?;
        let ciphertext = crypto::seal(&plaintext, backup_key, &aad_bytes)?;
        let backup = E2eeKeyBackup {
            backup_id,
            version,
            algorithm: KEY_BACKUP_ALGORITHM.to_owned(),
            sender: actor.clone(),
            previous_backup_id: aad.previous_backup_id,
            key_ids,
            ciphertext_sha256: sha256_hex(&ciphertext),
            ciphertext,
            plaintext_sha256: sha256_hex(&plaintext),
            aad_sha256: sha256_hex(&aad_bytes),
            created_at: Utc::now(),
        };
        self.log(AuditAction::KeyBackedUp, Some(actor), None, "keys backed up");
        Ok(backup)
    }

    /// Restore a key backup payload.
    pub fn restore_backup(&self, backup: &E2eeKeyBackup, backup_key: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self.open_backup_plaintext(backup, backup_key, None)?;
        if sha256_hex(&plaintext) == backup.plaintext_sha256 {
            Ok(plaintext)
        } else {
            Err(Error::Protocol("key backup digest mismatch".to_owned()))
        }
    }

    /// Restore usable key records from a backup and validate the expected backup sender.
    pub fn restore_key_records_from_backup(
        &mut self,
        backup: &E2eeKeyBackup,
        backup_key: &[u8],
        expected_sender: &Did,
    ) -> Result<Vec<E2eeKeyRecord>> {
        let plaintext = self.open_backup_plaintext(backup, backup_key, Some(expected_sender))?;
        let bundle: E2eeKeyBackupPlaintext = serde_json::from_slice(&plaintext)?;
        if bundle.version != backup.version {
            return Err(Error::Protocol("key backup version mismatch".to_owned()));
        }
        let mut restored = Vec::new();
        for record in bundle.records {
            if !backup.key_ids.contains(&record.key_id) {
                return Err(Error::Protocol("key backup contains unexpected key".to_owned()));
            }
            self.keys.insert(record.key_id.clone(), record.clone());
            restored.push(record);
        }
        self.log(
            AuditAction::KeyRestored,
            Some(expected_sender.clone()),
            None,
            "keys restored from backup",
        );
        Ok(restored)
    }

    /// Validate backup metadata without decrypting the payload.
    pub fn validate_backup_authenticity(
        &self,
        backup: &E2eeKeyBackup,
        expected_sender: &Did,
    ) -> Result<()> {
        if &backup.sender != expected_sender {
            return Err(Error::Protocol("key backup sender mismatch".to_owned()));
        }
        if backup.algorithm != KEY_BACKUP_ALGORITHM {
            return Err(Error::Protocol("unsupported key backup algorithm".to_owned()));
        }
        if sha256_hex(&backup.ciphertext) != backup.ciphertext_sha256 {
            return Err(Error::Protocol("key backup ciphertext digest mismatch".to_owned()));
        }
        let aad = E2eeKeyBackupAad {
            backup_id: backup.backup_id.clone(),
            version: backup.version,
            algorithm: backup.algorithm.clone(),
            sender: backup.sender.clone(),
            previous_backup_id: backup.previous_backup_id.clone(),
            key_ids: backup.key_ids.clone(),
        };
        let aad_bytes = crate::canonical::canonical_json_bytes(&aad)?;
        if sha256_hex(&aad_bytes) != backup.aad_sha256 {
            return Err(Error::Protocol("key backup AAD digest mismatch".to_owned()));
        }
        Ok(())
    }

    /// Build an E2EE message envelope.
    pub fn create_message(
        &self,
        message_id: impl Into<String>,
        group_id: &str,
        sender: Did,
        ciphertext: Vec<u8>,
    ) -> Result<E2eeMessage> {
        let group = self
            .groups
            .get(group_id)
            .ok_or_else(|| Error::Protocol("group not found".to_owned()))?;
        let message_id = message_id.into();
        let digest = message_digest(&message_id, group_id, group.epoch, &sender, &ciphertext);
        Ok(E2eeMessage {
            message_id,
            group_id: group_id.to_owned(),
            epoch: group.epoch,
            sender,
            ciphertext,
            digest,
        })
    }

    /// Validate sender membership, epoch, integrity and replay.
    pub fn validate_message(&mut self, message: &E2eeMessage) -> Result<()> {
        match self.inspect_message(message) {
            E2eeMessageValidation::Valid => {}
            E2eeMessageValidation::Invalid { failure } => {
                return Err(Error::Protocol(format!("message validation failed: {failure:?}")));
            }
        }
        self.seen_messages.insert(message.message_id.clone());
        self.log(
            AuditAction::MessageValidated,
            Some(message.sender.clone()),
            Some(message.group_id.clone()),
            "message validated",
        );
        Ok(())
    }

    /// Inspect a message without mutating replay state.
    pub fn inspect_message(&self, message: &E2eeMessage) -> E2eeMessageValidation {
        let Some(group) = self.groups.get(&message.group_id) else {
            return E2eeMessageValidation::Invalid {
                failure: E2eeMessageValidationFailure::UnknownGroup,
            };
        };
        if !group.members.contains(&message.sender) {
            return E2eeMessageValidation::Invalid {
                failure: E2eeMessageValidationFailure::WrongSender,
            };
        }
        if group.epoch != message.epoch {
            return E2eeMessageValidation::Invalid {
                failure: E2eeMessageValidationFailure::WrongEpoch {
                    local_epoch: group.epoch,
                    message_epoch: message.epoch,
                },
            };
        }
        let expected = message_digest(
            &message.message_id,
            &message.group_id,
            message.epoch,
            &message.sender,
            &message.ciphertext,
        );
        if expected != message.digest {
            return E2eeMessageValidation::Invalid {
                failure: E2eeMessageValidationFailure::IntegrityMismatch,
            };
        }
        if self.seen_messages.contains(&message.message_id) {
            return E2eeMessageValidation::Invalid {
                failure: E2eeMessageValidationFailure::Replay,
            };
        }
        E2eeMessageValidation::Valid
    }

    /// Get a group.
    pub fn group(&self, group_id: &str) -> Option<&E2eeGroup> {
        self.groups.get(group_id)
    }

    /// Revoke a device, causing all future encrypted writes from it to fail closed.
    pub fn revoke_device(&mut self, principal_id: &Did, device_id: &DeviceId) {
        self.revoked_devices.insert((principal_id.clone(), device_id.clone()), Utc::now());
    }

    /// Check if a device is revoked.
    pub fn is_device_revoked(&self, principal_id: &Did, device_id: &DeviceId) -> bool {
        self.revoked_devices.contains_key(&(principal_id.clone(), device_id.clone()))
    }

    /// Build an E2EE message envelope from a specific device, failing closed if the
    /// device is revoked.
    pub fn create_message_from_device(
        &self,
        message_id: impl Into<String>,
        group_id: &str,
        sender: Did,
        device_id: &DeviceId,
        ciphertext: Vec<u8>,
    ) -> Result<E2eeMessage> {
        if self.is_device_revoked(&sender, device_id) {
            return Err(Error::Protocol(format!(
                "device {} is revoked; encrypted writes fail closed",
                device_id.as_str()
            )));
        }
        self.create_message(message_id, group_id, sender, ciphertext)
    }

    /// Export audit entries.
    pub fn audit_entries(&self) -> &[AuditEntry] {
        &self.audit
    }

    /// Export audit entries as JSON.
    pub fn export_audit_json(&self) -> Result<String> {
        serde_json::to_string(&self.audit).map_err(Into::into)
    }

    fn group_mut(&mut self, group_id: &str) -> Result<&mut E2eeGroup> {
        self.groups.get_mut(group_id).ok_or_else(|| Error::Protocol("group not found".to_owned()))
    }

    fn open_backup_plaintext(
        &self,
        backup: &E2eeKeyBackup,
        backup_key: &[u8],
        expected_sender: Option<&Did>,
    ) -> Result<Vec<u8>> {
        if let Some(expected_sender) = expected_sender {
            self.validate_backup_authenticity(backup, expected_sender)?;
        } else if sha256_hex(&backup.ciphertext) != backup.ciphertext_sha256 {
            return Err(Error::Protocol("key backup ciphertext digest mismatch".to_owned()));
        }
        let aad = E2eeKeyBackupAad {
            backup_id: backup.backup_id.clone(),
            version: backup.version,
            algorithm: backup.algorithm.clone(),
            sender: backup.sender.clone(),
            previous_backup_id: backup.previous_backup_id.clone(),
            key_ids: backup.key_ids.clone(),
        };
        let aad_bytes = crate::canonical::canonical_json_bytes(&aad)?;
        if sha256_hex(&aad_bytes) != backup.aad_sha256 {
            return Err(Error::Protocol("key backup AAD digest mismatch".to_owned()));
        }
        let plaintext = crypto::open(&backup.ciphertext, backup_key, &aad_bytes)?;
        if sha256_hex(&plaintext) == backup.plaintext_sha256 {
            Ok(plaintext)
        } else {
            Err(Error::Protocol("key backup digest mismatch".to_owned()))
        }
    }

    fn log(
        &mut self,
        action: AuditAction,
        actor: Option<Did>,
        group_id: Option<String>,
        detail: impl Into<String>,
    ) {
        self.audit.push(AuditEntry {
            timestamp: Utc::now(),
            action,
            actor,
            group_id,
            detail: detail.into(),
        });
    }
}

fn message_digest(
    message_id: &str,
    group_id: &str,
    epoch: u64,
    sender: &Did,
    ciphertext: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message_id.as_bytes());
    hasher.update(group_id.as_bytes());
    hasher.update(epoch.to_le_bytes());
    hasher.update(sender.as_str().as_bytes());
    hasher.update(ciphertext);
    format!("{:x}", hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn e2ee_manages_groups_members_merge_and_epoch() {
        let alice = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let mut manager = E2eeManager::new();

        manager.create_group("g1", alice.clone(), BTreeSet::from([bob.clone()]));
        assert_eq!(manager.join_group("g1", carol.clone()).unwrap(), 1);
        assert_eq!(manager.remove_member("g1", &bob).unwrap(), 2);
        assert_eq!(manager.advance_epoch("g1", alice.clone()).unwrap(), 3);

        manager.create_group("g2", alice.clone(), BTreeSet::new());
        let merged =
            manager.merge_groups("g3", vec!["g1".to_owned(), "g2".to_owned()], alice).unwrap();
        assert!(merged.members.contains(&carol));
        assert_eq!(merged.merged_from.len(), 2);
    }

    #[test]
    fn e2ee_rotates_exports_backs_up_and_restores_keys() {
        let alice = did("alice");
        let mut manager = E2eeManager::new();
        manager.create_group("g1", alice.clone(), BTreeSet::new());

        let key = manager.rotate_key("g1", alice.clone(), b"secret-key".to_vec()).unwrap();
        assert_eq!(manager.export_key(&key.key_id, alice.clone()).unwrap(), b"secret-key");

        let backup = manager.backup_keys("b1", vec![key.key_id], b"backup-key", alice).unwrap();
        let restored = manager.restore_backup(&backup, b"backup-key").unwrap();
        assert!(serde_json::from_slice::<E2eeKeyBackupPlaintext>(&restored).is_ok());
        assert!(manager.restore_backup(&backup, b"wrong").is_err());
    }

    #[test]
    fn e2ee_restores_key_records_and_rejects_wrong_sender() {
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = E2eeManager::new();
        manager.create_group("g1", alice.clone(), BTreeSet::new());

        let key = manager.rotate_key("g1", alice.clone(), b"secret-key".to_vec()).unwrap();
        let backup = manager
            .backup_keys_with_rotation(
                "b2",
                2,
                Some("b1".to_owned()),
                vec![key.key_id],
                b"backup-key",
                alice.clone(),
            )
            .unwrap();

        assert_eq!(backup.previous_backup_id.as_deref(), Some("b1"));
        assert!(manager.validate_backup_authenticity(&backup, &alice).is_ok());
        assert!(manager.validate_backup_authenticity(&backup, &bob).is_err());

        let mut restored = E2eeManager::new();
        let records =
            restored.restore_key_records_from_backup(&backup, b"backup-key", &alice).unwrap();
        assert_eq!(records[0].key_bytes, b"secret-key");
    }

    #[test]
    fn e2ee_validates_sender_integrity_and_replay() {
        let alice = did("alice");
        let mut manager = E2eeManager::new();
        manager.create_group("g1", alice.clone(), BTreeSet::new());

        let message = manager.create_message("m1", "g1", alice, b"ciphertext".to_vec()).unwrap();
        assert_eq!(manager.inspect_message(&message), E2eeMessageValidation::Valid);
        manager.validate_message(&message).unwrap();
        assert_eq!(
            manager.inspect_message(&message),
            E2eeMessageValidation::Invalid { failure: E2eeMessageValidationFailure::Replay }
        );

        let mut tampered = message.clone();
        tampered.message_id = "m2".to_owned();
        tampered.ciphertext = b"changed".to_vec();
        assert_eq!(
            manager.inspect_message(&tampered),
            E2eeMessageValidation::Invalid {
                failure: E2eeMessageValidationFailure::IntegrityMismatch
            }
        );
    }

    #[test]
    fn e2ee_device_revocation_fails_closed_on_encrypted_writes() {
        let alice = did("alice");
        let device_id = DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap();
        let mut manager = E2eeManager::new();
        manager.create_group("g1", alice.clone(), BTreeSet::new());

        // Before revocation, message creation succeeds.
        let msg = manager
            .create_message_from_device(
                "m1",
                "g1",
                alice.clone(),
                &device_id,
                b"ciphertext".to_vec(),
            )
            .unwrap();
        assert_eq!(msg.sender, alice);

        // Revoke the device.
        manager.revoke_device(&alice, &device_id);
        assert!(manager.is_device_revoked(&alice, &device_id));

        // After revocation, encrypted writes fail closed.
        let result = manager.create_message_from_device(
            "m2",
            "g1",
            alice.clone(),
            &device_id,
            b"ciphertext".to_vec(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    #[test]
    fn e2ee_exports_audit_trail() {
        let alice = did("alice");
        let mut manager = E2eeManager::new();
        manager.create_group("g1", alice, BTreeSet::new());

        assert!(!manager.audit_entries().is_empty());
        assert!(manager.export_audit_json().unwrap().contains("group_created"));
    }
}
