//! E2EE state helpers for group, key, validation and audit management.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Did, Error, Result};

pub const TEST_ONLY_KEY_BACKUP_ALGORITHM: &str = "xorsha256.test-only.v1";

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
    /// Key IDs included in the backup.
    pub key_ids: Vec<String>,
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// Plaintext digest.
    pub plaintext_sha256: String,
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

/// E2EE manager.
#[derive(Clone, Debug, Default)]
pub struct E2eeManager {
    groups: BTreeMap<String, E2eeGroup>,
    keys: BTreeMap<String, E2eeKeyRecord>,
    seen_messages: BTreeSet<String>,
    audit: Vec<AuditEntry>,
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

    /// Create an encrypted backup of selected keys.
    ///
    /// This helper is intentionally marked test-only: it protects against
    /// accidental plaintext storage in examples, but it is not authenticated
    /// encryption and must not be used for production key backup.
    pub fn backup_keys(
        &mut self,
        backup_id: impl Into<String>,
        key_ids: Vec<String>,
        backup_key: &[u8],
        actor: Did,
    ) -> Result<E2eeKeyBackup> {
        let mut plaintext = Vec::new();
        for key_id in &key_ids {
            let key =
                self.keys.get(key_id).ok_or_else(|| Error::Protocol("key not found".to_owned()))?;
            plaintext.extend_from_slice(key_id.as_bytes());
            plaintext.push(0);
            plaintext.extend_from_slice(&key.key_bytes);
            plaintext.push(0xff);
        }
        let backup = E2eeKeyBackup {
            backup_id: backup_id.into(),
            key_ids,
            ciphertext: xor_sha256_stream(&plaintext, backup_key),
            plaintext_sha256: sha256_hex(&plaintext),
        };
        self.log(AuditAction::KeyBackedUp, Some(actor), None, "keys backed up");
        Ok(backup)
    }

    /// Restore a key backup payload.
    pub fn restore_backup(&self, backup: &E2eeKeyBackup, backup_key: &[u8]) -> Result<Vec<u8>> {
        let plaintext = xor_sha256_stream(&backup.ciphertext, backup_key);
        if sha256_hex(&plaintext) == backup.plaintext_sha256 {
            Ok(plaintext)
        } else {
            Err(Error::Protocol("key backup digest mismatch".to_owned()))
        }
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
        let group = self
            .groups
            .get(&message.group_id)
            .ok_or_else(|| Error::Protocol("group not found".to_owned()))?;
        if !group.members.contains(&message.sender) {
            return Err(Error::Protocol("sender is not a group member".to_owned()));
        }
        if group.epoch != message.epoch {
            return Err(Error::Protocol("message epoch mismatch".to_owned()));
        }
        let expected = message_digest(
            &message.message_id,
            &message.group_id,
            message.epoch,
            &message.sender,
            &message.ciphertext,
        );
        if expected != message.digest {
            return Err(Error::Protocol("message integrity mismatch".to_owned()));
        }
        if !self.seen_messages.insert(message.message_id.clone()) {
            return Err(Error::Protocol("replayed message".to_owned()));
        }
        self.log(
            AuditAction::MessageValidated,
            Some(message.sender.clone()),
            Some(message.group_id.clone()),
            "message validated",
        );
        Ok(())
    }

    /// Get a group.
    pub fn group(&self, group_id: &str) -> Option<&E2eeGroup> {
        self.groups.get(group_id)
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

fn xor_sha256_stream(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut counter = 0u64;
    for chunk in input.chunks(32) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
        let stream = hasher.finalize();
        for (index, byte) in chunk.iter().enumerate() {
            output.push(byte ^ stream[index]);
        }
        counter += 1;
    }
    output
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
        assert!(String::from_utf8_lossy(&restored).contains("secret-key"));
        assert!(manager.restore_backup(&backup, b"wrong").is_err());
    }

    #[test]
    fn e2ee_validates_sender_integrity_and_replay() {
        let alice = did("alice");
        let mut manager = E2eeManager::new();
        manager.create_group("g1", alice.clone(), BTreeSet::new());

        let message = manager.create_message("m1", "g1", alice, b"ciphertext".to_vec()).unwrap();
        manager.validate_message(&message).unwrap();
        assert!(manager.validate_message(&message).is_err());

        let mut tampered = message.clone();
        tampered.message_id = "m2".to_owned();
        tampered.ciphertext = b"changed".to_vec();
        assert!(manager.validate_message(&tampered).is_err());
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
