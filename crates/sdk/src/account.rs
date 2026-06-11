//! Account data management for Cokret v1.
//!
//! This module provides account data management for users, including:
//! - User-specific settings
//! - Client-specific data
//! - Account data synchronization

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::base::BaseClient;
use crate::{Did, Result};

/// Standard account-data type for the personal blocklist
/// (`moderation.md` §4.1).
pub const ACCOUNT_DATA_BLOCKLIST: &str = "ck.account.blocklist";

/// CKP R3 spec-sync (2026-05-27) — wire payload for `ck.account_data.set`.
/// Mirrors the spec event payload `account-data-set.schema.json` shape:
/// owner/key/body/encrypted_content/body_digest/tombstone/updated_at/
/// expected_state_digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDataSetPayload {
    /// Account owner DID. MUST equal the submitting actor.
    pub owner: Did,
    /// Account-data type key (e.g. `ck.account.blocklist`,
    /// `m.push_rules`).
    pub key: String,
    /// Cleartext body. Mutually exclusive with `encrypted_content`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// AEAD-wrapped body (preferred at rest for sensitive types).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    /// SHA-256 digest of the canonical body for tombstone-safe deletes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_digest: Option<String>,
    /// Tombstone marker — when true the entry is logically deleted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tombstone: bool,
    pub updated_at: DateTime<Utc>,
    /// CAS guard against expected per-key state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<String>,
}

/// CKP R3 spec-sync (2026-05-27) — `ck.account.blocklist` payload shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBlocklistPayload {
    pub owner: Did,
    pub version: u64,
    #[serde(default)]
    pub entries: Vec<AccountBlocklistPayloadEntry>,
}

/// Single entry inside an [`AccountBlocklistPayload`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBlocklistPayloadEntry {
    /// DID of the blocked subject.
    pub target: Did,
    /// Block mode (`hide`, `mute`, `block`, ...). Reducer treats unknown
    /// modes as `block` by default.
    pub mode: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Personal-blocklist entry.
///
/// The blocklist is **actor-private**: it MUST NOT be federated, MUST NOT
/// influence Space-level moderation decisions, and only filters the local
/// client's view. It complements (not replaces) Space `moderation_policy`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistEntry {
    pub block_did: Did,
    pub created_at: DateTime<Utc>,
    /// Optional automatic expiration. When `None`, the block is permanent
    /// until the local user removes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl BlocklistEntry {
    pub fn new(block_did: Did) -> Self {
        Self {
            block_did,
            created_at: Utc::now(),
            expires_at: None,
            reason: None,
        }
    }

    pub fn with_ttl(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.expires_at
            .map(|deadline| now < deadline)
            .unwrap_or(true)
    }
}

/// Personal blocklist (`ck.account.blocklist`) — actor-private filter list
/// kept in account data.
///
/// Storage rules per `moderation.md` §4.1:
///
/// - Persisted only as `ck.account.blocklist` account data (not as a shared Space state event).
/// - MUST NOT be exfiltrated to federation peers, push gateways, or directory services.
/// - When a Space is encrypted with MLS, the blocklist MAY be stored inside the actor's encrypted
///   account data backup, never as plaintext on the principal server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBlocklist {
    pub entries: BTreeMap<String, BlocklistEntry>,
}

impl AccountBlocklist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block(&mut self, entry: BlocklistEntry) {
        self.entries
            .insert(entry.block_did.as_str().to_owned(), entry);
    }

    pub fn unblock(&mut self, did: &Did) -> bool {
        self.entries.remove(did.as_str()).is_some()
    }

    pub fn is_blocked(&self, did: &Did, now: DateTime<Utc>) -> bool {
        self.entries
            .get(did.as_str())
            .is_some_and(|entry| entry.is_active(now))
    }

    /// Drop expired entries; returns the number removed.
    pub fn prune_expired(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.is_active(now));
        before - self.entries.len()
    }
}

/// Account data entry.
#[derive(Clone, Debug)]
pub struct AccountData {
    /// Data type
    pub data_type: String,
    /// Data content
    pub content: Value,
}

/// Account data manager.
#[derive(Clone)]
pub struct AccountDataManager {
    /// Base client reference
    _base_client: Arc<BaseClient>,
    /// Account data by type
    account_data: Arc<std::sync::RwLock<BTreeMap<String, AccountData>>>,
}

impl AccountDataManager {
    /// Create a new account data manager.
    pub fn new(base_client: Arc<BaseClient>) -> Self {
        Self {
            _base_client: base_client,
            account_data: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
        }
    }

    /// Get account data by type.
    pub fn get(&self, data_type: &str) -> Option<AccountData> {
        self.account_data
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(data_type)
            .cloned()
    }

    /// Set account data.
    pub fn set(&self, data_type: String, content: Value) -> Result<()> {
        let account_data = AccountData {
            data_type: data_type.clone(),
            content,
        };
        self.account_data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(data_type, account_data);
        Ok(())
    }

    /// Remove account data.
    pub fn remove(&self, data_type: &str) -> Result<()> {
        self.account_data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(data_type);
        Ok(())
    }

    /// Get all account data.
    pub fn all(&self) -> BTreeMap<String, AccountData> {
        self.account_data
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Clear all account data.
    pub fn clear(&self) -> Result<()> {
        self.account_data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_data_manager_sets_and_gets() {
        let base_client = Arc::new(BaseClient::new());
        let manager = AccountDataManager::new(base_client);

        let content = serde_json::json!({"theme": "dark"});
        manager.set("theme".to_owned(), content.clone()).unwrap();

        let retrieved = manager.get("theme").unwrap();
        assert_eq!(retrieved.data_type, "theme");
        assert_eq!(retrieved.content, content);
    }

    #[test]
    fn account_data_manager_removes() {
        let base_client = Arc::new(BaseClient::new());
        let manager = AccountDataManager::new(base_client);

        manager
            .set("test".to_owned(), serde_json::json!({"key": "value"}))
            .unwrap();
        assert!(manager.get("test").is_some());

        manager.remove("test").unwrap();
        assert!(manager.get("test").is_none());
    }

    #[test]
    fn account_data_manager_lists_all() {
        let base_client = Arc::new(BaseClient::new());
        let manager = AccountDataManager::new(base_client);

        manager
            .set("key1".to_owned(), serde_json::json!(1))
            .unwrap();
        manager
            .set("key2".to_owned(), serde_json::json!(2))
            .unwrap();

        let all = manager.all();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("key1"));
        assert!(all.contains_key("key2"));
    }

    #[test]
    fn blocklist_blocks_unblocks_and_expires() {
        use chrono::Duration;
        let alice = Did::new("did:web:alice.example").unwrap();
        let bob = Did::new("did:web:bob.example").unwrap();
        let now = Utc::now();
        let mut bl = AccountBlocklist::new();
        bl.block(BlocklistEntry::new(alice.clone()).with_reason("spam"));
        bl.block(BlocklistEntry::new(bob.clone()).with_ttl(now + Duration::seconds(60)));

        assert!(bl.is_blocked(&alice, now));
        assert!(bl.is_blocked(&bob, now));

        // After Bob's TTL elapses he is no longer blocked.
        let later = now + Duration::seconds(120);
        assert!(bl.is_blocked(&alice, later));
        assert!(!bl.is_blocked(&bob, later));

        // Pruning removes expired entries.
        assert_eq!(bl.prune_expired(later), 1);
        assert_eq!(bl.entries.len(), 1);

        // Unblock alice removes her permanently.
        assert!(bl.unblock(&alice));
        assert!(!bl.is_blocked(&alice, later));
    }
}
