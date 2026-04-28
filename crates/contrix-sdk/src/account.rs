//! Account data management for Contrix v1.
//!
//! This module provides account data management for users, including:
//! - User-specific settings
//! - Client-specific data
//! - Account data synchronization

use std::{
    collections::BTreeMap,
    sync::Arc,
};

use serde_json::Value;

use crate::{
    base::BaseClient,
    model::Did,
    Result,
};

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
    base_client: Arc<BaseClient>,
    /// Account data by type
    account_data: Arc<std::sync::RwLock<BTreeMap<String, AccountData>>>,
}

impl AccountDataManager {
    /// Create a new account data manager.
    pub fn new(base_client: Arc<BaseClient>) -> Self {
        Self {
            base_client,
            account_data: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
        }
    }

    /// Get account data by type.
    pub fn get(&self, data_type: &str) -> Option<AccountData> {
        self.account_data
            .read()
            .unwrap()
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
            .unwrap()
            .insert(data_type, account_data);
        Ok(())
    }

    /// Remove account data.
    pub fn remove(&self, data_type: &str) -> Result<()> {
        self.account_data
            .write()
            .unwrap()
            .remove(data_type);
        Ok(())
    }

    /// Get all account data.
    pub fn all(&self) -> BTreeMap<String, AccountData> {
        self.account_data.read().unwrap().clone()
    }

    /// Clear all account data.
    pub fn clear(&self) -> Result<()> {
        self.account_data.write().unwrap().clear();
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

        manager.set("test".to_owned(), serde_json::json!({"key": "value"})).unwrap();
        assert!(manager.get("test").is_some());

        manager.remove("test").unwrap();
        assert!(manager.get("test").is_none());
    }

    #[test]
    fn account_data_manager_lists_all() {
        let base_client = Arc::new(BaseClient::new());
        let manager = AccountDataManager::new(base_client);

        manager.set("key1".to_owned(), serde_json::json!(1)).unwrap();
        manager.set("key2".to_owned(), serde_json::json!(2)).unwrap();

        let all = manager.all();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("key1"));
        assert!(all.contains_key("key2"));
    }
}
