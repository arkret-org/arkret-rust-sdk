//! Presence management for Contrix v1.
//!
//! This module provides user presence management, including:
//! - Online/offline status tracking
//! - Last active timestamp
//! - Device-specific presence
//! - Presence status updates

use std::{collections::BTreeMap, sync::Arc};

use chrono::{DateTime, Utc};

use crate::{Result, base::BaseClient, model::Did, sync::PresenceStatus};

/// Presence information for a user.
#[derive(Clone, Debug)]
pub struct Presence {
    /// User DID
    pub user_id: Did,
    /// Current presence status
    pub status: PresenceStatus,
    /// Last active timestamp
    pub last_active: Option<DateTime<Utc>>,
    /// Currently active device
    pub active_device: Option<String>,
    /// Status message
    pub status_msg: Option<String>,
}

/// Presence manager.
#[derive(Clone)]
pub struct PresenceManager {
    /// Base client reference
    base_client: Arc<BaseClient>,
    /// Presence by user ID
    presence: Arc<std::sync::RwLock<BTreeMap<String, Presence>>>,
}

impl PresenceManager {
    /// Create a new presence manager.
    pub fn new(base_client: Arc<BaseClient>) -> Self {
        Self { base_client, presence: Arc::new(std::sync::RwLock::new(BTreeMap::new())) }
    }

    /// Get presence for a user.
    pub fn get(&self, user_id: &Did) -> Option<Presence> {
        self.presence.read().unwrap().get(user_id.as_str()).cloned()
    }

    /// Set presence for a user.
    pub fn set(&self, presence: Presence) -> Result<()> {
        let user_id = presence.user_id.as_str().to_owned();
        self.presence.write().unwrap().insert(user_id, presence);
        Ok(())
    }

    /// Update presence status for a user.
    pub fn update_status(&self, user_id: &Did, status: PresenceStatus) -> Result<()> {
        let mut presence_map = self.presence.write().unwrap();
        let entry = presence_map.entry(user_id.as_str().to_owned()).or_insert_with(|| Presence {
            user_id: user_id.clone(),
            status: PresenceStatus::Offline,
            last_active: None,
            active_device: None,
            status_msg: None,
        });

        entry.status = status;
        entry.last_active = Some(Utc::now());

        Ok(())
    }

    /// Set the current user's presence status.
    pub fn set_my_status(&self, status: PresenceStatus) -> Result<()> {
        if let Some(session_meta) = self.base_client.session_meta() {
            self.update_status(&session_meta.user_id, status)
        } else {
            Err(crate::Error::Protocol("no session".to_owned()))
        }
    }

    /// Get all online users.
    pub fn online_users(&self) -> Vec<Presence> {
        self.presence
            .read()
            .unwrap()
            .values()
            .filter(|p| p.status == PresenceStatus::Online)
            .cloned()
            .collect()
    }

    /// Get all users with a specific status.
    pub fn users_with_status(&self, status: PresenceStatus) -> Vec<Presence> {
        self.presence.read().unwrap().values().filter(|p| p.status == status).cloned().collect()
    }

    /// Get all presence data.
    pub fn all(&self) -> BTreeMap<String, Presence> {
        self.presence.read().unwrap().clone()
    }

    /// Clear all presence data.
    pub fn clear(&self) -> Result<()> {
        self.presence.write().unwrap().clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_manager_sets_and_gets() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user_id = Did::new("did:web:alice.example.com").unwrap();
        let presence = Presence {
            user_id: user_id.clone(),
            status: PresenceStatus::Online,
            last_active: Some(Utc::now()),
            active_device: None,
            status_msg: None,
        };

        manager.set(presence.clone()).unwrap();

        let retrieved = manager.get(&user_id).unwrap();
        assert_eq!(retrieved.status, PresenceStatus::Online);
        assert_eq!(retrieved.user_id, user_id);
    }

    #[test]
    fn presence_manager_updates_status() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user_id = Did::new("did:web:alice.example.com").unwrap();

        manager.update_status(&user_id, PresenceStatus::Online).unwrap();
        let presence = manager.get(&user_id).unwrap();
        assert_eq!(presence.status, PresenceStatus::Online);
        assert!(presence.last_active.is_some());

        manager.update_status(&user_id, PresenceStatus::Offline).unwrap();
        let presence = manager.get(&user_id).unwrap();
        assert_eq!(presence.status, PresenceStatus::Offline);
    }

    #[test]
    fn presence_manager_lists_online_users() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user1 = Did::new("did:web:alice.example.com").unwrap();
        let user2 = Did::new("did:web:bob.example.com").unwrap();

        manager.update_status(&user1, PresenceStatus::Online).unwrap();
        manager.update_status(&user2, PresenceStatus::Offline).unwrap();

        let online = manager.online_users();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].user_id, user1);
    }

    #[test]
    fn presence_manager_filters_by_status() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user1 = Did::new("did:web:alice.example.com").unwrap();
        let user2 = Did::new("did:web:bob.example.com").unwrap();
        let user3 = Did::new("did:web:charlie.example.com").unwrap();

        manager.update_status(&user1, PresenceStatus::Online).unwrap();
        manager.update_status(&user2, PresenceStatus::Unavailable).unwrap();
        manager.update_status(&user3, PresenceStatus::Unavailable).unwrap();

        let unavailable = manager.users_with_status(PresenceStatus::Unavailable);
        assert_eq!(unavailable.len(), 2);
    }
}
