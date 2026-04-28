//! Base client state machine for Contrix v1.
//!
//! This module implements the core client state management without IO operations.
//! It handles:
//! - Session management
//! - Sync token tracking
//! - Space state management
//! - Event processing and state resolution
//! - Read markers and notifications

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use crate::{
    Result,
    cursor::SyncTracker,
    model::{DeviceId, Did, Event, SpaceId},
    resolver::SpaceState,
    store::{MemoryRepoStore, RepoStore},
};

/// Session metadata for the authenticated user.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    /// User DID
    pub user_id: Did,
    /// Device ID
    pub device_id: DeviceId,
    /// Access token (if using token-based auth)
    pub access_token: Option<String>,
    /// Session expiration
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl SessionMeta {
    /// Create new session metadata.
    pub fn new(user_id: Did, device_id: DeviceId) -> Self {
        Self { user_id, device_id, access_token: None, expires_at: None }
    }

    /// Check if the session is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at { chrono::Utc::now() > expires_at } else { false }
    }
}

/// Space state in the client.
#[derive(Clone, Debug)]
pub struct ClientSpace {
    /// Space ID
    pub space_id: SpaceId,
    /// Current state (joined, left, invited)
    pub state: SpaceStateType,
    /// Resolved space state
    pub space_state: SpaceState,
    /// Read marker for this space
    pub read_marker: Option<String>,
    /// Notification count
    pub notification_count: u64,
    /// Highlight count
    pub highlight_count: u64,
}

/// Space membership state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceStateType {
    /// User is a member of the space
    Joined,
    /// User has left the space
    Left,
    /// User is invited to the space
    Invited,
}

/// Base client state machine.
///
/// This client manages all local state without performing IO operations.
/// It processes sync responses and maintains the current state of spaces.
#[derive(Clone)]
pub struct BaseClient {
    /// Session metadata
    session: Arc<RwLock<Option<SessionMeta>>>,
    /// Current sync tracker
    sync_tracker: Arc<RwLock<SyncTracker>>,
    /// Space states by space ID
    spaces: Arc<RwLock<BTreeMap<String, ClientSpace>>>,
    /// Repo store
    store: Arc<dyn RepoStore>,
}

impl BaseClient {
    /// Create a new base client with default memory store.
    pub fn new() -> Self {
        Self::with_store(Arc::new(MemoryRepoStore::new()))
    }

    /// Create a new base client with a custom store.
    pub fn with_store(store: Arc<dyn RepoStore>) -> Self {
        Self {
            session: Arc::new(RwLock::new(None)),
            sync_tracker: Arc::new(RwLock::new(SyncTracker::new())),
            spaces: Arc::new(RwLock::new(BTreeMap::new())),
            store,
        }
    }

    /// Get the current session metadata.
    pub fn session_meta(&self) -> Option<SessionMeta> {
        self.session.read().unwrap().as_ref().cloned()
    }

    /// Set the session metadata.
    pub fn set_session_meta(&self, meta: SessionMeta) -> Result<()> {
        let mut session = self.session.write().unwrap();
        *session = Some(meta);
        Ok(())
    }

    /// Clear the session (logout).
    pub fn clear_session(&self) -> Result<()> {
        let mut session = self.session.write().unwrap();
        *session = None;

        // Clear sync state
        let mut tracker = self.sync_tracker.write().unwrap();
        tracker.clear();

        // Clear all spaces
        let mut spaces = self.spaces.write().unwrap();
        spaces.clear();

        Ok(())
    }

    /// Check if the client has an active session.
    pub fn is_logged_in(&self) -> bool {
        let session = self.session.read().unwrap();
        match session.as_ref() {
            Some(meta) => !meta.is_expired(),
            None => false,
        }
    }

    /// Get the current sync token.
    pub fn sync_token(&self) -> Option<String> {
        let tracker = self.sync_tracker.read().unwrap();
        tracker.sync_tokens.get("default").cloned()
    }

    /// Get the current cursor for resuming sync.
    pub fn current_cursor(&self) -> Result<crate::Cursor> {
        let tracker = self.sync_tracker.read().unwrap();
        tracker.current_cursor()
    }

    /// Get a space by ID.
    pub fn get_space(&self, space_id: &SpaceId) -> Option<ClientSpace> {
        let spaces = self.spaces.read().unwrap();
        spaces.get(space_id.as_str()).cloned()
    }

    /// Get all joined spaces.
    pub fn joined_spaces(&self) -> Vec<ClientSpace> {
        let spaces = self.spaces.read().unwrap();
        spaces.values().filter(|s| s.state == SpaceStateType::Joined).cloned().collect()
    }

    /// Get all invited spaces.
    pub fn invited_spaces(&self) -> Vec<ClientSpace> {
        let spaces = self.spaces.read().unwrap();
        spaces.values().filter(|s| s.state == SpaceStateType::Invited).cloned().collect()
    }

    /// Get all left spaces.
    pub fn left_spaces(&self) -> Vec<ClientSpace> {
        let spaces = self.spaces.read().unwrap();
        spaces.values().filter(|s| s.state == SpaceStateType::Left).cloned().collect()
    }

    /// Process events and update space states.
    pub fn process_events(&self, space_id: &SpaceId, events: Vec<Event>) -> Result<()> {
        // Get or create the client space
        let mut spaces = self.spaces.write().unwrap();
        let client_space = spaces.entry(space_id.as_str().to_owned()).or_insert_with(|| {
            let space_state = SpaceState::new(space_id.clone(), "1".to_owned());
            ClientSpace {
                space_id: space_id.clone(),
                state: SpaceStateType::Joined,
                space_state,
                read_marker: None,
                notification_count: 0,
                highlight_count: 0,
            }
        });

        // Apply events to the space state
        client_space.space_state.apply_events(&events)?;

        Ok(())
    }

    /// Update space membership state.
    pub fn update_space_state(&self, space_id: &SpaceId, state: SpaceStateType) -> Result<()> {
        let mut spaces = self.spaces.write().unwrap();
        let client_space = spaces.entry(space_id.as_str().to_owned()).or_insert_with(|| {
            let space_state = SpaceState::new(space_id.clone(), "1".to_owned());
            ClientSpace {
                space_id: space_id.clone(),
                state,
                space_state,
                read_marker: None,
                notification_count: 0,
                highlight_count: 0,
            }
        });
        client_space.state = state;
        Ok(())
    }

    /// Update unread counts for a space.
    pub fn update_unread_counts(
        &self,
        space_id: &SpaceId,
        notification_count: u64,
        highlight_count: u64,
    ) -> Result<()> {
        let mut spaces = self.spaces.write().unwrap();
        if let Some(client_space) = spaces.get_mut(space_id.as_str()) {
            client_space.notification_count = notification_count;
            client_space.highlight_count = highlight_count;
        }
        Ok(())
    }

    /// Set the read marker for a space.
    pub fn set_read_marker(&self, space_id: &SpaceId, marker: String) -> Result<()> {
        let mut spaces = self.spaces.write().unwrap();
        if let Some(client_space) = spaces.get_mut(space_id.as_str()) {
            client_space.read_marker = Some(marker);
        }
        Ok(())
    }

    /// Get the read marker for a space.
    pub fn read_marker(&self, space_id: &SpaceId) -> Option<String> {
        let spaces = self.spaces.read().unwrap();
        spaces.get(space_id.as_str()).and_then(|s| s.read_marker.clone())
    }

    /// Get the underlying store.
    pub fn store(&self) -> Arc<dyn RepoStore> {
        self.store.clone()
    }
}

impl Default for BaseClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_meta_checks_expiration() {
        let meta = SessionMeta {
            user_id: Did::new("did:web:alice.example.com").unwrap(),
            device_id: DeviceId::new("dev_123").unwrap(),
            access_token: Some("token".to_owned()),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        };

        assert!(meta.is_expired());
    }

    #[test]
    fn session_meta_valid_when_not_expired() {
        let meta = SessionMeta {
            user_id: Did::new("did:web:alice.example.com").unwrap(),
            device_id: DeviceId::new("dev_123").unwrap(),
            access_token: Some("token".to_owned()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        };

        assert!(!meta.is_expired());
    }

    #[test]
    fn base_client_starts_with_no_session() {
        let client = BaseClient::new();
        assert!(!client.is_logged_in());
        assert!(client.session_meta().is_none());
    }

    #[test]
    fn base_client_can_set_session() {
        let client = BaseClient::new();
        let meta = SessionMeta::new(
            Did::new("did:web:alice.example.com").unwrap(),
            DeviceId::new("dev_123").unwrap(),
        );

        client.set_session_meta(meta.clone()).unwrap();
        assert!(client.is_logged_in());

        let retrieved = client.session_meta().unwrap();
        assert_eq!(retrieved.user_id, meta.user_id);
        assert_eq!(retrieved.device_id, meta.device_id);
    }

    #[test]
    fn base_client_clears_session() {
        let client = BaseClient::new();
        let meta = SessionMeta::new(
            Did::new("did:web:alice.example.com").unwrap(),
            DeviceId::new("dev_123").unwrap(),
        );

        client.set_session_meta(meta).unwrap();
        assert!(client.is_logged_in());

        client.clear_session().unwrap();
        assert!(!client.is_logged_in());
    }

    #[test]
    fn base_client_tracks_space_state() {
        let client = BaseClient::new();
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();

        client.update_space_state(&space_id, SpaceStateType::Joined).unwrap();

        let space = client.get_space(&space_id);
        assert!(space.is_some());
        assert_eq!(space.unwrap().state, SpaceStateType::Joined);
    }

    #[test]
    fn base_client_filters_joined_spaces() {
        let client = BaseClient::new();
        let space1 = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let space2 = SpaceId::new("cx:space:01JS0SP000000000000000001").unwrap();
        let space3 = SpaceId::new("cx:space:01JS0SP000000000000000002").unwrap();

        client.update_space_state(&space1, SpaceStateType::Joined).unwrap();
        client.update_space_state(&space2, SpaceStateType::Left).unwrap();
        client.update_space_state(&space3, SpaceStateType::Invited).unwrap();

        let joined = client.joined_spaces();
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].space_id, space1);

        let left = client.left_spaces();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].space_id, space2);

        let invited = client.invited_spaces();
        assert_eq!(invited.len(), 1);
        assert_eq!(invited[0].space_id, space3);
    }
}
