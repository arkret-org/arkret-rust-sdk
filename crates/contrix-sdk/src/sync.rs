//! Client sync protocol implementation.
//!
//! This module implements the Contrix v1 client sync protocol:
//! - Incremental sync with cursors
//! - Backfill handling
//! - Device message handling
//! - Filter and subscription support

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use crate::{EventId, SpaceId};

/// Sync request for incremental synchronization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Previous sync token for incremental sync
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Timeout for long-polling (milliseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Presence status update
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_presence: Option<PresenceStatus>,
    /// Filter for selective sync
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<SyncFilter>,
    /// Space subscriptions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriptions: Option<SubscriptionConfig>,
}

/// Sync response from the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Token for the next sync
    pub next_batch: String,
    /// Space sync results
    #[serde(default)]
    pub spaces: BTreeMap<String, SyncSpace>,
    /// Matrix bridge compatibility. Native Contrix implementations should use `spaces`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rooms: BTreeMap<String, SyncSpace>,
    /// To-device messages
    #[serde(default)]
    pub to_device: Vec<ToDeviceMessage>,
    /// Device list changes
    #[serde(default)]
    pub device_lists: DeviceListChanges,
    /// Presence events
    #[serde(default)]
    pub presence: Vec<PresenceEvent>,
    /// Account data
    #[serde(default)]
    pub account_data: Vec<AccountData>,
    /// Notifications
    #[serde(default)]
    pub notifications: Vec<NotificationDelta>,
    /// Partial response flag
    #[serde(default)]
    pub partial: bool,
}

/// Sync result for a single Space.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SyncSpace {
    /// Timeline events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<SyncTimeline>,
    /// State events
    #[serde(default)]
    pub state: Vec<Value>,
    /// Summary information
    #[serde(default)]
    pub summary: Value,
    /// Ephemeral events
    #[serde(default)]
    pub ephemeral: Vec<Value>,
    /// Unread counts
    #[serde(default)]
    pub unread: UnreadCounts,
}

/// Timeline events with pagination.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncTimeline {
    /// Events in the timeline
    pub events: Vec<Value>,
    /// Limited flag (if true, history was limited)
    pub limited: bool,
    /// Previous batch token for backfill
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_batch: Option<String>,
}

/// Unread notification counts.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UnreadCounts {
    /// Notification count
    #[serde(default)]
    pub notification_count: u64,
    /// Highlight count
    #[serde(default)]
    pub highlight_count: u64,
}

/// Device list changes.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DeviceListChanges {
    /// Changed device lists
    #[serde(default)]
    pub changed: Vec<String>,
    /// Left users
    #[serde(default)]
    pub left: Vec<String>,
}

/// To-device message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToDeviceMessage {
    /// Message type
    #[serde(rename = "type")]
    pub message_type: String,
    /// Message content
    pub content: Value,
}

/// Presence status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Offline,
    Unavailable,
}

/// Presence event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceEvent {
    /// User ID
    pub user_id: String,
    /// Presence status
    pub presence: PresenceStatus,
    /// Last active timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active: Option<DateTime<Utc>>,
    /// Currently active device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// Account data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountData {
    /// Data type
    #[serde(rename = "type")]
    pub data_type: String,
    /// Data content
    pub content: Value,
}

/// Notification delta.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationDelta {
    /// Notification ID
    pub id: String,
    /// Notification type
    #[serde(rename = "type")]
    pub notification_type: String,
    /// Action (add/update/remove)
    pub action: String,
    /// Notification data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Sync filter for selective synchronization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncFilter {
    /// Space IDs to sync
    #[serde(default)]
    pub space_ids: Vec<SpaceId>,
    /// Entity types to filter
    #[serde(default)]
    pub entity_types: Vec<String>,
    /// Relation types to filter
    #[serde(default)]
    pub relation_types: Vec<String>,
    /// Minimum HLC
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_hlc: Option<String>,
    /// Maximum result count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Subscription configuration for spaces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    /// Space subscriptions
    pub subscriptions: Vec<SpaceSubscription>,
    /// Batch size for timeline
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    /// Timeline filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_filter: Option<Value>,
}

/// Space subscription.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpaceSubscription {
    /// Space ID
    pub space_id: SpaceId,
    /// Timeline filter (lazy loading, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_filter: Option<TimelineFilter>,
    /// Required state
    #[serde(default)]
    pub required_state: Vec<String>,
}

/// Timeline filter options.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineFilter {
    /// All events
    All,
    /// Only messages
    MessagesOnly,
    /// Custom filter
    Custom { filter: Value },
}

/// Backfill request for historical events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackfillRequest {
    /// Space ID to backfill
    pub space_id: SpaceId,
    /// Starting point (cursor or event ID)
    pub from: BackfillFrom,
    /// Direction
    #[serde(default)]
    pub direction: BackfillDirection,
    /// Maximum events to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Backfill starting point.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackfillFrom {
    /// Start from a cursor
    Cursor { cursor: String },
    /// Start from an event ID
    EventId { event_id: EventId },
    /// Start from the beginning
    Beginning,
}

/// Backfill direction.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackfillDirection {
    /// Backward (newer to older)
    #[default]
    Backward,
    /// Forward (older to newer)
    Forward,
    /// Both directions
    Both,
}

/// Backfill response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackfillResponse {
    /// Events in reverse chronological order
    pub events: Vec<Value>,
    /// Count of total events available
    pub total_count: u64,
    /// Next cursor for continued backfill
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Reached beginning of history
    pub beginning_of_history: bool,
    /// Reached end of history
    pub end_of_history: bool,
}

/// Sync client for managing incremental synchronization.
pub struct SyncClient {
    /// Current sync token
    current_token: Option<String>,
    /// Device ID
    _device_id: String,
    /// Active subscriptions
    subscriptions: HashMap<SpaceId, SpaceSubscription>,
}

impl SyncClient {
    /// Create a new sync client.
    pub fn new(device_id: String) -> Self {
        Self { current_token: None, _device_id: device_id, subscriptions: HashMap::new() }
    }

    /// Get the current sync token.
    pub fn current_token(&self) -> Option<&str> {
        self.current_token.as_deref()
    }

    /// Update the sync token from a response.
    pub fn update_token(&mut self, next_batch: String) {
        self.current_token = Some(next_batch);
    }

    /// Create a sync request with current token.
    pub fn create_request(&self) -> SyncRequest {
        SyncRequest {
            since: self.current_token.clone(),
            timeout_ms: Some(30000), // 30 second default
            set_presence: Some(PresenceStatus::Online),
            filter: None,
            subscriptions: None,
        }
    }

    /// Create a sync request with custom options.
    pub fn create_request_with_options(
        &self,
        timeout_ms: Option<u64>,
        filter: Option<SyncFilter>,
        subscriptions: Option<SubscriptionConfig>,
    ) -> SyncRequest {
        SyncRequest {
            since: self.current_token.clone(),
            timeout_ms,
            set_presence: Some(PresenceStatus::Online),
            filter,
            subscriptions,
        }
    }

    /// Process a sync response and extract updates.
    pub fn process_response(&mut self, response: SyncResponse) -> SyncUpdates {
        // Update token
        self.current_token = Some(response.next_batch);

        // Extract updates
        let mut space_updates = Vec::new();
        let spaces = if response.spaces.is_empty() { response.rooms } else { response.spaces };
        for (space_id, sync_space) in spaces {
            space_updates.push(SpaceUpdate {
                space_id: SpaceId::new(space_id).unwrap(),
                timeline: sync_space.timeline,
                state: sync_space.state,
                summary: sync_space.summary,
            });
        }

        SyncUpdates {
            space_updates,
            to_device: response.to_device,
            device_lists: response.device_lists,
            presence: response.presence,
            account_data: response.account_data,
            notifications: response.notifications,
            partial: response.partial,
        }
    }

    /// Subscribe to a space.
    pub fn subscribe(&mut self, subscription: SpaceSubscription) {
        self.subscriptions.insert(subscription.space_id.clone(), subscription);
    }

    /// Unsubscribe from a space.
    pub fn unsubscribe(&mut self, space_id: &SpaceId) {
        self.subscriptions.remove(space_id);
    }

    /// Get active subscriptions.
    pub fn subscriptions(&self) -> Vec<&SpaceSubscription> {
        self.subscriptions.values().collect()
    }

    /// Reset sync state (e.g., after reconnection).
    pub fn reset(&mut self) {
        self.current_token = None;
    }
}

impl Default for SyncClient {
    fn default() -> Self {
        Self::new("default".to_owned())
    }
}

/// Updates extracted from a sync response.
#[derive(Clone, Debug)]
pub struct SyncUpdates {
    /// Space updates
    pub space_updates: Vec<SpaceUpdate>,
    /// To-device messages
    pub to_device: Vec<ToDeviceMessage>,
    /// Device list changes
    pub device_lists: DeviceListChanges,
    /// Presence events
    pub presence: Vec<PresenceEvent>,
    /// Account data
    pub account_data: Vec<AccountData>,
    /// Notification deltas
    pub notifications: Vec<NotificationDelta>,
    /// Partial response flag
    pub partial: bool,
}

/// Update for a single space.
#[derive(Clone, Debug)]
pub struct SpaceUpdate {
    pub space_id: SpaceId,
    pub timeline: Option<SyncTimeline>,
    pub state: Vec<Value>,
    pub summary: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_request_serializes_correctly() {
        let request = SyncRequest {
            since: Some("token123".to_owned()),
            timeout_ms: Some(30000),
            set_presence: Some(PresenceStatus::Online),
            filter: None,
            subscriptions: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"since\":\"token123\""));
        assert!(json.contains("\"timeout_ms\":30000"));
    }

    #[test]
    fn sync_response_deserializes_correctly() {
        let json = r#"{
            "next_batch": "token456",
            "spaces": {
                "cx:space:01JS0SP000000000000000000": {
                    "timeline": {
                        "events": [],
                        "limited": false
                    },
                    "state": [],
                    "summary": {},
                    "ephemeral": [],
                    "unread": {
                        "notification_count": 0,
                        "highlight_count": 0
                    }
                }
            },
            "to_device": [],
            "device_lists": {
                "changed": [],
                "left": []
            },
            "presence": [],
            "account_data": [],
            "notifications": [],
            "partial": false
        }"#;

        let response: SyncResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.next_batch, "token456");
        assert_eq!(response.spaces.len(), 1);
    }

    #[test]
    fn sync_client_manages_token() {
        let mut client = SyncClient::new("device1".to_owned());
        assert!(client.current_token().is_none());

        client.update_token("token123".to_owned());
        assert_eq!(client.current_token(), Some("token123"));

        let request = client.create_request();
        assert_eq!(request.since, Some("token123".to_owned()));
    }

    #[test]
    fn sync_client_processes_response() {
        let mut client = SyncClient::new("device1".to_owned());

        let response = SyncResponse {
            next_batch: "token456".to_owned(),
            spaces: BTreeMap::new(),
            rooms: BTreeMap::new(),
            to_device: vec![],
            device_lists: DeviceListChanges::default(),
            presence: vec![],
            account_data: vec![],
            notifications: vec![],
            partial: false,
        };

        client.process_response(response);
        assert_eq!(client.current_token(), Some("token456"));
    }

    #[test]
    fn backfill_request_serializes_correctly() {
        let request = BackfillRequest {
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            from: BackfillFrom::Beginning,
            direction: BackfillDirection::Backward,
            limit: Some(100),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"space_id\""));
        assert!(json.contains("\"direction\":\"backward\""));
    }
}
