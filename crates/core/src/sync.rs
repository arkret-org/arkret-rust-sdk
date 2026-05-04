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
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{DeviceId, Did, Error, Event, EventId, Hlc, Result, SpaceId, canonical};

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
    /// Optional frontier that the server should wait to observe before replying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<WaitForFrontier>,
}

/// Sync response from the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Token for the next sync
    pub next_batch: String,
    /// Space sync results
    #[serde(default)]
    pub spaces: BTreeMap<String, SyncSpace>,
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
    /// Transaction ID if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn_id: Option<String>,
    /// Message type
    #[serde(rename = "type")]
    pub message_type: String,
    /// Sender principal if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_principal_id: Option<Did>,
    /// Sender device if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<DeviceId>,
    /// Recipient principal if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    /// Recipient device if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    /// Message send time if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<DateTime<Utc>>,
    /// Message expiry if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Message content
    pub content: Value,
    /// Device proof if carried by the upstream envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<Value>,
    /// Unsigned service metadata if carried by the upstream envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Deterministic order key for timeline events.
///
/// Events sort by causal depth, HLC, actor ID, actor sequence and event ID. The
/// caller supplies causal depth because it depends on the known event graph.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TimelineOrderKey {
    /// Transitive causal depth in the local event graph.
    pub causal_depth: u64,
    /// Hybrid logical clock for the event.
    pub hlc: Hlc,
    /// Event actor.
    pub actor_id: Did,
    /// Actor-local sequence.
    pub actor_seq: u64,
    /// Event ID tie-breaker.
    pub event_id: EventId,
}

impl TimelineOrderKey {
    /// Build an order key from an event and a caller-computed causal depth.
    pub fn from_event(event: &Event, causal_depth: u64) -> Self {
        Self {
            causal_depth,
            hlc: event.hlc.clone(),
            actor_id: event.actor_id.clone(),
            actor_seq: event.actor_seq,
            event_id: event.event_id.clone(),
        }
    }
}

/// Stream position for one space at a sync boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStreamPosition {
    /// Space covered by this position.
    pub space_id: SpaceId,
    /// Causal frontier event IDs.
    #[serde(default)]
    pub frontier: Vec<EventId>,
    /// Last deterministic timeline order key observed for this space.
    pub timeline_order: Hlc,
    /// State hash or Merkle root at this point.
    pub state_hash: String,
}

impl SyncStreamPosition {
    /// Return true when this position covers the required frontier.
    pub fn covers(&self, required: &Self) -> bool {
        if self.space_id != required.space_id || self.timeline_order < required.timeline_order {
            return false;
        }
        if !required.state_hash.is_empty() && self.state_hash != required.state_hash {
            return false;
        }

        let frontier: BTreeSet<_> = self.frontier.iter().collect();
        required.frontier.iter().all(|event_id| frontier.contains(event_id))
    }
}

/// Hash the request filter and subscriptions for token binding.
pub fn sync_filter_hash(
    filter: Option<&SyncFilter>,
    subscriptions: Option<&SubscriptionConfig>,
) -> Result<String> {
    canonical::canonical_sha256(&serde_json::json!({
        "filter": filter,
        "subscriptions": subscriptions,
    }))
}

/// Sync token binding context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncTokenBinding {
    /// Opaque token received from the sync service.
    pub token: String,
    /// Principal this token belongs to.
    pub principal_id: Did,
    /// Device this token belongs to.
    pub device_id: DeviceId,
    /// Service that minted the token.
    pub service_id: Did,
    /// Canonical hash of filter and subscription shape.
    pub filter_hash: String,
    /// Stream positions captured by the token.
    #[serde(default)]
    pub positions: Vec<SyncStreamPosition>,
    /// Expiry time for the token.
    pub expires_at: DateTime<Utc>,
}

impl SyncTokenBinding {
    /// Create a binding for a concrete request context.
    #[allow(clippy::too_many_arguments)]
    pub fn for_request(
        token: String,
        principal_id: Did,
        device_id: DeviceId,
        service_id: Did,
        filter: Option<&SyncFilter>,
        subscriptions: Option<&SubscriptionConfig>,
        positions: Vec<SyncStreamPosition>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Ok(Self {
            token,
            principal_id,
            device_id,
            service_id,
            filter_hash: sync_filter_hash(filter, subscriptions)?,
            positions,
            expires_at,
        })
    }

    /// Validate that the token is being resumed by the same principal/device/service/filter.
    pub fn validate_context(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
        service_id: &Did,
        filter_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.expires_at <= now {
            return Err(Error::Protocol("sync token has expired".to_owned()));
        }
        if &self.principal_id != principal_id
            || &self.device_id != device_id
            || &self.service_id != service_id
            || self.filter_hash != filter_hash
        {
            return Err(Error::Protocol("sync token binding mismatch".to_owned()));
        }
        Ok(())
    }

    /// Whether the token has expired at `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// Whether a request starts from scratch or resumes an existing token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// No `since` token. The response should establish full local state.
    Initial,
    /// A `since` token is present. The response is an incremental delta.
    Incremental,
}

/// Client-visible sync semantics for one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSemantics {
    /// Initial or incremental.
    pub mode: SyncMode,
    /// Token used for incremental sync, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Initial sync establishes state for the requested scope.
    pub expects_full_state: bool,
    /// Incremental sync requires the token binding context to match.
    pub requires_token_binding: bool,
}

impl SyncSemantics {
    /// Derive semantics from a request.
    pub fn from_request(request: &SyncRequest) -> Self {
        let mode = if request.since.is_some() { SyncMode::Incremental } else { SyncMode::Initial };
        Self {
            mode,
            since: request.since.clone(),
            expects_full_state: mode == SyncMode::Initial,
            requires_token_binding: mode == SyncMode::Incremental,
        }
    }
}

/// Space membership bucket in sync responses and list projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipBucket {
    /// Joined spaces.
    Joined,
    /// Invited spaces.
    Invited,
    /// Spaces where the user has knocked/requested access.
    Knocked,
    /// Left spaces.
    Left,
}

/// A sync update assigned to one membership bucket.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketedSpaceUpdate {
    /// Bucket name.
    pub bucket: MembershipBucket,
    /// Updated space ID.
    pub space_id: SpaceId,
    /// Raw update payload.
    pub update: SyncSpace,
}

/// Reason a timeline gap exists locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncGapReason {
    /// Server returned `timeline.limited`.
    Limited,
    /// Sync token expired and local state must be reset or replayed.
    TokenExpired,
    /// Historical backfill is still pending.
    Backfill,
}

/// Backfill gap descriptor created from a limited timeline or token expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncGap {
    /// Space containing the gap.
    pub space_id: SpaceId,
    /// Older edge event if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_id: Option<EventId>,
    /// Newer edge event if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_event_id: Option<EventId>,
    /// Backfill token supplied by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_batch: Option<String>,
    /// Why the gap exists.
    pub reason: SyncGapReason,
}

/// Model for `timeline.limited` and the backfill work it creates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitedTimelineState {
    /// Space containing the limited timeline.
    pub space_id: SpaceId,
    /// Whether the timeline was limited.
    pub limited: bool,
    /// Previous batch token for historical pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_batch: Option<String>,
    /// Gap to persist and backfill, if limited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap: Option<SyncGap>,
}

impl LimitedTimelineState {
    /// Build limited timeline state from a sync timeline section.
    pub fn from_timeline(space_id: SpaceId, timeline: &SyncTimeline) -> Self {
        let prev_event_id = timeline.events.first().and_then(event_id_from_value);
        let next_event_id = timeline.events.last().and_then(event_id_from_value);
        let gap = timeline.limited.then(|| SyncGap {
            space_id: space_id.clone(),
            prev_event_id,
            next_event_id,
            prev_batch: timeline.prev_batch.clone(),
            reason: SyncGapReason::Limited,
        });

        Self { space_id, limited: timeline.limited, prev_batch: timeline.prev_batch.clone(), gap }
    }

    /// Convert this limited section into a backfill request, if one is needed.
    pub fn backfill_request(&self, limit: u32) -> Option<BackfillRequest> {
        let gap = self.gap.as_ref()?;
        Some(BackfillRequest {
            space_id: self.space_id.clone(),
            from: gap
                .prev_batch
                .as_ref()
                .map(|cursor| BackfillFrom::Cursor { cursor: cursor.clone() })
                .or_else(|| {
                    gap.prev_event_id
                        .as_ref()
                        .map(|event_id| BackfillFrom::EventId { event_id: event_id.clone() })
                })
                .unwrap_or(BackfillFrom::Beginning),
            direction: BackfillDirection::Backward,
            limit: Some(limit),
        })
    }
}

/// `X-Contrix-Wait-For` frontier wait request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitForFrontier {
    /// Required positions before the server should return.
    #[serde(default)]
    pub positions: Vec<SyncStreamPosition>,
    /// Maximum wait time in milliseconds.
    pub timeout_ms: u64,
}

impl WaitForFrontier {
    /// Return true when the current positions satisfy every requested frontier.
    pub fn is_satisfied_by(&self, current: &[SyncStreamPosition]) -> bool {
        self.positions
            .iter()
            .all(|required| current.iter().any(|position| position.covers(required)))
    }
}

/// To-device delivery acknowledgement state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToDeviceAckStatus {
    /// Message was received by the client SDK.
    Received,
    /// Message was decrypted and handed to the consumer.
    Processed,
    /// Message failed permanently.
    Failed,
}

/// Acknowledgement for one to-device message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToDeviceAck {
    /// Message ID from to-device content.
    pub message_id: String,
    /// Local device acknowledging the message.
    pub device_id: DeviceId,
    /// Acknowledgement status.
    pub status: ToDeviceAckStatus,
    /// Client acknowledgement time.
    pub acknowledged_at: DateTime<Utc>,
}

fn event_id_from_value(value: &Value) -> Option<EventId> {
    serde_json::from_value::<Event>(value.clone()).ok().map(|event| event.event_id)
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
            wait_for: None,
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
            wait_for: None,
        }
    }

    /// Process a sync response and extract updates.
    pub fn process_response(&mut self, response: SyncResponse) -> SyncUpdates {
        // Update token
        self.current_token = Some(response.next_batch);

        // Extract updates
        let mut space_updates = Vec::new();
        for (space_id, sync_space) in response.spaces {
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
            wait_for: None,
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

    #[test]
    fn sync_semantics_distinguish_initial_and_incremental() {
        let mut request = SyncClient::new("device1".to_owned()).create_request();
        let initial = SyncSemantics::from_request(&request);

        assert_eq!(initial.mode, SyncMode::Initial);
        assert!(initial.expects_full_state);
        assert!(!initial.requires_token_binding);

        request.since = Some("token123".to_owned());
        let incremental = SyncSemantics::from_request(&request);

        assert_eq!(incremental.mode, SyncMode::Incremental);
        assert!(!incremental.expects_full_state);
        assert!(incremental.requires_token_binding);
    }

    #[test]
    fn token_binding_checks_principal_device_service_filter_and_expiry() {
        let principal = Did::new("did:web:alice.example").unwrap();
        let device = DeviceId::new("dev_123").unwrap();
        let service = Did::new("did:web:sync.example").unwrap();
        let filter = SyncFilter {
            space_ids: vec![SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap()],
            entity_types: vec!["message".to_owned()],
            relation_types: Vec::new(),
            min_hlc: None,
            limit: Some(20),
        };
        let filter_hash = sync_filter_hash(Some(&filter), None).unwrap();
        let binding = SyncTokenBinding::for_request(
            "token123".to_owned(),
            principal.clone(),
            device.clone(),
            service.clone(),
            Some(&filter),
            None,
            Vec::new(),
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap();

        binding.validate_context(&principal, &device, &service, &filter_hash, Utc::now()).unwrap();
        assert!(
            binding
                .validate_context(
                    &principal,
                    &device,
                    &service,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    Utc::now(),
                )
                .is_err()
        );
    }

    #[test]
    fn timeline_order_key_uses_causal_depth_then_hlc_actor_sequence_and_event() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let actor = Did::new("did:web:alice.example").unwrap();
        let mut newer_hlc = Event::new(
            "cx.message.create",
            space_id.clone(),
            actor.clone(),
            2,
            Hlc::new("01970e589d22-00000000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"newer"}),
        )
        .unwrap();
        newer_hlc.event_id = EventId::new("cx:event:0002").unwrap();
        let mut deeper = Event::new(
            "cx.message.create",
            space_id,
            actor,
            1,
            Hlc::new("01970e589d21-00000000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"deeper"}),
        )
        .unwrap();
        deeper.event_id = EventId::new("cx:event:0001").unwrap();

        let mut keys =
            [TimelineOrderKey::from_event(&newer_hlc, 0), TimelineOrderKey::from_event(&deeper, 1)];
        keys.sort();

        assert_eq!(keys[0].event_id, newer_hlc.event_id);
        assert_eq!(keys[1].event_id, deeper.event_id);
    }

    #[test]
    fn wait_for_frontier_requires_covering_positions() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let event_id = EventId::new("cx:event:0001").unwrap();
        let required = SyncStreamPosition {
            space_id: space_id.clone(),
            frontier: vec![event_id.clone()],
            timeline_order: Hlc::new("01970e589d21-00000000-a13f9c2e").unwrap(),
            state_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };
        let wait_for = WaitForFrontier { positions: vec![required], timeout_ms: 1500 };
        let current = SyncStreamPosition {
            space_id,
            frontier: vec![event_id],
            timeline_order: Hlc::new("01970e589d22-00000000-a13f9c2e").unwrap(),
            state_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };

        assert!(wait_for.is_satisfied_by(&[current]));
    }

    #[test]
    fn limited_timeline_creates_backfill_gap_and_request() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let event = Event::new(
            "cx.message.create",
            space_id.clone(),
            Did::new("did:web:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-00000000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"hello"}),
        )
        .unwrap();
        let timeline = SyncTimeline {
            events: vec![serde_json::to_value(event).unwrap()],
            limited: true,
            prev_batch: Some("backfill-token".to_owned()),
        };

        let state = LimitedTimelineState::from_timeline(space_id, &timeline);
        let request = state.backfill_request(25).unwrap();

        assert!(state.gap.is_some());
        assert!(matches!(request.from, BackfillFrom::Cursor { .. }));
        assert_eq!(request.limit, Some(25));
    }
}
