//! Stateful sync client utilities.
//!
//! The protocol types live in [`crate::sync`]. This module adds the client-side
//! control plane: retry/backoff state, response processing and sliding-window
//! subscription helpers.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DeviceId, Did, Error, Event, EventId, Result, SpaceId, canonical,
    sync::{
        AccountData, DeviceListChanges, NotificationDelta, PresenceEvent, PresenceStatus,
        LimitedTimelineState, MembershipBucket, SpaceSubscription, SpaceUpdate,
        SubscriptionConfig, SyncFilter, SyncRequest, SyncResponse, SyncTimeline, SyncUpdates,
        TimelineFilter, TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, ToDeviceMessage,
        WaitForFrontier,
    },
};

/// Retry configuration for sync failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackoffConfig {
    /// Initial delay after the first failure.
    pub initial_delay: Duration,
    /// Maximum delay after repeated failures.
    pub max_delay: Duration,
    /// Multiplier applied after each failure.
    pub multiplier: u32,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            multiplier: 2,
        }
    }
}

/// Exponential backoff state.
#[derive(Clone, Debug)]
pub struct ExponentialBackoff {
    config: BackoffConfig,
    failures: u32,
}

impl ExponentialBackoff {
    /// Create backoff state with a custom configuration.
    pub fn new(config: BackoffConfig) -> Self {
        Self { config, failures: 0 }
    }

    /// Record a failed sync attempt and return the next wait duration.
    pub fn record_failure(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        self.current_delay()
    }

    /// Clear failure state after a successful sync.
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    /// Number of consecutive failures.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Current delay for the consecutive failure count.
    pub fn current_delay(&self) -> Duration {
        if self.failures == 0 {
            return Duration::ZERO;
        }

        let exponent = self.failures.saturating_sub(1);
        let factor = self.config.multiplier.saturating_pow(exponent);
        self.config.initial_delay.saturating_mul(factor).min(self.config.max_delay)
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(BackoffConfig::default())
    }
}

/// Result of one sync-loop iteration.
#[derive(Clone, Debug)]
pub enum SyncLoopStep {
    /// A response was processed successfully.
    Updates(SyncUpdates),
    /// Sync failed; caller should wait for `retry_after` before trying again.
    Retry { retry_after: Duration, error: String },
}

/// Minimal transport abstraction used by [`SyncLoop`].
pub trait SyncTransport {
    /// Execute one sync request.
    fn sync(&mut self, request: SyncRequest) -> Result<SyncResponse>;
}

impl<F> SyncTransport for F
where
    F: FnMut(SyncRequest) -> Result<SyncResponse>,
{
    fn sync(&mut self, request: SyncRequest) -> Result<SyncResponse> {
        self(request)
    }
}

/// Long-polling sync loop state.
pub struct SyncLoop {
    token: Option<String>,
    timeout: Duration,
    presence: Option<PresenceStatus>,
    filter: Option<SyncFilter>,
    subscriptions: Option<SubscriptionConfig>,
    wait_for: Option<WaitForFrontier>,
    backoff: ExponentialBackoff,
    processor: SyncResponseProcessor,
}

impl SyncLoop {
    /// Create a sync loop with a 30 second long-poll timeout.
    pub fn new() -> Self {
        Self {
            token: None,
            timeout: Duration::from_secs(30),
            presence: Some(PresenceStatus::Online),
            filter: None,
            subscriptions: None,
            wait_for: None,
            backoff: ExponentialBackoff::default(),
            processor: SyncResponseProcessor::new(),
        }
    }

    /// Set the long-poll timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the filter sent with each request.
    pub fn with_filter(mut self, filter: SyncFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set subscriptions sent with each request.
    pub fn with_subscriptions(mut self, subscriptions: SubscriptionConfig) -> Self {
        self.subscriptions = Some(subscriptions);
        self
    }

    /// Set a frontier the server should wait for before returning.
    pub fn with_wait_for(mut self, wait_for: WaitForFrontier) -> Self {
        self.wait_for = Some(wait_for);
        self
    }

    /// Build the next long-poll request.
    pub fn next_request(&self) -> SyncRequest {
        let timeout_ms = self.timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        SyncRequest {
            since: self.token.clone(),
            timeout_ms: Some(timeout_ms),
            set_presence: self.presence.clone(),
            filter: self.filter.clone(),
            subscriptions: self.subscriptions.clone(),
            wait_for: self.wait_for.clone(),
        }
    }

    /// Execute one loop iteration.
    ///
    /// The caller owns sleeping and cancellation. This keeps the type portable
    /// across native and WASM runtimes.
    pub fn step<T>(&mut self, transport: &mut T) -> SyncLoopStep
    where
        T: SyncTransport,
    {
        let request = self.next_request();
        match transport.sync(request) {
            Ok(response) => {
                self.backoff.reset();
                self.token = Some(response.next_batch.clone());
                match self.processor.process(response) {
                    Ok(updates) => SyncLoopStep::Updates(updates),
                    Err(error) => {
                        let retry_after = self.backoff.record_failure();
                        SyncLoopStep::Retry { retry_after, error: error.to_string() }
                    }
                }
            }
            Err(error) => {
                let retry_after = self.backoff.record_failure();
                SyncLoopStep::Retry { retry_after, error: error.to_string() }
            }
        }
    }

    /// Current sync token.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Reset the loop after unrecoverable state loss.
    pub fn reset(&mut self) {
        self.token = None;
        self.backoff.reset();
        self.processor.clear();
    }
}

impl Default for SyncLoop {
    fn default() -> Self {
        Self::new()
    }
}

/// Processed sync response cache and dispatcher.
#[derive(Clone, Debug, Default)]
pub struct SyncResponseProcessor {
    spaces: BTreeMap<SpaceId, ProcessedSpace>,
    limited_timelines: BTreeMap<SpaceId, LimitedTimelineState>,
    to_device: VecDeque<ToDeviceMessage>,
    to_device_acks: BTreeMap<String, ToDeviceAck>,
    changed_device_lists: BTreeSet<String>,
    left_device_lists: BTreeSet<String>,
    presence: BTreeMap<String, PresenceEvent>,
    account_data: BTreeMap<String, AccountData>,
    notifications: BTreeMap<String, NotificationDelta>,
    last_token: Option<String>,
}

impl SyncResponseProcessor {
    /// Create an empty response processor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a full sync response into a delta and update local caches.
    pub fn process(&mut self, response: SyncResponse) -> Result<SyncUpdates> {
        self.last_token = Some(response.next_batch);

        let mut space_updates = Vec::new();
        let spaces = if response.spaces.is_empty() { response.rooms } else { response.spaces };
        for (raw_space_id, sync_space) in spaces {
            let space_id = SpaceId::new(raw_space_id)?;
            let processed = self.spaces.entry(space_id.clone()).or_default();
            if let Some(timeline) = &sync_space.timeline {
                processed.timeline_events += timeline.events.len();
                processed.last_timeline = Some(timeline.clone());
                processed.last_limited = timeline.limited;
                processed.last_prev_batch = timeline.prev_batch.clone();
                if timeline.limited {
                    let limited = LimitedTimelineState::from_timeline(space_id.clone(), timeline);
                    processed.limited_timeline_count += 1;
                    processed.pending_gap = limited.gap.clone();
                    self.limited_timelines.insert(space_id.clone(), limited);
                }
            }
            processed.state_events += sync_space.state.len();
            processed.summary = sync_space.summary.clone();
            processed.notification_count = sync_space.unread.notification_count;
            processed.highlight_count = sync_space.unread.highlight_count;

            space_updates.push(SpaceUpdate {
                space_id,
                timeline: sync_space.timeline,
                state: sync_space.state,
                summary: sync_space.summary,
            });
        }

        for message in &response.to_device {
            self.to_device.push_back(message.clone());
        }
        for user_id in &response.device_lists.changed {
            self.changed_device_lists.insert(user_id.clone());
        }
        for user_id in &response.device_lists.left {
            self.left_device_lists.insert(user_id.clone());
        }
        for event in &response.presence {
            self.presence.insert(event.user_id.clone(), event.clone());
        }
        for item in &response.account_data {
            self.account_data.insert(item.data_type.clone(), item.clone());
        }
        for notification in &response.notifications {
            self.notifications.insert(notification.id.clone(), notification.clone());
        }

        Ok(SyncUpdates {
            space_updates,
            to_device: response.to_device,
            device_lists: response.device_lists,
            presence: response.presence,
            account_data: response.account_data,
            notifications: response.notifications,
            partial: response.partial,
        })
    }

    /// Get cached data for a processed space.
    pub fn space(&self, space_id: &SpaceId) -> Option<&ProcessedSpace> {
        self.spaces.get(space_id)
    }

    /// Drain queued to-device messages in receive order.
    pub fn drain_to_device(&mut self) -> Vec<ToDeviceMessage> {
        self.to_device.drain(..).collect()
    }

    /// Acknowledge a to-device message by ID for the local device.
    pub fn acknowledge_to_device(
        &mut self,
        message_id: impl Into<String>,
        device_id: DeviceId,
        status: ToDeviceAckStatus,
    ) -> ToDeviceAck {
        let message_id = message_id.into();
        let ack = ToDeviceAck { message_id: message_id.clone(), device_id, status, acknowledged_at: Utc::now() };
        self.to_device_acks.insert(message_id, ack.clone());
        ack
    }

    /// Get an acknowledgement for one to-device message.
    pub fn to_device_ack(&self, message_id: &str) -> Option<&ToDeviceAck> {
        self.to_device_acks.get(message_id)
    }

    /// Pending limited timeline sections that need backfill.
    pub fn limited_timelines(&self) -> Vec<&LimitedTimelineState> {
        self.limited_timelines.values().collect()
    }

    /// Last successfully processed sync token.
    pub fn last_token(&self) -> Option<&str> {
        self.last_token.as_deref()
    }

    /// Latest known presence for a user.
    pub fn presence(&self, user_id: &str) -> Option<&PresenceEvent> {
        self.presence.get(user_id)
    }

    /// Latest account data by type.
    pub fn account_data(&self, data_type: &str) -> Option<&AccountData> {
        self.account_data.get(data_type)
    }

    /// Latest notification by ID.
    pub fn notification(&self, id: &str) -> Option<&NotificationDelta> {
        self.notifications.get(id)
    }

    /// Merged device list changes seen so far.
    pub fn device_lists(&self) -> DeviceListChanges {
        DeviceListChanges {
            changed: self.changed_device_lists.iter().cloned().collect(),
            left: self.left_device_lists.iter().cloned().collect(),
        }
    }

    /// Clear all cached processor state.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Cached state for one processed space.
#[derive(Clone, Debug, Default)]
pub struct ProcessedSpace {
    /// Last timeline section received for this space.
    pub last_timeline: Option<SyncTimeline>,
    /// Total timeline events processed.
    pub timeline_events: usize,
    /// Total state events processed.
    pub state_events: usize,
    /// Last summary object.
    pub summary: serde_json::Value,
    /// Current notification count.
    pub notification_count: u64,
    /// Current highlight count.
    pub highlight_count: u64,
    /// Last timeline section had `limited: true`.
    pub last_limited: bool,
    /// Last previous-batch token from timeline pagination.
    pub last_prev_batch: Option<String>,
    /// Number of limited timeline sections processed.
    pub limited_timeline_count: usize,
    /// Pending gap created by the latest limited timeline.
    pub pending_gap: Option<crate::sync::SyncGap>,
}

/// Outbound send queue operation kind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendQueueItemKind {
    /// New message/event.
    Message,
    /// Message edit targeting an existing event.
    Edit { target_event_id: EventId },
    /// Redaction targeting an existing event.
    Redaction { target_event_id: EventId },
    /// Reaction add/remove targeting an existing event.
    Reaction { target_event_id: EventId, reaction_key: String, add: bool },
    /// Custom event kind.
    Custom { kind: String },
}

impl SendQueueItemKind {
    fn event_kind(&self) -> String {
        match self {
            Self::Message => "cx.message.create".to_owned(),
            Self::Edit { .. } => "cx.message.revise".to_owned(),
            Self::Redaction { .. } => "cx.message.redact".to_owned(),
            Self::Reaction { add, .. } if *add => "cx.reaction.add".to_owned(),
            Self::Reaction { .. } => "cx.reaction.remove".to_owned(),
            Self::Custom { kind } => kind.clone(),
        }
    }
}

/// Send queue item lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendQueueStatus {
    /// Waiting for connectivity or dependencies.
    Queued,
    /// Currently being sent.
    Sending,
    /// Server accepted the transaction.
    Sent,
    /// Send failed and may be retried after `next_retry_at`.
    Failed,
    /// User or dependency cancellation.
    Cancelled,
}

/// Local echo projected before a queued item is sent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalEcho {
    /// Idempotent transaction ID.
    pub transaction_id: String,
    /// Stable local item ID for UI reconciliation.
    pub item_id: String,
    /// Space receiving the item.
    pub space_id: SpaceId,
    /// Event kind represented by the echo.
    pub event_kind: String,
    /// Echo content.
    pub content: Value,
    /// Local creation time.
    pub created_at: DateTime<Utc>,
    /// Current queue status.
    pub status: SendQueueStatus,
}

/// One queued outbound event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SendQueueItem {
    /// Idempotent transaction ID.
    pub transaction_id: String,
    /// Target space.
    pub space_id: SpaceId,
    /// Operation kind.
    pub kind: SendQueueItemKind,
    /// Event content.
    pub content: Value,
    /// Canonical hash of the idempotent payload.
    pub payload_hash: String,
    /// Other transaction IDs that must be sent first.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Lifecycle status.
    pub status: SendQueueStatus,
    /// Number of send attempts.
    pub attempts: u32,
    /// Next retry time after a transient failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Server event ID once sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_event_id: Option<EventId>,
    /// Queue insertion order.
    pub sequence: u64,
    /// Local enqueue time.
    pub enqueued_at: DateTime<Utc>,
    /// Last lifecycle update time.
    pub updated_at: DateTime<Utc>,
    /// Local echo for UI consumers.
    pub local_echo: LocalEcho,
}

/// Serializable send queue state.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SendQueueSnapshot {
    /// Items in queue order.
    #[serde(default)]
    pub items: Vec<SendQueueItem>,
    /// Next insertion sequence.
    pub next_sequence: u64,
}

/// In-memory send queue with idempotent transaction semantics.
#[derive(Clone, Debug, Default)]
pub struct SendQueue {
    items: BTreeMap<String, SendQueueItem>,
    order: VecDeque<String>,
    next_sequence: u64,
}

impl SendQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a queue from a serialized snapshot.
    pub fn from_snapshot(snapshot: SendQueueSnapshot) -> Result<Self> {
        let mut queue = Self { next_sequence: snapshot.next_sequence, ..Self::default() };
        for item in snapshot.items {
            if queue.items.contains_key(&item.transaction_id) {
                return Err(Error::IdempotencyConflict(item.transaction_id));
            }
            queue.order.push_back(item.transaction_id.clone());
            queue.items.insert(item.transaction_id.clone(), item);
        }
        Ok(queue)
    }

    /// Export queue state for persistence by the embedding application.
    pub fn snapshot(&self) -> SendQueueSnapshot {
        SendQueueSnapshot {
            items: self
                .order
                .iter()
                .filter_map(|transaction_id| self.items.get(transaction_id).cloned())
                .collect(),
            next_sequence: self.next_sequence,
        }
    }

    /// Number of queued items in all states.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Enqueue a new message.
    pub fn enqueue_message(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        content: Value,
    ) -> Result<SendQueueItem> {
        self.enqueue(transaction_id, space_id, SendQueueItemKind::Message, content, Vec::new())
    }

    /// Enqueue a message edit.
    pub fn enqueue_edit(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        target_event_id: EventId,
        content: Value,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        self.enqueue(
            transaction_id,
            space_id,
            SendQueueItemKind::Edit { target_event_id },
            content,
            depends_on,
        )
    }

    /// Enqueue a redaction.
    pub fn enqueue_redaction(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        target_event_id: EventId,
        reason: Option<String>,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        let content = reason.map(|reason| serde_json::json!({ "reason": reason })).unwrap_or(Value::Null);
        self.enqueue(
            transaction_id,
            space_id,
            SendQueueItemKind::Redaction { target_event_id },
            content,
            depends_on,
        )
    }

    /// Enqueue a reaction add/remove.
    pub fn enqueue_reaction(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        target_event_id: EventId,
        reaction_key: String,
        add: bool,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        self.enqueue(
            transaction_id,
            space_id,
            SendQueueItemKind::Reaction { target_event_id, reaction_key, add },
            Value::Null,
            depends_on,
        )
    }

    /// Enqueue an arbitrary outbound event.
    pub fn enqueue(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        kind: SendQueueItemKind,
        content: Value,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        let payload_hash = queue_payload_hash(&space_id, &kind, &content, &depends_on)?;
        let transaction_id = transaction_id.unwrap_or_else(|| {
            format!("txn_{}", payload_hash.trim_start_matches("sha256:"))
        });

        if let Some(existing) = self.items.get(&transaction_id) {
            if existing.payload_hash == payload_hash {
                return Ok(existing.clone());
            }
            return Err(Error::IdempotencyConflict(transaction_id));
        }

        let now = Utc::now();
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let event_kind = kind.event_kind();
        let local_echo = LocalEcho {
            transaction_id: transaction_id.clone(),
            item_id: format!("local:{}", transaction_id),
            space_id: space_id.clone(),
            event_kind,
            content: content.clone(),
            created_at: now,
            status: SendQueueStatus::Queued,
        };
        let item = SendQueueItem {
            transaction_id: transaction_id.clone(),
            space_id,
            kind,
            content,
            payload_hash,
            depends_on,
            status: SendQueueStatus::Queued,
            attempts: 0,
            next_retry_at: None,
            remote_event_id: None,
            sequence,
            enqueued_at: now,
            updated_at: now,
            local_echo,
        };
        self.order.push_back(transaction_id.clone());
        self.items.insert(transaction_id, item.clone());
        Ok(item)
    }

    /// Items ready to send now, in dependency-safe order.
    pub fn ready_batch(&self, now: DateTime<Utc>, limit: usize) -> Vec<SendQueueItem> {
        self.order
            .iter()
            .filter_map(|transaction_id| self.items.get(transaction_id))
            .filter(|item| self.is_ready(item, now))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get one queue item.
    pub fn get(&self, transaction_id: &str) -> Option<&SendQueueItem> {
        self.items.get(transaction_id)
    }

    /// Mark an item as actively sending.
    pub fn mark_sending(&mut self, transaction_id: &str) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Sending;
        item.attempts = item.attempts.saturating_add(1);
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Mark an item as accepted by the server.
    pub fn mark_sent(&mut self, transaction_id: &str, remote_event_id: EventId) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Sent;
        item.remote_event_id = Some(remote_event_id);
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Mark an item as failed and schedule retry.
    pub fn mark_failed(&mut self, transaction_id: &str, retry_after: Duration) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Failed;
        item.next_retry_at =
            Some(Utc::now() + chrono::Duration::from_std(retry_after).unwrap_or_default());
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Cancel an item, optionally cascading to dependent queued items.
    pub fn cancel(&mut self, transaction_id: &str, cascade: bool) -> Result<()> {
        self.cancel_one(transaction_id)?;
        if cascade {
            let dependents: Vec<_> = self
                .items
                .values()
                .filter(|item| item.depends_on.iter().any(|dependency| dependency == transaction_id))
                .map(|item| item.transaction_id.clone())
                .collect();
            for dependent in dependents {
                self.cancel(&dependent, true)?;
            }
        }
        Ok(())
    }

    fn is_ready(&self, item: &SendQueueItem, now: DateTime<Utc>) -> bool {
        if !matches!(item.status, SendQueueStatus::Queued | SendQueueStatus::Failed) {
            return false;
        }
        if item.next_retry_at.map(|retry_at| retry_at > now).unwrap_or(false) {
            return false;
        }
        item.depends_on.iter().all(|dependency| {
            self.items
                .get(dependency)
                .map(|dependency| dependency.status == SendQueueStatus::Sent)
                .unwrap_or(false)
        })
    }

    fn item_mut(&mut self, transaction_id: &str) -> Result<&mut SendQueueItem> {
        self.items
            .get_mut(transaction_id)
            .ok_or_else(|| Error::Protocol(format!("send queue transaction not found: {}", transaction_id)))
    }

    fn cancel_one(&mut self, transaction_id: &str) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Cancelled;
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }
}

fn queue_payload_hash(
    space_id: &SpaceId,
    kind: &SendQueueItemKind,
    content: &Value,
    depends_on: &[String],
) -> Result<String> {
    canonical::canonical_sha256(&serde_json::json!({
        "space_id": space_id,
        "kind": kind,
        "content": content,
        "depends_on": depends_on,
    }))
}

/// Sliding Sync list configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlidingWindow {
    /// Inclusive start index.
    pub start: usize,
    /// Exclusive end index.
    pub end: usize,
}

impl SlidingWindow {
    /// Create a new window.
    pub fn new(start: usize, end: usize) -> Result<Self> {
        if start > end {
            return Err(Error::Protocol("sliding sync window start is after end".to_owned()));
        }
        Ok(Self { start, end })
    }

    /// Number of items covered by this window.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Sliding Sync state for a space list.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SlidingSync {
    all_spaces: Vec<SpaceId>,
    subscribed_spaces: BTreeSet<SpaceId>,
    windows: Vec<SlidingWindow>,
    batch_size: Option<u32>,
    timeline_filter: Option<TimelineFilter>,
}

impl SlidingSync {
    /// Create an empty Sliding Sync state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the known ordered space list.
    pub fn set_space_list(&mut self, spaces: Vec<SpaceId>) {
        self.all_spaces = spaces;
    }

    /// Replace the active windows.
    pub fn set_windows(&mut self, windows: Vec<SlidingWindow>) {
        self.windows = windows;
    }

    /// Set timeline batch size.
    pub fn set_batch_size(&mut self, batch_size: Option<u32>) {
        self.batch_size = batch_size;
    }

    /// Set timeline filter for generated subscriptions.
    pub fn set_timeline_filter(&mut self, timeline_filter: Option<TimelineFilter>) {
        self.timeline_filter = timeline_filter;
    }

    /// Apply incremental insertions/removals to the ordered space list.
    pub fn apply_delta(&mut self, removals: &[SpaceId], insertions: Vec<(usize, SpaceId)>) {
        let removal_set: BTreeSet<_> = removals.iter().cloned().collect();
        self.all_spaces.retain(|space_id| !removal_set.contains(space_id));

        for (index, space_id) in insertions {
            let index = index.min(self.all_spaces.len());
            self.all_spaces.insert(index, space_id);
        }
    }

    /// Spaces currently visible through all windows.
    pub fn visible_spaces(&self) -> Vec<SpaceId> {
        let mut visible = BTreeSet::new();
        for window in &self.windows {
            for space_id in self.all_spaces.iter().skip(window.start).take(window.len()) {
                visible.insert(space_id.clone());
            }
        }
        visible.into_iter().collect()
    }

    /// Build protocol subscriptions for the current visible spaces.
    pub fn subscription_config(&mut self) -> SubscriptionConfig {
        let visible = self.visible_spaces();
        self.subscribed_spaces = visible.iter().cloned().collect();

        SubscriptionConfig {
            subscriptions: visible
                .into_iter()
                .map(|space_id| SpaceSubscription {
                    space_id,
                    timeline_filter: self.timeline_filter.clone(),
                    required_state: Vec::new(),
                })
                .collect(),
            batch_size: self.batch_size,
            timeline_filter: None,
        }
    }

    /// True if a space is part of the current visible subscription set.
    pub fn is_subscribed(&self, space_id: &SpaceId) -> bool {
        self.subscribed_spaces.contains(space_id)
    }

    /// Export sliding-window state for persistence.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Restore sliding-window state from a previous snapshot.
    pub fn from_snapshot(snapshot: Self) -> Self {
        snapshot
    }
}

/// Sort order for the room/space list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceListSort {
    /// Most recent activity first.
    #[default]
    Recency,
    /// Name ascending.
    Name,
    /// Unread count descending.
    Unread,
    /// Favorites first, then recency.
    Favorite,
}

/// Filter for room/space list projections.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListFilter {
    /// Membership buckets to include. Empty means all buckets.
    #[serde(default)]
    pub memberships: BTreeSet<MembershipBucket>,
    /// Favorite flag filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    /// Include only spaces with unread notifications.
    #[serde(default)]
    pub unread_only: bool,
    /// Optional category filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl SpaceListFilter {
    fn matches(&self, entry: &SpaceListEntry) -> bool {
        (self.memberships.is_empty() || self.memberships.contains(&entry.membership))
            && self.favorite.map(|favorite| entry.favorite == favorite).unwrap_or(true)
            && (!self.unread_only || entry.unread_count > 0 || entry.highlight_count > 0)
            && self.category.as_ref().map(|category| entry.category.as_ref() == Some(category)).unwrap_or(true)
    }
}

/// One item in a room/space list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListEntry {
    /// Space ID.
    pub space_id: SpaceId,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Membership bucket.
    pub membership: MembershipBucket,
    /// Last event ID used for recency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    /// Last deterministic timeline position.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<TimelineOrderKey>,
    /// Notification count.
    pub unread_count: u64,
    /// Highlight count.
    pub highlight_count: u64,
    /// User favorite flag.
    pub favorite: bool,
    /// Optional category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl SpaceListEntry {
    /// Create a list entry with default joined membership.
    pub fn joined(space_id: SpaceId) -> Self {
        Self {
            space_id,
            name: None,
            membership: MembershipBucket::Joined,
            last_event_id: None,
            last_activity: None,
            unread_count: 0,
            highlight_count: 0,
            favorite: false,
            category: None,
        }
    }
}

/// Incremental space list change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceListChange {
    /// New visible entry.
    Inserted { index: usize, entry: SpaceListEntry },
    /// Existing visible entry changed in place.
    Updated { index: usize, entry: SpaceListEntry },
    /// Entry disappeared from the visible projection.
    Removed { old_index: usize, space_id: SpaceId },
    /// Existing entry moved after sorting/filtering.
    Moved { old_index: usize, new_index: usize, space_id: SpaceId },
}

/// Result of applying one room/space-list mutation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListUpdate {
    /// Ordered visible space IDs after the mutation.
    #[serde(default)]
    pub ordered: Vec<SpaceId>,
    /// Incremental changes suitable for UI bindings.
    #[serde(default)]
    pub changes: Vec<SpaceListChange>,
}

/// Serializable room/space list state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListSnapshot {
    /// Entries by space.
    #[serde(default)]
    pub entries: BTreeMap<SpaceId, SpaceListEntry>,
    /// Visible ordered projection.
    #[serde(default)]
    pub ordered: Vec<SpaceId>,
    /// Current sort.
    pub sort: SpaceListSort,
    /// Current filter.
    pub filter: SpaceListFilter,
}

/// Room/space list service with deterministic sorting, filtering and deltas.
#[derive(Clone, Debug, Default)]
pub struct SpaceListService {
    entries: BTreeMap<SpaceId, SpaceListEntry>,
    ordered: Vec<SpaceId>,
    sort: SpaceListSort,
    filter: SpaceListFilter,
}

impl SpaceListService {
    /// Create an empty list service.
    pub fn new() -> Self {