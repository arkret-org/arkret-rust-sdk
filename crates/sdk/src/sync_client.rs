//! Stateful sync client utilities.
//!
//! The protocol types live in [`crate::sync`]. This module adds the client-side
//! control plane: retry/backoff state, response processing and sliding-window
//! subscription helpers.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DeviceId, Error, Event, EventId, Result, SpaceId, canonical,
    sync::{
        AccountData, DeviceListChanges, LimitedTimelineState, MembershipBucket, NotificationDelta,
        PresenceEvent, PresenceStatus, SpaceSubscription, SpaceUpdate, SubscriptionConfig,
        SyncFilter, SyncRequest, SyncResponse, SyncTimeline, SyncUpdates, TimelineFilter,
        TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, ToDeviceMessage, WaitForFrontier,
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
    /// The caller requested cancellation before a transport request started.
    Cancelled,
    /// A request was deferred because the configured in-flight limit was reached.
    Backpressure { retry_after: Duration },
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

/// Boxed future returned by async sync transports.
pub type BoxSyncFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Async transport abstraction used by [`SyncLoop::step_async`].
pub trait AsyncSyncTransport {
    /// Execute one async sync request.
    fn sync_async<'a>(&'a self, request: SyncRequest) -> BoxSyncFuture<'a, SyncResponse>;
}

impl<F, Fut> AsyncSyncTransport for F
where
    F: Fn(SyncRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Result<SyncResponse>> + Send + 'static,
{
    fn sync_async<'a>(&'a self, request: SyncRequest) -> BoxSyncFuture<'a, SyncResponse> {
        Box::pin(self(request))
    }
}

/// Async streaming transport abstraction for `/api/v1/sync/subscribe`.
pub trait SyncSubscribeTransport {
    /// Streaming response type chosen by the concrete HTTP backend.
    type StreamResponse;

    /// Open a server-side sync subscription stream.
    fn sync_subscribe<'a>(
        &'a self,
        space_id: &'a str,
        cursor: Option<&'a str>,
    ) -> BoxSyncFuture<'a, Self::StreamResponse>;
}

#[cfg(feature = "client")]
impl AsyncSyncTransport for crate::Client {
    fn sync_async<'a>(&'a self, request: SyncRequest) -> BoxSyncFuture<'a, SyncResponse> {
        Box::pin(async move { self.sync(&request).await })
    }
}

#[cfg(feature = "client")]
impl SyncSubscribeTransport for crate::Client {
    type StreamResponse = reqwest::Response;

    fn sync_subscribe<'a>(
        &'a self,
        space_id: &'a str,
        cursor: Option<&'a str>,
    ) -> BoxSyncFuture<'a, Self::StreamResponse> {
        Box::pin(async move { self.sync_subscribe_stream(space_id, cursor).await })
    }
}

/// Cancellation token that stays independent of a specific async runtime.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a non-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation for future sync work.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Clear a previous cancellation request.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Async sync backpressure settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackpressureConfig {
    /// Maximum number of concurrent transport requests.
    pub max_in_flight_requests: usize,
    /// Delay returned when a caller should retry after backpressure.
    pub retry_after: Duration,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self { max_in_flight_requests: 1, retry_after: Duration::from_millis(100) }
    }
}

/// Runtime-neutral async sync loop controls.
#[derive(Clone, Debug)]
pub struct SyncLoopControl {
    cancellation: CancellationToken,
    backpressure: BackpressureConfig,
    in_flight: Arc<AtomicUsize>,
}

impl SyncLoopControl {
    /// Create controls with default cancellation and single-flight backpressure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an existing cancellation token.
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Set backpressure behavior.
    pub fn with_backpressure(mut self, backpressure: BackpressureConfig) -> Self {
        self.backpressure = backpressure;
        self
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Clear cancellation.
    pub fn reset_cancellation(&self) {
        self.cancellation.reset();
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Configured retry delay for backpressure responses.
    pub fn backpressure_retry_after(&self) -> Duration {
        self.backpressure.retry_after
    }

    fn try_acquire(&self) -> Option<InFlightPermit> {
        let max = self.backpressure.max_in_flight_requests.max(1);
        let mut current = self.in_flight.load(Ordering::SeqCst);
        loop {
            if current >= max {
                return None;
            }
            match self.in_flight.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(InFlightPermit { in_flight: Arc::clone(&self.in_flight) }),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Default for SyncLoopControl {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::default(),
            backpressure: BackpressureConfig::default(),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct InFlightPermit {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Strategy used when a limited timeline indicates a sync gap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncGapStrategy {
    /// Preserve the token and let the caller backfill gaps explicitly.
    #[default]
    PreserveTokenAndBackfill,
    /// Clear the token so the next sync restarts from an initial snapshot.
    ResetTokenOnLimitedTimeline,
}

/// Serializable sync loop state for durable token persistence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncLoopSnapshot {
    /// Last accepted sync token.
    pub token: Option<String>,
    /// Long-poll timeout persisted as milliseconds for portability.
    pub timeout_ms: u64,
    /// Gap handling strategy used by the loop.
    pub gap_strategy: SyncGapStrategy,
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
    gap_strategy: SyncGapStrategy,
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
            gap_strategy: SyncGapStrategy::PreserveTokenAndBackfill,
        }
    }

    /// Restore a loop from a previously persisted snapshot.
    pub fn from_snapshot(snapshot: SyncLoopSnapshot) -> Self {
        let mut sync_loop = Self::new()
            .with_timeout(Duration::from_millis(snapshot.timeout_ms))
            .with_gap_strategy(snapshot.gap_strategy);
        sync_loop.token = snapshot.token;
        sync_loop
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

    /// Set the gap strategy used after limited timelines.
    pub fn with_gap_strategy(mut self, strategy: SyncGapStrategy) -> Self {
        self.gap_strategy = strategy;
        self
    }

    /// Set retry backoff configuration.
    pub fn with_backoff_config(mut self, config: BackoffConfig) -> Self {
        self.backoff = ExponentialBackoff::new(config);
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

    fn handle_response(&mut self, response: SyncResponse) -> SyncLoopStep {
        self.backoff.reset();
        self.token = Some(response.next_batch.clone());
        match self.processor.process(response) {
            Ok(updates) => {
                if self.gap_strategy == SyncGapStrategy::ResetTokenOnLimitedTimeline
                    && updates.space_updates.iter().any(|update| {
                        update.timeline.as_ref().is_some_and(|timeline| timeline.limited)
                    })
                {
                    self.token = None;
                }
                SyncLoopStep::Updates(updates)
            }
            Err(error) => {
                let retry_after = self.backoff.record_failure();
                SyncLoopStep::Retry { retry_after, error: error.to_string() }
            }
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
            Ok(response) => self.handle_response(response),
            Err(error) => {
                let retry_after = self.backoff.record_failure();
                SyncLoopStep::Retry { retry_after, error: error.to_string() }
            }
        }
    }

    /// Execute one async loop iteration with default controls.
    pub async fn step_async<T>(&mut self, transport: &T) -> SyncLoopStep
    where
        T: AsyncSyncTransport + ?Sized,
    {
        let control = SyncLoopControl::default();
        self.step_async_with_control(transport, &control).await
    }

    /// Execute one async loop iteration with cancellation and backpressure.
    pub async fn step_async_with_control<T>(
        &mut self,
        transport: &T,
        control: &SyncLoopControl,
    ) -> SyncLoopStep
    where
        T: AsyncSyncTransport + ?Sized,
    {
        if control.is_cancelled() {
            return SyncLoopStep::Cancelled;
        }
        let Some(_permit) = control.try_acquire() else {
            return SyncLoopStep::Backpressure { retry_after: control.backpressure_retry_after() };
        };
        let request = self.next_request();
        match transport.sync_async(request).await {
            Ok(response) => self.handle_response(response),
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

    /// Export durable sync loop state.
    pub fn snapshot(&self) -> SyncLoopSnapshot {
        SyncLoopSnapshot {
            token: self.token.clone(),
            timeout_ms: self.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            gap_strategy: self.gap_strategy,
        }
    }

    /// Restore durable token state on an existing loop.
    pub fn restore_snapshot(&mut self, snapshot: SyncLoopSnapshot) {
        self.token = snapshot.token;
        self.timeout = Duration::from_millis(snapshot.timeout_ms);
        self.gap_strategy = snapshot.gap_strategy;
        self.processor.clear();
        self.backoff.reset();
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
        for (raw_space_id, sync_space) in response.spaces {
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
        let ack = ToDeviceAck {
            message_id: message_id.clone(),
            device_id,
            status,
            acknowledged_at: Utc::now(),
        };
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
    pub summary: Value,
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
        let content =
            reason.map(|reason| serde_json::json!({ "reason": reason })).unwrap_or(Value::Null);
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
        let transaction_id = transaction_id
            .unwrap_or_else(|| format!("txn_{}", payload_hash.trim_start_matches("sha256:")));

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
                .filter(|item| {
                    item.depends_on.iter().any(|dependency| dependency == transaction_id)
                })
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
        self.items.get_mut(transaction_id).ok_or_else(|| {
            Error::Protocol(format!("send queue transaction not found: {}", transaction_id))
        })
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

/// Sort order for the space list.
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

/// Filter for space list projections.
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
            && self
                .category
                .as_ref()
                .map(|category| entry.category.as_ref() == Some(category))
                .unwrap_or(true)
    }
}

/// One item in a space list.
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

/// Result of applying one space-list mutation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListUpdate {
    /// Ordered visible space IDs after the mutation.
    #[serde(default)]
    pub ordered: Vec<SpaceId>,
    /// Incremental changes suitable for UI bindings.
    #[serde(default)]
    pub changes: Vec<SpaceListChange>,
}

/// Serializable space-list state.
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

/// Space list service with deterministic sorting, filtering and deltas.
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
        Self::default()
    }

    /// Restore service state from a snapshot.
    pub fn from_snapshot(snapshot: SpaceListSnapshot) -> Self {
        Self {
            entries: snapshot.entries,
            ordered: snapshot.ordered,
            sort: snapshot.sort,
            filter: snapshot.filter,
        }
    }

    /// Export list state for persistence by the embedding application.
    pub fn snapshot(&self) -> SpaceListSnapshot {
        SpaceListSnapshot {
            entries: self.entries.clone(),
            ordered: self.ordered.clone(),
            sort: self.sort,
            filter: self.filter.clone(),
        }
    }

    /// Current ordered visible entries.
    pub fn entries(&self) -> Vec<&SpaceListEntry> {
        self.ordered.iter().filter_map(|space_id| self.entries.get(space_id)).collect()
    }

    /// Set sort mode and return the resulting delta.
    pub fn set_sort(&mut self, sort: SpaceListSort) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.sort = sort;
        self.rebuild_update(previous)
    }

    /// Set filter and return the resulting delta.
    pub fn set_filter(&mut self, filter: SpaceListFilter) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.filter = filter;
        self.rebuild_update(previous)
    }

    /// Insert or update one entry.
    pub fn upsert(&mut self, entry: SpaceListEntry) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.entries.insert(entry.space_id.clone(), entry);
        self.rebuild_update(previous)
    }

    /// Remove one entry.
    pub fn remove(&mut self, space_id: &SpaceId) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.entries.remove(space_id);
        self.rebuild_update(previous)
    }

    /// Apply a processed sync update to list metadata.
    pub fn apply_space_update(
        &mut self,
        update: &SpaceUpdate,
        membership: MembershipBucket,
    ) -> SpaceListUpdate {
        let mut entry = self
            .entries
            .get(&update.space_id)
            .cloned()
            .unwrap_or_else(|| SpaceListEntry::joined(update.space_id.clone()));
        entry.membership = membership;
        if let Some(name) = update
            .summary
            .get("name")
            .or_else(|| update.summary.get("title"))
            .and_then(Value::as_str)
        {
            entry.name = Some(name.to_owned());
        }
        if let Some(favorite) = update.summary.get("favorite").and_then(Value::as_bool) {
            entry.favorite = favorite;
        }
        if let Some(category) = update.summary.get("category").and_then(Value::as_str) {
            entry.category = Some(category.to_owned());
        }
        if let Some(unread_count) = update.summary.get("unread_count").and_then(Value::as_u64) {
            entry.unread_count = unread_count;
        }
        if let Some(highlight_count) = update.summary.get("highlight_count").and_then(Value::as_u64)
        {
            entry.highlight_count = highlight_count;
        }
        if let Some(timeline) = &update.timeline
            && let Some(event) = timeline
                .events
                .last()
                .and_then(|value| serde_json::from_value::<Event>(value.clone()).ok())
        {
            entry.last_event_id = Some(event.event_id.clone());
            entry.last_activity =
                Some(TimelineOrderKey::from_event(&event, event.prev_refs.len() as u64));
        }
        self.upsert(entry)
    }

    fn rebuild_update(&mut self, previous: Vec<SpaceListEntry>) -> SpaceListUpdate {
        let current = self.rebuild_order();
        let changes = diff_space_lists(&previous, &current);
        SpaceListUpdate {
            ordered: current.iter().map(|entry| entry.space_id.clone()).collect(),
            changes,
        }
    }

    fn rebuild_order(&mut self) -> Vec<SpaceListEntry> {
        let mut entries = self.visible_entries();
        entries.sort_by(|left, right| compare_space_entries(left, right, self.sort));
        self.ordered = entries.iter().map(|entry| entry.space_id.clone()).collect();
        entries
    }

    fn visible_entries(&self) -> Vec<SpaceListEntry> {
        self.entries.values().filter(|entry| self.filter.matches(entry)).cloned().collect()
    }
}

fn compare_space_entries(
    left: &SpaceListEntry,
    right: &SpaceListEntry,
    sort: SpaceListSort,
) -> std::cmp::Ordering {
    let name_order = left.name.cmp(&right.name).then_with(|| left.space_id.cmp(&right.space_id));
    match sort {
        SpaceListSort::Recency => right.last_activity.cmp(&left.last_activity).then(name_order),
        SpaceListSort::Name => name_order,
        SpaceListSort::Unread => right
            .highlight_count
            .cmp(&left.highlight_count)
            .then_with(|| right.unread_count.cmp(&left.unread_count))
            .then_with(|| right.last_activity.cmp(&left.last_activity))
            .then(name_order),
        SpaceListSort::Favorite => right
            .favorite
            .cmp(&left.favorite)
            .then_with(|| right.last_activity.cmp(&left.last_activity))
            .then(name_order),
    }
}

fn diff_space_lists(
    previous: &[SpaceListEntry],
    current: &[SpaceListEntry],
) -> Vec<SpaceListChange> {
    let previous_index: BTreeMap<_, _> = previous
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.space_id.clone(), (index, entry)))
        .collect();
    let current_index: BTreeMap<_, _> = current
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.space_id.clone(), (index, entry)))
        .collect();
    let mut changes = Vec::new();

    for (space_id, (old_index, _)) in &previous_index {
        if !current_index.contains_key(space_id) {
            changes.push(SpaceListChange::Removed {
                old_index: *old_index,
                space_id: space_id.clone(),
            });
        }
    }
    for (space_id, (new_index, entry)) in &current_index {
        match previous_index.get(space_id) {
            None => changes
                .push(SpaceListChange::Inserted { index: *new_index, entry: (*entry).clone() }),
            Some((old_index, previous_entry)) if *old_index != *new_index => {
                changes.push(SpaceListChange::Moved {
                    old_index: *old_index,
                    new_index: *new_index,
                    space_id: space_id.clone(),
                });
                if *previous_entry != *entry {
                    changes.push(SpaceListChange::Updated {
                        index: *new_index,
                        entry: (*entry).clone(),
                    });
                }
            }
            Some((_, previous_entry)) if *previous_entry != *entry => {
                changes
                    .push(SpaceListChange::Updated { index: *new_index, entry: (*entry).clone() });
            }
            _ => {}
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::Did;
    use crate::sync::{DeviceListChanges, SyncSpace, UnreadCounts};

    fn sync_response(next_batch: &str) -> SyncResponse {
        SyncResponse {
            next_batch: next_batch.to_owned(),
            spaces: BTreeMap::new(),
            to_device: Vec::new(),
            device_lists: DeviceListChanges::default(),
            presence: Vec::new(),
            account_data: Vec::new(),
            notifications: Vec::new(),
            partial: false,
        }
    }

    #[test]
    fn backoff_grows_until_capped() {
        let mut backoff = ExponentialBackoff::new(BackoffConfig {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(250),
            multiplier: 2,
        });

        assert_eq!(backoff.record_failure(), Duration::from_millis(100));
        assert_eq!(backoff.record_failure(), Duration::from_millis(200));
        assert_eq!(backoff.record_failure(), Duration::from_millis(250));
        backoff.reset();
        assert_eq!(backoff.current_delay(), Duration::ZERO);
    }

    #[test]
    fn sync_loop_recovers_after_failure() {
        let mut calls = 0;
        let mut transport = |request: SyncRequest| {
            calls += 1;
            if calls == 1 {
                assert_eq!(request.timeout_ms, Some(30_000));
                Err(Error::Protocol("network down".to_owned()))
            } else {
                assert!(request.since.is_none());
                Ok(sync_response("s1"))
            }
        };
        let mut sync_loop = SyncLoop::new();

        assert!(matches!(sync_loop.step(&mut transport), SyncLoopStep::Retry { .. }));
        assert!(matches!(sync_loop.step(&mut transport), SyncLoopStep::Updates(_)));
        assert_eq!(sync_loop.token(), Some("s1"));
    }

    #[tokio::test]
    async fn async_sync_loop_uses_transport_and_persists_token() {
        let transport = |request: SyncRequest| async move {
            assert_eq!(request.timeout_ms, Some(15));
            assert!(request.since.is_none());
            Ok(sync_response("async1"))
        };
        let mut sync_loop = SyncLoop::new().with_timeout(Duration::from_millis(15));

        assert!(matches!(sync_loop.step_async(&transport).await, SyncLoopStep::Updates(_)));
        let snapshot = sync_loop.snapshot();
        assert_eq!(snapshot.token.as_deref(), Some("async1"));

        let restored = SyncLoop::from_snapshot(snapshot);
        assert_eq!(restored.next_request().since.as_deref(), Some("async1"));
    }

    #[tokio::test]
    async fn async_sync_loop_honors_cancellation() {
        let transport = |_request: SyncRequest| async { Ok(sync_response("unused")) };
        let control = SyncLoopControl::new();
        control.cancel();

        let mut sync_loop = SyncLoop::new();

        assert!(matches!(
            sync_loop.step_async_with_control(&transport, &control).await,
            SyncLoopStep::Cancelled
        ));
        assert!(sync_loop.token().is_none());
    }

    #[test]
    fn sync_loop_control_applies_backpressure() {
        let control = SyncLoopControl::new().with_backpressure(BackpressureConfig {
            max_in_flight_requests: 1,
            retry_after: Duration::from_millis(25),
        });
        let permit = control.try_acquire().unwrap();

        assert!(control.try_acquire().is_none());
        assert_eq!(control.backpressure_retry_after(), Duration::from_millis(25));

        drop(permit);
        assert!(control.try_acquire().is_some());
    }

    #[test]
    fn sync_loop_can_reset_token_on_limited_timeline_gap() {
        let space_id = "cx:space:01JS0SP000000000000000000";
        let mut response = sync_response("gap-token");
        response.spaces.insert(
            space_id.to_owned(),
            SyncSpace {
                timeline: Some(SyncTimeline {
                    events: Vec::new(),
                    limited: true,
                    prev_batch: Some("prev".to_owned()),
                }),
                state: Vec::new(),
                summary: json!({}),
                ephemeral: Vec::new(),
                unread: UnreadCounts::default(),
            },
        );
        let mut transport = |_request: SyncRequest| Ok(response.clone());
        let mut sync_loop =
            SyncLoop::new().with_gap_strategy(SyncGapStrategy::ResetTokenOnLimitedTimeline);

        assert!(matches!(sync_loop.step(&mut transport), SyncLoopStep::Updates(_)));
        assert!(sync_loop.token().is_none());
    }

    #[test]
    fn sync_loop_includes_wait_for_frontier() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let wait_for = WaitForFrontier {
            positions: vec![crate::sync::SyncStreamPosition {
                space_id,
                frontier: Vec::new(),
                timeline_order: crate::Hlc::new("01970e589d21-00000000-a13f9c2e").unwrap(),
                state_hash:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
            }],
            timeout_ms: 5000,
        };

        let request = SyncLoop::new().with_wait_for(wait_for.clone()).next_request();

        assert_eq!(request.wait_for, Some(wait_for));
    }

    #[test]
    fn processor_dispatches_all_update_categories() {
        let space_id = "cx:space:01JS0SP000000000000000000";
        let mut response = sync_response("s2");
        response.spaces.insert(
            space_id.to_owned(),
            SyncSpace {
                timeline: None,
                state: vec![json!({"kind":"state"})],
                summary: json!({"name":"space"}),
                ephemeral: Vec::new(),
                unread: UnreadCounts { notification_count: 3, highlight_count: 1 },
            },
        );
        response.to_device.push(ToDeviceMessage {
            message_type: "m.test".to_owned(),
            content: json!({"ok":true}),
        });
        response.device_lists.changed.push("did:web:alice.example".to_owned());
        response.presence.push(PresenceEvent {
            user_id: "did:web:alice.example".to_owned(),
            presence: PresenceStatus::Online,
            last_active: None,
            device_id: None,
        });
        response.account_data.push(AccountData {
            data_type: "cx.settings".to_owned(),
            content: json!({"theme":"light"}),
        });
        response.notifications.push(NotificationDelta {
            id: "n1".to_owned(),
            notification_type: "mention".to_owned(),
            action: "add".to_owned(),
            data: None,
        });

        let mut processor = SyncResponseProcessor::new();
        let updates = processor.process(response).unwrap();
        let parsed_space_id = SpaceId::new(space_id).unwrap();

        assert_eq!(updates.space_updates.len(), 1);
        assert_eq!(processor.space(&parsed_space_id).unwrap().notification_count, 3);
        assert_eq!(processor.drain_to_device().len(), 1);
        assert!(processor.presence("did:web:alice.example").is_some());
        assert!(processor.account_data("cx.settings").is_some());
        assert!(processor.notification("n1").is_some());
        assert_eq!(processor.device_lists().changed.len(), 1);
    }

    #[test]
    fn processor_tracks_limited_timelines_and_to_device_ack() {
        let space_id = "cx:space:01JS0SP000000000000000000";
        let parsed_space_id = SpaceId::new(space_id).unwrap();
        let event = Event::new(
            "cx.message.create",
            parsed_space_id.clone(),
            Did::new("did:web:alice.example").unwrap(),
            1,
            crate::Hlc::new("01970e589d21-00000000-a13f9c2e").unwrap(),
            json!({"body":"hello"}),
        )
        .unwrap();
        let mut response = sync_response("s3");
        response.spaces.insert(
            space_id.to_owned(),
            SyncSpace {
                timeline: Some(SyncTimeline {
                    events: vec![serde_json::to_value(event).unwrap()],
                    limited: true,
                    prev_batch: Some("prev".to_owned()),
                }),
                state: Vec::new(),
                summary: json!({}),
                ephemeral: Vec::new(),
                unread: UnreadCounts::default(),
            },
        );

        let mut processor = SyncResponseProcessor::new();
        processor.process(response).unwrap();
        let ack = processor.acknowledge_to_device(
            "devmsg1",
            DeviceId::new("dev_123").unwrap(),
            ToDeviceAckStatus::Processed,
        );

        assert_eq!(processor.space(&parsed_space_id).unwrap().limited_timeline_count, 1);
        assert_eq!(processor.limited_timelines().len(), 1);
        assert_eq!(processor.to_device_ack("devmsg1"), Some(&ack));
    }

    #[test]
    fn send_queue_is_idempotent_orders_dependencies_and_snapshots() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let mut queue = SendQueue::new();
        let message = queue
            .enqueue_message(Some("txn1".to_owned()), space_id.clone(), json!({"body":"hello"}))
            .unwrap();
        let duplicate = queue
            .enqueue_message(Some("txn1".to_owned()), space_id.clone(), json!({"body":"hello"}))
            .unwrap();
        let edit = queue
            .enqueue_edit(
                Some("txn2".to_owned()),
                space_id,
                EventId::new("cx:event:0001").unwrap(),
                json!({"content":{"body":"hi"}}),
                vec!["txn1".to_owned()],
            )
            .unwrap();

        assert_eq!(message.payload_hash, duplicate.payload_hash);
        assert_eq!(queue.ready_batch(Utc::now(), 10), vec![message]);

        queue.mark_sending("txn1").unwrap();
        queue.mark_sent("txn1", EventId::new("cx:event:0001").unwrap()).unwrap();
        assert_eq!(queue.ready_batch(Utc::now(), 10), vec![edit]);

        let restored = SendQueue::from_snapshot(queue.snapshot()).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.get("txn1").unwrap().status, SendQueueStatus::Sent);
    }

    #[test]
    fn send_queue_cancels_dependent_edit_redaction_and_reaction() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let event_id = EventId::new("cx:event:0001").unwrap();
        let mut queue = SendQueue::new();
        queue
            .enqueue_message(Some("txn1".to_owned()), space_id.clone(), json!({"body":"hello"}))
            .unwrap();
        queue
            .enqueue_redaction(
                Some("txn2".to_owned()),
                space_id.clone(),
                event_id.clone(),
                None,
                vec!["txn1".to_owned()],
            )
            .unwrap();
        queue
            .enqueue_reaction(
                Some("txn3".to_owned()),
                space_id,
                event_id,
                "+1".to_owned(),
                true,
                vec!["txn2".to_owned()],
            )
            .unwrap();

        queue.cancel("txn1", true).unwrap();

        assert_eq!(queue.get("txn1").unwrap().status, SendQueueStatus::Cancelled);
        assert_eq!(queue.get("txn2").unwrap().status, SendQueueStatus::Cancelled);
        assert_eq!(queue.get("txn3").unwrap().status, SendQueueStatus::Cancelled);
    }

    #[test]
    fn sliding_sync_builds_windowed_subscriptions_and_applies_deltas() {
        let s1 = SpaceId::new("cx:space:01JS0SP000000000000000001").unwrap();
        let s2 = SpaceId::new("cx:space:01JS0SP000000000000000002").unwrap();
        let s3 = SpaceId::new("cx:space:01JS0SP000000000000000003").unwrap();
        let s4 = SpaceId::new("cx:space:01JS0SP000000000000000004").unwrap();

        let mut sliding = SlidingSync::new();
        sliding.set_space_list(vec![s1.clone(), s2.clone(), s3]);
        sliding.set_windows(vec![SlidingWindow::new(0, 2).unwrap()]);
        sliding.apply_delta(&[s1], vec![(1, s4.clone())]);

        let config = sliding.subscription_config();

        assert_eq!(config.subscriptions.len(), 2);
        assert_eq!(config.subscriptions[0].space_id, s2);
        assert_eq!(config.subscriptions[1].space_id, s4);
        assert!(sliding.is_subscribed(&s4));
    }

    #[test]
    fn space_list_sorts_filters_and_reports_incremental_changes() {
        let s1 = SpaceId::new("cx:space:01JS0SP000000000000000001").unwrap();
        let s2 = SpaceId::new("cx:space:01JS0SP000000000000000002").unwrap();
        let mut list = SpaceListService::new();
        let mut alpha = SpaceListEntry::joined(s1);
        alpha.name = Some("Alpha".to_owned());
        alpha.unread_count = 1;
        let mut beta = SpaceListEntry::joined(s2.clone());
        beta.name = Some("Beta".to_owned());
        beta.favorite = true;
        beta.unread_count = 5;

        let first = list.upsert(alpha);
        let second = list.upsert(beta);
        let sorted = list.set_sort(SpaceListSort::Unread);
        let filtered =
            list.set_filter(SpaceListFilter { unread_only: true, ..SpaceListFilter::default() });

        assert!(matches!(first.changes[0], SpaceListChange::Inserted { .. }));
        assert!(
            second.changes.iter().any(|change| matches!(change, SpaceListChange::Inserted { .. }))
        );
        assert_eq!(sorted.ordered[0], s2);
        assert_eq!(filtered.ordered.len(), 2);

        let snapshot = list.snapshot();
        let restored = SpaceListService::from_snapshot(snapshot);
        assert_eq!(restored.entries().len(), 2);
        assert_eq!(restored.entries()[0].space_id, s2);
    }
}
