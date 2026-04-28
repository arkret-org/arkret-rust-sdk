//! Stateful sync client utilities.
//!
//! The protocol types live in [`crate::sync`]. This module adds the client-side
//! control plane: retry/backoff state, response processing and sliding-window
//! subscription helpers.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::Duration,
};

use crate::{
    Error, Result, SpaceId,
    sync::{
        AccountData, DeviceListChanges, NotificationDelta, PresenceEvent, PresenceStatus,
        SpaceSubscription, SpaceUpdate, SubscriptionConfig, SyncFilter, SyncRequest, SyncResponse,
        SyncTimeline, SyncUpdates, TimelineFilter, ToDeviceMessage,
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

    /// Build the next long-poll request.
    pub fn next_request(&self) -> SyncRequest {
        let timeout_ms = self.timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        SyncRequest {
            since: self.token.clone(),
            timeout_ms: Some(timeout_ms),
            set_presence: self.presence.clone(),
            filter: self.filter.clone(),
            subscriptions: self.subscriptions.clone(),
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
    to_device: VecDeque<ToDeviceMessage>,
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
}

/// Sliding Sync list configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, Default)]
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
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::sync::{DeviceListChanges, SyncSpace, UnreadCounts};

    fn sync_response(next_batch: &str) -> SyncResponse {
        SyncResponse {
            next_batch: next_batch.to_owned(),
            spaces: BTreeMap::new(),
            rooms: BTreeMap::new(),
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
    fn sliding_sync_builds_windowed_subscriptions_and_applies_deltas() {
        let s1 = SpaceId::new("cx:space:01JS0SP000000000000000001").unwrap();
        let s2 = SpaceId::new("cx:space:01JS0SP000000000000000002").unwrap();
        let s3 = SpaceId::new("cx:space:01JS0SP000000000000000003").unwrap();
        let s4 = SpaceId::new("cx:space:01JS0SP000000000000000004").unwrap();

        let mut sliding = SlidingSync::new();
        sliding.set_space_list(vec![s1.clone(), s2.clone(), s3.clone()]);
        sliding.set_windows(vec![SlidingWindow::new(0, 2).unwrap()]);
        sliding.apply_delta(&[s1], vec![(1, s4.clone())]);

        let config = sliding.subscription_config();

        assert_eq!(config.subscriptions.len(), 2);
        assert_eq!(config.subscriptions[0].space_id, s2);
        assert_eq!(config.subscriptions[1].space_id, s4);
        assert!(sliding.is_subscribed(&s4));
    }
}
