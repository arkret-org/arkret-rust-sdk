//! Timeline and event management for Contrix v1.
//!
//! This module provides timeline management for spaces, including:
//! - Event pagination
//! - Backfill support
//! - Timeline gaps
//! - Latest event tracking

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

use crate::{
    Result,
    base::BaseClient,
    model::{DeviceId, Did, Event, EventId, SpaceId},
    receipts::{ReadReceipt, ReceiptVisibility},
    sync::{
        BackfillDirection, BackfillFrom, BackfillRequest, SyncGapReason, SyncTimeline,
        TimelineOrderKey,
    },
    typing::TypingNotification,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Configuration for timeline queries.
#[derive(Clone, Debug)]
pub struct TimelineOptions {
    /// Maximum number of events to return
    pub limit: u32,
    /// Direction for pagination
    pub direction: TimelineDirection,
    /// Starting point for pagination
    pub from: TimelineFrom,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        Self { limit: 50, direction: TimelineDirection::Backward, from: TimelineFrom::Latest }
    }
}

/// Direction for timeline pagination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineDirection {
    /// Forward from the starting point (older to newer)
    Forward,
    /// Backward from the starting point (newer to older)
    Backward,
    /// Both directions from the starting point
    Both,
}

/// Starting point for timeline queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimelineFrom {
    /// Start from the latest event
    Latest,
    /// Start from a specific event ID
    EventId(EventId),
    /// Start from the beginning
    Beginning,
    /// Start from the end
    End,
}

/// A gap in the timeline where events are missing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineGap {
    /// Event ID before the gap
    pub prev_event_id: Option<EventId>,
    /// Event ID after the gap
    pub next_event_id: Option<EventId>,
    /// Estimated number of missing events
    pub estimated_gap_count: Option<u64>,
    /// Backfill token if supplied by sync.
    pub prev_batch: Option<String>,
    /// Why this gap exists.
    pub reason: SyncGapReason,
}

/// Event with its position in the timeline.
#[derive(Clone, Debug)]
pub struct TimelineEvent {
    /// The event
    pub event: Event,
    /// Deterministic order key.
    pub order: TimelineOrderKey,
    /// Position in the timeline
    pub position: TimelinePosition,
}

/// Position information for a timeline event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelinePosition {
    /// Index in the timeline
    pub index: usize,
    /// Whether this is the latest event
    pub is_latest: bool,
}

/// Stable UI-facing timeline item kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineItemKind {
    /// Message-like event.
    Message,
    /// Generic event that is not reduced into a richer item.
    Event,
    /// Local echo from an outbound queue.
    LocalEcho,
}

/// Aggregated reaction summary for one item.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineReactionSummary {
    /// Reaction key.
    pub reaction_key: String,
    /// Number of active senders.
    pub count: u64,
    /// Active senders in deterministic order.
    #[serde(default)]
    pub senders: Vec<Did>,
}

/// Read receipt summary attached to one item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineReadReceipt {
    /// User who sent the receipt.
    pub user_id: Did,
    /// Event the receipt targets.
    pub event_id: EventId,
    /// Public/private visibility.
    pub visibility: ReceiptVisibility,
    /// Optional thread.
    pub thread_id: Option<String>,
    /// Receipt time.
    pub received_at: DateTime<Utc>,
}

/// Typing state attached to a timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineTypingUpdate {
    /// Typing user.
    pub user_id: Did,
    /// Typing device.
    pub device_id: DeviceId,
    /// Whether the device is typing.
    pub is_typing: bool,
    /// Expiration time.
    pub expires_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// Stable UI-facing timeline item.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimelineItem {
    /// Stable item ID. Message IDs are preferred over event IDs.
    pub item_id: String,
    /// Original event ID that created this item.
    pub event_id: EventId,
    /// Latest event ID after edits/redactions.
    pub latest_event_id: EventId,
    /// Space ID.
    pub space_id: SpaceId,
    /// Sender of the original event.
    pub sender: Did,
    /// Item kind.
    pub kind: TimelineItemKind,
    /// Original deterministic position. Edits do not move the item.
    pub order: TimelineOrderKey,
    /// Latest event order that modified this item.
    pub latest_order: TimelineOrderKey,
    /// Current content after edits/redactions.
    pub content: Value,
    /// Edit event IDs in receive order.
    #[serde(default)]
    pub edit_event_ids: Vec<EventId>,
    /// Whether the item is redacted.
    pub redacted: bool,
    /// Redaction event ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_by: Option<EventId>,
    /// Reaction summaries keyed by reaction key.
    #[serde(default)]
    pub reactions: BTreeMap<String, TimelineReactionSummary>,
    /// Read receipts attached to this item.
    #[serde(default)]
    pub read_receipts: Vec<TimelineReadReceipt>,
}

impl TimelineItem {
    fn from_event(event: &Event, order: TimelineOrderKey, kind: TimelineItemKind) -> Self {
        let item_id = message_id(event).unwrap_or_else(|| event.event_id.to_string());
        Self {
            item_id,
            event_id: event.event_id.clone(),
            latest_event_id: event.event_id.clone(),
            space_id: event.space_id.clone(),
            sender: event.actor_id.clone(),
            kind,
            order: order.clone(),
            latest_order: order,
            content: event.content.clone(),
            edit_event_ids: Vec::new(),
            redacted: false,
            redacted_by: None,
            reactions: BTreeMap::new(),
            read_receipts: Vec::new(),
        }
    }
}

/// Result of focused event loading from local timeline state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FocusedTimeline {
    /// Requested target event.
    pub target_event_id: EventId,
    /// Items before the target.
    #[serde(default)]
    pub before: Vec<TimelineItem>,
    /// Target item, if loaded locally.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<TimelineItem>,
    /// Items after the target.
    #[serde(default)]
    pub after: Vec<TimelineItem>,
    /// Gaps relevant to this focused load.
    #[serde(default)]
    pub gaps: Vec<TimelineGap>,
    /// Suggested backfill request when the target or surrounding context is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backfill_request: Option<BackfillRequest>,
}

/// Event cache insertion result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCacheInsert {
    /// New event was inserted.
    Inserted,
    /// Same event ID and digest was already cached.
    DuplicateEventId,
    /// Same digest was already cached under another event ID.
    DuplicateDigest { existing_event_id: EventId },
}

/// Cached raw event and deterministic order metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedEvent {
    /// Parsed event.
    pub event: Event,
    /// Raw event JSON as received from sync/backfill.
    pub raw: Value,
    /// Canonical event digest.
    pub digest: String,
    /// Deterministic order key.
    pub order: TimelineOrderKey,
}

/// Result of applying sync or backfill to the cache.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCacheUpdate {
    /// Newly inserted event IDs.
    #[serde(default)]
    pub inserted: Vec<EventId>,
    /// Duplicate event IDs ignored.
    #[serde(default)]
    pub duplicate_event_ids: Vec<EventId>,
    /// Duplicate digests ignored.
    #[serde(default)]
    pub duplicate_digests: Vec<EventId>,
    /// Gaps created or remaining for the space.
    #[serde(default)]
    pub gaps: Vec<TimelineGap>,
}

/// In-memory event cache for raw events, processed items and timeline gaps.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventCache {
    events: BTreeMap<EventId, CachedEvent>,
    digest_index: BTreeMap<String, EventId>,
    depths: BTreeMap<EventId, u64>,
    processed_items: BTreeMap<SpaceId, BTreeMap<String, TimelineItem>>,
    gaps: BTreeMap<SpaceId, Vec<TimelineGap>>,
}

impl EventCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one parsed event, deduplicating by event ID and canonical digest.
    pub fn insert_event(&mut self, event: Event) -> Result<EventCacheInsert> {
        let raw = serde_json::to_value(&event)?;
        self.insert_event_with_raw(event, raw)
    }

    /// Insert one event with its raw JSON payload.
    pub fn insert_event_with_raw(&mut self, event: Event, raw: Value) -> Result<EventCacheInsert> {
        let digest = event.event_digest()?;
        if let Some(existing) = self.events.get(&event.event_id) {
            if existing.digest == digest {
                return Ok(EventCacheInsert::DuplicateEventId);
            }
            return Err(crate::Error::IdempotencyConflict(event.event_id.to_string()));
        }
        if let Some(existing_event_id) = self.digest_index.get(&digest) {
            return Ok(EventCacheInsert::DuplicateDigest {
                existing_event_id: existing_event_id.clone(),
            });
        }

        let depth = causal_depth_for(&event, &self.depths);
        let order = TimelineOrderKey::from_event(&event, depth);
        self.depths.insert(event.event_id.clone(), depth);
        self.digest_index.insert(digest.clone(), event.event_id.clone());
        self.events.insert(event.event_id.clone(), CachedEvent { event, raw, digest, order });
        Ok(EventCacheInsert::Inserted)
    }

    /// Apply a sync timeline section and record a limited gap when present.
    pub fn apply_sync_timeline(
        &mut self,
        space_id: SpaceId,
        timeline: &SyncTimeline,
    ) -> Result<EventCacheUpdate> {
        let mut update = EventCacheUpdate::default();
        let mut edge_event_ids = Vec::new();
        for raw in &timeline.events {
            let event: Event = serde_json::from_value(raw.clone())?;
            edge_event_ids.push(event.event_id.clone());
            match self.insert_event_with_raw(event, raw.clone())? {
                EventCacheInsert::Inserted => {
                    update.inserted.push(edge_event_ids.last().unwrap().clone())
                }
                EventCacheInsert::DuplicateEventId => {
                    update.duplicate_event_ids.push(edge_event_ids.last().unwrap().clone())
                }
                EventCacheInsert::DuplicateDigest { existing_event_id } => {
                    update.duplicate_digests.push(existing_event_id)
                }
            }
        }

        if timeline.limited {
            let gap = TimelineGap {
                prev_event_id: edge_event_ids.first().cloned(),
                next_event_id: edge_event_ids.last().cloned(),
                estimated_gap_count: None,
                prev_batch: timeline.prev_batch.clone(),
                reason: SyncGapReason::Limited,
            };
            self.gaps.entry(space_id.clone()).or_default().push(gap);
        }
        update.gaps = self.gaps(&space_id);
        Ok(update)
    }

    /// Apply backfilled events and clear the oldest persisted gap for the space.
    pub fn reconcile_backfill(
        &mut self,
        space_id: SpaceId,
        events: Vec<Event>,
    ) -> Result<EventCacheUpdate> {
        let mut update = EventCacheUpdate::default();
        for event in events {
            let event_id = event.event_id.clone();
            match self.insert_event(event)? {
                EventCacheInsert::Inserted => update.inserted.push(event_id),
                EventCacheInsert::DuplicateEventId => update.duplicate_event_ids.push(event_id),
                EventCacheInsert::DuplicateDigest { existing_event_id } => {
                    update.duplicate_digests.push(existing_event_id)
                }
            }
        }
        if let Some(gaps) = self.gaps.get_mut(&space_id) {
            if !gaps.is_empty() {
                gaps.remove(0);
            }
        }
        update.gaps = self.gaps(&space_id);
        Ok(update)
    }

    /// Store processed timeline items for later restoration.
    pub fn store_processed_items(
        &mut self,
        space_id: SpaceId,
        items: impl IntoIterator<Item = TimelineItem>,
    ) {
        let entry = self.processed_items.entry(space_id).or_default();
        for item in items {
            entry.insert(item.item_id.clone(), item);
        }
    }

    /// Processed timeline items for a space.
    pub fn processed_items(&self, space_id: &SpaceId) -> Vec<TimelineItem> {
        self.processed_items
            .get(space_id)
            .map(|items| items.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Cached event by ID.
    pub fn event(&self, event_id: &EventId) -> Option<&CachedEvent> {
        self.events.get(event_id)
    }

    /// Persisted gaps for a space.
    pub fn gaps(&self, space_id: &SpaceId) -> Vec<TimelineGap> {
        self.gaps.get(space_id).cloned().unwrap_or_default()
    }

    /// Create a backfill request for the next persisted gap.
    pub fn next_gap_backfill_request(
        &self,
        space_id: &SpaceId,
        limit: u32,
    ) -> Option<BackfillRequest> {
        let gap = self.gaps.get(space_id)?.first()?;
        Some(BackfillRequest {
            space_id: space_id.clone(),
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

/// Timeline for a space, managing events and pagination.
#[derive(Clone)]
pub struct Timeline {
    /// Space ID
    space_id: SpaceId,
    /// Base client reference
    _base_client: Arc<BaseClient>,
    /// Events in the timeline
    events: VecDeque<TimelineEvent>,
    /// Event IDs already seen by this timeline.
    event_ids: BTreeSet<EventId>,
    /// Causal depth by event ID.
    event_depths: BTreeMap<EventId, u64>,
    /// Stable timeline items by item ID.
    items: BTreeMap<String, TimelineItem>,
    /// Stable item IDs in deterministic order.
    item_order: Vec<String>,
    /// Event ID to stable item ID.
    event_to_item: BTreeMap<EventId, String>,
    /// Active reaction OR-set keyed by item, actor and reaction key.
    reaction_index: BTreeMap<(String, Did, String), bool>,
    /// Active typing updates keyed by user/device.
    typing: BTreeMap<(Did, DeviceId), TimelineTypingUpdate>,
    /// Known gaps in the timeline
    gaps: Vec<TimelineGap>,
    /// Latest event ID
    latest_event_id: Option<EventId>,
    /// Oldest event ID
    oldest_event_id: Option<EventId>,
    /// Maximum timeline size
    max_size: usize,
}

impl Timeline {
    /// Create a new timeline for a space.
    pub fn new(space_id: SpaceId, base_client: Arc<BaseClient>) -> Self {
        Self {
            space_id,
            _base_client: base_client,
            events: VecDeque::with_capacity(100),
            event_ids: BTreeSet::new(),
            event_depths: BTreeMap::new(),
            items: BTreeMap::new(),
            item_order: Vec::new(),
            event_to_item: BTreeMap::new(),
            reaction_index: BTreeMap::new(),
            typing: BTreeMap::new(),
            gaps: Vec::new(),
            latest_event_id: None,
            oldest_event_id: None,
            max_size: 1000,
        }
    }

    /// Set the maximum timeline size.
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Get the number of events in the timeline.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the timeline is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get the latest event ID.
    pub fn latest_event_id(&self) -> Option<&EventId> {
        self.latest_event_id.as_ref()
    }

    /// Get the oldest event ID.
    pub fn oldest_event_id(&self) -> Option<&EventId> {
        self.oldest_event_id.as_ref()
    }

    /// Get events in the timeline.
    pub fn events(&self) -> Vec<TimelineEvent> {
        self.events.iter().cloned().collect()
    }

    /// Get stable UI-facing timeline items.
    pub fn items(&self) -> Vec<TimelineItem> {
        self.item_order.iter().filter_map(|item_id| self.items.get(item_id).cloned()).collect()
    }

    /// Get one stable item by item ID.
    pub fn get_item(&self, item_id: &str) -> Option<TimelineItem> {
        self.items.get(item_id).cloned()
    }

    /// Get the stable item produced or modified by an event ID.
    pub fn item_for_event(&self, event_id: &EventId) -> Option<TimelineItem> {
        self.event_to_item.get(event_id).and_then(|item_id| self.get_item(item_id))
    }

    /// Get a specific event by ID.
    pub fn get_event(&self, event_id: &EventId) -> Option<TimelineEvent> {
        self.events.iter().find(|te| &te.event.event_id == event_id).cloned()
    }

    /// Get the latest event.
    pub fn latest_event(&self) -> Option<TimelineEvent> {
        self.events.back().cloned()
    }

    /// Get the oldest event.
    pub fn oldest_event(&self) -> Option<TimelineEvent> {
        self.events.front().cloned()
    }

    /// Add new events to the timeline (typically from sync).
    pub fn append_events(&mut self, events: Vec<Event>) -> Result<()> {
        for event in events {
            self.insert_event(event)?;
            self.trim_front();
        }

        Ok(())
    }

    /// Prepend events from backfill.
    pub fn prepend_events(&mut self, events: Vec<Event>) -> Result<()> {
        for event in events.into_iter().rev() {
            self.insert_event(event)?;
            self.trim_back();
        }

        Ok(())
    }

    /// Get a paginated slice of the timeline.
    pub fn paginate(&self, options: &TimelineOptions) -> Vec<TimelineEvent> {
        let events: Vec<TimelineEvent> = self.events.iter().cloned().collect();

        match &options.from {
            TimelineFrom::Latest => {
                match options.direction {
                    TimelineDirection::Backward => {
                        // Return the latest `limit` events
                        events.into_iter().rev().take(options.limit as usize).collect()
                    }
                    TimelineDirection::Forward => {
                        // Return the oldest `limit` events
                        events.into_iter().take(options.limit as usize).collect()
                    }
                    TimelineDirection::Both => {
                        // Return all events up to limit
                        events.into_iter().take(options.limit as usize).collect()
                    }
                }
            }
            TimelineFrom::EventId(event_id) => {
                if let Some(start_idx) = events.iter().position(|te| &te.event.event_id == event_id)
                {
                    match options.direction {
                        TimelineDirection::Backward => {
                            // Return events before start_idx
                            events[..start_idx]
                                .iter()
                                .rev()
                                .take(options.limit as usize)
                                .cloned()
                                .collect()
                        }
                        TimelineDirection::Forward => {
                            // Return events after start_idx
                            events[start_idx + 1..]
                                .iter()
                                .take(options.limit as usize)
                                .cloned()
                                .collect()
                        }
                        TimelineDirection::Both => {
                            // Return events around start_idx
                            let before = start_idx.saturating_sub(options.limit as usize / 2);
                            let after =
                                (start_idx + options.limit as usize / 2 + 1).min(events.len());
                            events[before..after].to_vec()
                        }
                    }
                } else {
                    // Event not found in timeline
                    Vec::new()
                }
            }
            TimelineFrom::Beginning => events.into_iter().take(options.limit as usize).collect(),
            TimelineFrom::End => events.into_iter().rev().take(options.limit as usize).collect(),
        }
    }

    /// Create a backfill request based on timeline gaps.
    pub fn create_backfill_request(&self, limit: u32) -> Option<BackfillRequest> {
        // Find the oldest gap or the beginning
        let from = if let Some(gap) = self.gaps.first() {
            if let Some(prev_batch) = &gap.prev_batch {
                BackfillFrom::Cursor { cursor: prev_batch.clone() }
            } else if let Some(prev_id) = &gap.prev_event_id {
                BackfillFrom::EventId { event_id: prev_id.clone() }
            } else {
                BackfillFrom::Beginning
            }
        } else if let Some(oldest_id) = &self.oldest_event_id {
            BackfillFrom::EventId { event_id: oldest_id.clone() }
        } else {
            BackfillFrom::Beginning
        };

        Some(BackfillRequest {
            space_id: self.space_id.clone(),
            from,
            direction: BackfillDirection::Backward,
            limit: Some(limit),
        })
    }

    /// Record a gap in the timeline.
    pub fn record_gap(
        &mut self,
        prev_event_id: Option<EventId>,
        next_event_id: Option<EventId>,
        estimated_count: Option<u64>,
    ) {
        let gap = TimelineGap {
            prev_event_id,
            next_event_id,
            estimated_gap_count: estimated_count,
            prev_batch: None,
            reason: SyncGapReason::Backfill,
        };
        self.gaps.push(gap);
    }

    /// Record a limited timeline gap from sync.
    pub fn record_limited_gap(
        &mut self,
        prev_event_id: Option<EventId>,
        next_event_id: Option<EventId>,
        prev_batch: Option<String>,
    ) {
        self.gaps.push(TimelineGap {
            prev_event_id,
            next_event_id,
            estimated_gap_count: None,
            prev_batch,
            reason: SyncGapReason::Limited,
        });
    }

    /// Clear known gaps (e.g., after backfill).
    pub fn clear_gaps(&mut self) {
        self.gaps.clear();
    }

    /// Get known gaps.
    pub fn gaps(&self) -> Vec<TimelineGap> {
        self.gaps.clone()
    }

    /// Apply a read receipt to a stable timeline item.
    pub fn apply_read_receipt(&mut self, receipt: ReadReceipt) {
        let item_id = self
            .event_to_item
            .get(&receipt.event_id)
            .cloned()
            .unwrap_or_else(|| receipt.event_id.to_string());
        if let Some(item) = self.items.get_mut(&item_id) {
            let summary = TimelineReadReceipt {
                user_id: receipt.user_id,
                event_id: receipt.event_id,
                visibility: receipt.visibility,
                thread_id: receipt.thread_id,
                received_at: receipt.received_at,
            };
            item.read_receipts.retain(|existing| {
                existing.user_id != summary.user_id || existing.thread_id != summary.thread_id
            });
            item.read_receipts.push(summary);
            item.read_receipts.sort_by(|left, right| left.user_id.cmp(&right.user_id));
        }
    }

    /// Apply a typing notification to ephemeral timeline state.
    pub fn apply_typing(&mut self, notification: TypingNotification) {
        let key = (notification.user_id.clone(), notification.device_id.clone());
        if notification.is_typing {
            self.typing.insert(
                key,
                TimelineTypingUpdate {
                    user_id: notification.user_id,
                    device_id: notification.device_id,
                    is_typing: true,
                    expires_at: notification.expires_at,
                    updated_at: notification.updated_at,
                },
            );
        } else {
            self.typing.remove(&key);
        }
    }

    /// Active typing users at `now`, merged across devices.
    pub fn active_typers_at(&self, now: DateTime<Utc>) -> Vec<Did> {
        let mut users = BTreeSet::new();
        for update in self.typing.values() {
            if update.is_typing && update.expires_at > now {
                users.insert(update.user_id.clone());
            }
        }
        users.into_iter().collect()
    }

    /// Load a focused item window around a target event.
    pub fn focused_window(
        &self,
        target_event_id: EventId,
        before: usize,
        after: usize,
    ) -> FocusedTimeline {
        let Some(item_id) = self.event_to_item.get(&target_event_id).cloned() else {
            return FocusedTimeline {
                target_event_id: target_event_id.clone(),
                before: Vec::new(),
                target: None,
                after: Vec::new(),
                gaps: self.gaps.clone(),
                backfill_request: Some(BackfillRequest {
                    space_id: self.space_id.clone(),
                    from: BackfillFrom::EventId { event_id: target_event_id },
                    direction: BackfillDirection::Both,
                    limit: Some((before + after + 1) as u32),
                }),
            };
        };

        let Some(index) = self.item_order.iter().position(|candidate| candidate == &item_id) else {
            return FocusedTimeline {
                target_event_id,
                before: Vec::new(),
                target: None,
                after: Vec::new(),
                gaps: self.gaps.clone(),
                backfill_request: None,
            };
        };
        let start = index.saturating_sub(before);
        let end = (index + after + 1).min(self.item_order.len());
        let before_items = self.item_order[start..index]
            .iter()
            .filter_map(|id| self.items.get(id).cloned())
            .collect();
        let after_items = self.item_order[index + 1..end]
            .iter()
            .filter_map(|id| self.items.get(id).cloned())
            .collect();
        let needs_backfill = index < before || index + after + 1 > self.item_order.len();

        FocusedTimeline {
            target_event_id,
            before: before_items,
            target: self.items.get(&item_id).cloned(),
            after: after_items,
            gaps: self.gaps.clone(),
            backfill_request: needs_backfill.then(|| BackfillRequest {
                space_id: self.space_id.clone(),
                from: BackfillFrom::EventId {
                    event_id: self.items.get(&item_id).unwrap().event_id.clone(),
                },
                direction: BackfillDirection::Both,
                limit: Some((before + after + 1) as u32),
            }),
        }
    }

    /// Update positions for all events in the timeline.
    fn update_positions(&mut self) {
        let len = self.events.len();
        for (index, te) in self.events.iter_mut().enumerate() {
            te.position.index = index;
            te.position.is_latest = index == len - 1;
        }
    }

    /// Clear the timeline.
    pub fn clear(&mut self) {
        self.events.clear();
        self.gaps.clear();
        self.latest_event_id = None;
        self.oldest_event_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::{Did, Hlc};
    use serde_json::json;

    fn create_test_event(space_id: &SpaceId, index: u32) -> Event {
        Event {
            event_id: EventId::new(format!("cx:event:{:04x}", index)).unwrap(),
            kind: "cx.entity.create".to_owned(),
            space_id: space_id.clone(),
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:alice.example.com").unwrap(),
            actor_seq: index as u64,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new(format!("01970e589d21-000000{:02x}-a13f9c2e", index)).unwrap(),
            prev_refs: vec![],
            auth_refs: vec![],
            redacts: None,
            content: json!({"id": format!("cx:entity:{:04x}", index)}),
            unsigned: BTreeMap::new(),
            proofs: vec![],
        }
    }

    #[test]
    fn timeline_starts_empty() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let timeline = Timeline::new(space_id, base_client);

        assert!(timeline.is_empty());
        assert_eq!(timeline.len(), 0);
    }

    #[test]
    fn timeline_appends_events() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let mut timeline = Timeline::new(space_id.clone(), base_client);

        let events = vec![
            create_test_event(&space_id, 1),
            create_test_event(&space_id, 2),
            create_test_event(&space_id, 3),
        ];

        timeline.append_events(events).unwrap();

        assert_eq!(timeline.len(), 3);
        assert!(timeline.latest_event_id().is_some());
    }

    #[test]
    fn timeline_prepends_events() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let mut timeline = Timeline::new(space_id.clone(), base_client);

        // First append some events
        let events1 = vec![create_test_event(&space_id, 4), create_test_event(&space_id, 5)];
        timeline.append_events(events1).unwrap();

        // Then prepend older events
        let events2 = vec![create_test_event(&space_id, 2), create_test_event(&space_id, 3)];
        timeline.prepend_events(events2).unwrap();

        assert_eq!(timeline.len(), 4);
        assert!(timeline.oldest_event_id().is_some());
    }

    #[test]
    fn timeline_paginates_backward_from_latest() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let mut timeline = Timeline::new(space_id.clone(), base_client);

        let events: Vec<Event> = (1..=10).map(|i| create_test_event(&space_id, i)).collect();
        timeline.append_events(events).unwrap();

        let options = TimelineOptions {
            limit: 3,
            direction: TimelineDirection::Backward,
            from: TimelineFrom::Latest,
        };

        let paginated = timeline.paginate(&options);
        assert_eq!(paginated.len(), 3);
        // Should return the latest 3 events (in reverse order)
        assert_eq!(paginated[0].event.actor_seq, 10);
        assert_eq!(paginated[1].event.actor_seq, 9);
        assert_eq!(paginated[2].event.actor_seq, 8);
    }

    #[test]
    fn timeline_paginates_from_event_id() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let mut timeline = Timeline::new(space_id.clone(), base_client);

        let events: Vec<Event> = (1..=10).map(|i| create_test_event(&space_id, i)).collect();
        timeline.append_events(events).unwrap();

        let from_event = EventId::new("cx:event:0005").unwrap();
        let options = TimelineOptions {
            limit: 2,
            direction: TimelineDirection::Forward,
            from: TimelineFrom::EventId(from_event),
        };

        let paginated = timeline.paginate(&options);
        assert_eq!(paginated.len(), 2);
        // Should return events after event 5
        assert_eq!(paginated[0].event.actor_seq, 6);
        assert_eq!(paginated[1].event.actor_seq, 7);
    }

    #[test]
    fn timeline_tracks_gaps() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let mut timeline = Timeline::new(space_id, base_client);

        let prev_id = EventId::new("cx:event:0001").unwrap();
        let next_id = EventId::new("cx:event:0003").unwrap();

        timeline.record_gap(Some(prev_id.clone()), Some(next_id.clone()), Some(1));

        let gaps = timeline.gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].prev_event_id, Some(prev_id));
        assert_eq!(gaps[0].next_event_id, Some(next_id));
    }

    #[test]
    fn timeline_clears_gaps() {
        let base_client = Arc::new(BaseClient::new());
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let mut timeline = Timeline::new(space_id, base_client);

        timeline.record_gap(None, None, Some(10));
        assert_eq