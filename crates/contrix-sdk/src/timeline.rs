//! Timeline and event management for Contrix v1.
//!
//! This module provides timeline management for spaces, including:
//! - Event pagination
//! - Backfill support
//! - Timeline gaps
//! - Latest event tracking

use std::{
    collections::{VecDeque, BTreeMap},
    sync::Arc,
};

use serde_json::Value;

use crate::{
    base::BaseClient,
    model::{Event, EventId, SpaceId},
    sync::{BackfillDirection, BackfillFrom, BackfillRequest},
    Result,
};

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
        Self {
            limit: 50,
            direction: TimelineDirection::Backward,
            from: TimelineFrom::Latest,
        }
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
#[derive(Clone, Debug)]
pub struct TimelineGap {
    /// Event ID before the gap
    pub prev_event_id: Option<EventId>,
    /// Event ID after the gap
    pub next_event_id: Option<EventId>,
    /// Estimated number of missing events
    pub estimated_gap_count: Option<u64>,
}

/// Event with its position in the timeline.
#[derive(Clone, Debug)]
pub struct TimelineEvent {
    /// The event
    pub event: Event,
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

/// Timeline for a space, managing events and pagination.
#[derive(Clone)]
pub struct Timeline {
    /// Space ID
    space_id: SpaceId,
    /// Base client reference
    base_client: Arc<BaseClient>,
    /// Events in the timeline
    events: VecDeque<TimelineEvent>,
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
            base_client,
            events: VecDeque::with_capacity(100),
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

    /// Get a specific event by ID.
    pub fn get_event(&self, event_id: &EventId) -> Option<TimelineEvent> {
        self.events
            .iter()
            .find(|te| &te.event.event_id == event_id)
            .cloned()
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
            // Update latest event ID
            if self.latest_event_id.is_none() || event.hlc.as_str() > self.latest_event_id.as_ref().map(|id| id.as_str()).unwrap_or("") {
                self.latest_event_id = Some(event.event_id.clone());
            }

            let position = TimelinePosition {
                index: self.events.len(),
                is_latest: true,
            };

            let timeline_event = TimelineEvent {
                event,
                position,
            };

            self.events.push_back(timeline_event);

            // Trim if exceeds max size
            while self.events.len() > self.max_size {
                if let Some(removed) = self.events.pop_front() {
                    self.oldest_event_id = self.events.front().map(|te| te.event.event_id.clone());
                }
            }
        }

        // Update positions
        self.update_positions();

        Ok(())
    }

    /// Prepend events from backfill.
    pub fn prepend_events(&mut self, events: Vec<Event>) -> Result<()> {
        for event in events.into_iter().rev() {
            // Update oldest event ID
            if self.oldest_event_id.is_none() || event.hlc.as_str() < self.oldest_event_id.as_ref().map(|id| id.as_str()).unwrap_or("") {
                self.oldest_event_id = Some(event.event_id.clone());
            }

            let timeline_event = TimelineEvent {
                event,
                position: TimelinePosition {
                    index: 0,
                    is_latest: false,
                },
            };

            self.events.push_front(timeline_event);

            // Trim if exceeds max size
            while self.events.len() > self.max_size {
                if let Some(_removed) = self.events.pop_back() {
                    self.latest_event_id = self.events.back().map(|te| te.event.event_id.clone());
                }
            }
        }

        // Update positions
        self.update_positions();

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
                if let Some(start_idx) = events.iter().position(|te| &te.event.event_id == event_id) {
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
                            let after = (start_idx + options.limit as usize / 2 + 1).min(events.len());
                            events[before..after].to_vec()
                        }
                    }
                } else {
                    // Event not found in timeline
                    Vec::new()
                }
            }
            TimelineFrom::Beginning => {
                events.into_iter().take(options.limit as usize).collect()
            }
            TimelineFrom::End => {
                events.into_iter().rev().take(options.limit as usize).collect()
            }
        }
    }

    /// Create a backfill request based on timeline gaps.
    pub fn create_backfill_request(&self, limit: u32) -> Option<BackfillRequest> {
        // Find the oldest gap or the beginning
        let from = if let Some(gap) = self.gaps.first() {
            if let Some(prev_id) = &gap.prev_event_id {
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
    pub fn record_gap(&mut self, prev_event_id: Option<EventId>, next_event_id: Option<EventId>, estimated_count: Option<u64>) {
        let gap = TimelineGap {
            prev_event_id,
            next_event_id,
            estimated_gap_count: estimated_count,
        };
        self.gaps.push(gap);
    }

    /// Clear known gaps (e.g., after backfill).
    pub fn clear_gaps(&mut self) {
        self.gaps.clear();
    }

    /// Get known gaps.
    pub fn gaps(&self) -> Vec<TimelineGap> {
        self.gaps.clone()
    }

    /// Update positions for all events in the timeline.
    fn update_positions(&mut self) {
        let len = self.events.len();
        for (index, te) in self.events.iter_mut().enumerate() {
            te.position.index = index;
            te.position.is_latest = (index == len - 1);
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
    use crate::{DeviceId, Did, Hlc, base::SessionMeta};
    use serde_json::json;

    fn create_test_event(space_id: &SpaceId, index: u32) -> Event {
        Event {
            event_id: EventId::new(&format!("cx:event:{:04x}", index)).unwrap(),
            kind: "cx.entity.create".to_owned(),
            space_id: space_id.clone(),
            space_version: "1".to_owned(),
            actor_id: Did::new("did:web:alice.example.com").unwrap(),
            actor_seq: index as u64,
            created_at: chrono::Utc::now(),
            hlc: Hlc::new(&format!("01970e589d21-000000{:02x}-a13f9c2e", index)).unwrap(),
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
        let events1 = vec![
            create_test_event(&space_id, 4),
            create_test_event(&space_id, 5),
        ];
        timeline.append_events(events1).unwrap();

        // Then prepend older events
        let events2 = vec![
            create_test_event(&space_id, 2),
            create_test_event(&space_id, 3),
        ];
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
        let mut timeline = Timeline::new(space_id.clone(), base_client);

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
        let mut timeline = Timeline::new(space_id.clone(), base_client);

        timeline.record_gap(None, None, Some(10));
        assert_eq!(timeline.gaps().len(), 1);

        timeline.clear_gaps();
        assert_eq!(timeline.gaps().len(), 0);
    }
}
