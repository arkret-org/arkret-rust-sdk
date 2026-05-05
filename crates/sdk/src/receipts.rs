//! Read markers and read receipts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Did, EventId, SpaceId};

/// Read receipt visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVisibility {
    /// Visible to other members.
    Public,
    /// Private to this user/account.
    Private,
}

/// Read marker for one user in one space/thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarker {
    /// Space ID.
    pub space_id: SpaceId,
    /// User DID.
    pub user_id: Did,
    /// Event ID considered read.
    pub event_id: EventId,
    /// Optional thread ID.
    pub thread_id: Option<String>,
    /// Update time.
    pub updated_at: DateTime<Utc>,
}

/// Read receipt event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceipt {
    /// Space ID.
    pub space_id: SpaceId,
    /// User DID.
    pub user_id: Did,
    /// Event ID.
    pub event_id: EventId,
    /// Public or private receipt.
    pub visibility: ReceiptVisibility,
    /// Optional thread ID.
    pub thread_id: Option<String>,
    /// Receipt time.
    pub received_at: DateTime<Utc>,
}

/// Read receipt manager.
///
/// `dedup_window_ms` (default 1000 ms per `service-surface.md` §124)
/// controls the active de-duplication window. Calls to
/// [`Self::send_receipt`] within the window for the same
/// `(space_id, user_id, thread_id)` collapse into the existing receipt
/// instead of producing a new one.
#[derive(Clone, Debug)]
pub struct ReceiptManager {
    markers: BTreeMap<(SpaceId, Did, Option<String>), ReadMarker>,
    receipts: BTreeMap<(SpaceId, EventId, Option<String>), Vec<ReadReceipt>>,
    thread_index: BTreeSet<(SpaceId, Option<String>)>,
    last_send_at: BTreeMap<(SpaceId, Did, Option<String>), DateTime<Utc>>,
    dedup_window_ms: i64,
}

impl Default for ReceiptManager {
    fn default() -> Self {
        Self {
            markers: BTreeMap::new(),
            receipts: BTreeMap::new(),
            thread_index: BTreeSet::new(),
            last_send_at: BTreeMap::new(),
            dedup_window_ms: 1000,
        }
    }
}

impl ReceiptManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the active de-duplication window. Use a window of
    /// 0 ms to disable de-duplication entirely.
    pub fn with_dedup_window_ms(mut self, ms: i64) -> Self {
        self.dedup_window_ms = ms.max(0);
        self
    }

    /// Set a read marker.
    pub fn set_read_marker(
        &mut self,
        space_id: SpaceId,
        user_id: Did,
        event_id: EventId,
        thread_id: Option<String>,
    ) -> ReadMarker {
        let marker = ReadMarker {
            space_id: space_id.clone(),
            user_id: user_id.clone(),
            event_id,
            thread_id: thread_id.clone(),
            updated_at: Utc::now(),
        };
        self.thread_index.insert((space_id.clone(), thread_id.clone()));
        self.markers.insert((space_id, user_id, thread_id), marker.clone());
        marker
    }

    /// Get a read marker.
    pub fn read_marker(
        &self,
        space_id: &SpaceId,
        user_id: &Did,
        thread_id: Option<&str>,
    ) -> Option<&ReadMarker> {
        self.markers.get(&(space_id.clone(), user_id.clone(), thread_id.map(str::to_owned)))
    }

    /// Send/store a read receipt.
    ///
    /// Honors the active de-duplication window: when a receipt for the
    /// same `(space_id, user_id, thread_id)` was issued within the
    /// configured window, the new send is treated as a no-op and the
    /// existing latest receipt is returned. Set `dedup_window_ms = 0`
    /// to disable.
    pub fn send_receipt(
        &mut self,
        space_id: SpaceId,
        user_id: Did,
        event_id: EventId,
        visibility: ReceiptVisibility,
        thread_id: Option<String>,
    ) -> ReadReceipt {
        let now = Utc::now();
        let dedup_key = (space_id.clone(), user_id.clone(), thread_id.clone());
        if self.dedup_window_ms > 0
            && let Some(prev) = self.last_send_at.get(&dedup_key)
            && now.signed_duration_since(*prev).num_milliseconds() < self.dedup_window_ms
            && let Some(latest) = self
                .receipts
                .get(&(space_id.clone(), event_id.clone(), thread_id.clone()))
                .and_then(|stack| stack.last())
        {
            return latest.clone();
        }
        let receipt = ReadReceipt {
            space_id: space_id.clone(),
            user_id,
            event_id: event_id.clone(),
            visibility,
            thread_id: thread_id.clone(),
            received_at: now,
        };
        self.thread_index.insert((space_id.clone(), thread_id.clone()));
        self.last_send_at.insert(dedup_key, now);
        self.receipts
            .entry((space_id, event_id, thread_id))
            .or_default()
            .push(receipt.clone());
        receipt
    }

    /// Process a receipt received from sync.
    pub fn process_receipt(&mut self, receipt: ReadReceipt) {
        self.thread_index.insert((receipt.space_id.clone(), receipt.thread_id.clone()));
        self.receipts
            .entry((receipt.space_id.clone(), receipt.event_id.clone(), receipt.thread_id.clone()))
            .or_default()
            .push(receipt);
    }

    /// Receipts for one event/thread.
    pub fn receipts_for_event(
        &self,
        space_id: &SpaceId,
        event_id: &EventId,
        thread_id: Option<&str>,
    ) -> Vec<&ReadReceipt> {
        self.receipts
            .get(&(space_id.clone(), event_id.clone(), thread_id.map(str::to_owned)))
            .map(|receipts| receipts.iter().collect())
            .unwrap_or_default()
    }

    /// Known thread positions for a space.
    pub fn thread_positions(&self, space_id: &SpaceId) -> Vec<Option<String>> {
        self.thread_index
            .iter()
            .filter(|(candidate, _)| candidate == space_id)
            .map(|(_, thread_id)| thread_id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn receipts_manage_markers_public_private_and_threads() {
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let alice = did("alice");
        let event = EventId::new("cx:event:01").unwrap();
        let mut manager = ReceiptManager::new();

        manager.set_read_marker(
            space_id.clone(),
            alice.clone(),
            event.clone(),
            Some("t1".to_owned()),
        );
        assert!(manager.read_marker(&space_id, &alice, Some("t1")).is_some());

        manager.send_receipt(
            space_id.clone(),
            alice,
            event.clone(),
            ReceiptVisibility::Private,
            Some("t1".to_owned()),
        );
        manager.send_receipt(
            space_id.clone(),
            did("bob"),
            event.clone(),
            ReceiptVisibility::Public,
            Some("t1".to_owned()),
        );

        assert_eq!(manager.receipts_for_event(&space_id, &event, Some("t1")).len(), 2);
        assert_eq!(manager.thread_positions(&space_id), vec![Some("t1".to_owned())]);
    }
}
