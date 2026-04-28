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
#[derive(Clone, Debug, Default)]
pub struct ReceiptManager {
    markers: BTreeMap<(SpaceId, Did, Option<String>), ReadMarker>,
    receipts: BTreeMap<(SpaceId, EventId, Option<String>), Vec<ReadReceipt>>,
    thread_index: BTreeSet<(SpaceId, Option<String>)>,
}

impl ReceiptManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
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
    pub fn send_receipt(
        &mut self,
        space_id: SpaceId,
        user_id: Did,
        event_id: EventId,
        visibility: ReceiptVisibility,
        thread_id: Option<String>,
    ) -> ReadReceipt {
        let receipt = ReadReceipt {
            space_id: space_id.clone(),
            user_id,
            event_id: event_id.clone(),
            visibility,
            thread_id: thread_id.clone(),
            received_at: Utc::now(),
        };
        self.thread_index.insert((space_id.clone(), thread_id.clone()));
        self.receipts.entry((space_id, event_id, thread_id)).or_default().push(receipt.clone());
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
