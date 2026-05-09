//! Typing indicator state management.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{DeviceId, Did, SpaceId};

/// Typing notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypingNotification {
    pub space_id: SpaceId,
    pub user_id: Did,
    pub device_id: DeviceId,
    pub is_typing: bool,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Typing manager with timeout, multi-device merge and debounce.
#[derive(Clone, Debug)]
pub struct TypingManager {
    states: BTreeMap<(SpaceId, Did, DeviceId), TypingNotification>,
    last_sent: BTreeMap<(SpaceId, Did, DeviceId), DateTime<Utc>>,
    debounce: Duration,
}

impl TypingManager {
    /// Create a manager with debounce duration.
    pub fn new(debounce: Duration) -> Self {
        Self { states: BTreeMap::new(), last_sent: BTreeMap::new(), debounce }
    }

    /// Send/update a typing notification. Returns `None` when debounced.
    pub fn send_typing(
        &mut self,
        space_id: SpaceId,
        user_id: Did,
        device_id: DeviceId,
        is_typing: bool,
        timeout: Duration,
    ) -> Option<TypingNotification> {
        let key = (space_id.clone(), user_id.clone(), device_id.clone());
        let now = Utc::now();
        if self
            .last_sent
            .get(&key)
            .map(|last| now.signed_duration_since(*last) < self.debounce)
            .unwrap_or(false)
        {
            return None;
        }

        let notification = TypingNotification {
            space_id,
            user_id,
            device_id,
            is_typing,
            expires_at: now + timeout,
            updated_at: now,
        };
        self.process_notification(notification.clone());
        self.last_sent.insert(key, now);
        Some(notification)
    }

    /// Process a typing notification received from sync.
    pub fn process_notification(&mut self, notification: TypingNotification) {
        let key = (
            notification.space_id.clone(),
            notification.user_id.clone(),
            notification.device_id.clone(),
        );
        if notification.is_typing {
            self.states.insert(key, notification);
        } else {
            self.states.remove(&key);
        }
    }

    /// Expire stale typing states.
    pub fn expire(&mut self, now: DateTime<Utc>) {
        self.states
            .retain(|_, notification| notification.expires_at > now && notification.is_typing);
    }

    /// Active typing users in a space after merging devices.
    pub fn active_typers(&self, space_id: &SpaceId) -> Vec<&Did> {
        let mut users = BTreeSet::new();
        for notification in self.states.values() {
            if &notification.space_id == space_id
                && notification.is_typing
                && notification.expires_at > Utc::now()
            {
                users.insert(&notification.user_id);
            }
        }
        users.into_iter().collect()
    }

    /// Active typing devices for a user in a space.
    pub fn active_devices(&self, space_id: &SpaceId, user_id: &Did) -> Vec<&DeviceId> {
        self.states
            .values()
            .filter(|notification| {
                &notification.space_id == space_id
                    && &notification.user_id == user_id
                    && notification.is_typing
                    && notification.expires_at > Utc::now()
            })
            .map(|notification| &notification.device_id)
            .collect()
    }
}

impl Default for TypingManager {
    fn default() -> Self {
        Self::new(Duration::milliseconds(750))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        DeviceId::new(format!("dev_{id}")).unwrap()
    }

    #[test]
    fn typing_sends_processes_merges_devices_and_expires() {
        let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = TypingManager::new(Duration::zero());

        manager.send_typing(
            space_id.clone(),
            alice.clone(),
            device("phone"),
            true,
            Duration::seconds(30),
        );
        manager.send_typing(
            space_id.clone(),
            alice.clone(),
            device("laptop"),
            true,
            Duration::seconds(30),
        );

        assert_eq!(manager.active_typers(&space_id), vec![&alice]);
        assert_eq!(manager.active_devices(&space_id, &alice).len(), 2);

        manager.expire(Utc::now() + Duration::seconds(31));
        assert!(manager.active_typers(&space_id).is_empty());
    }

    #[test]
    fn typing_debounces_repeated_notifications_and_stops() {
        let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = TypingManager::new(Duration::seconds(60));

        assert!(
            manager
                .send_typing(
                    space_id.clone(),
                    alice.clone(),
                    device("phone"),
                    true,
                    Duration::seconds(30),
                )
                .is_some()
        );
        assert!(
            manager
                .send_typing(
                    space_id.clone(),
                    alice.clone(),
                    device("phone"),
                    true,
                    Duration::seconds(30),
                )
                .is_none()
        );

        manager.process_notification(TypingNotification {
            space_id: space_id.clone(),
            user_id: alice,
            device_id: device("phone"),
            is_typing: false,
            expires_at: Utc::now(),
            updated_at: Utc::now(),
        });
        assert!(manager.active_typers(&space_id).is_empty());
    }
}
