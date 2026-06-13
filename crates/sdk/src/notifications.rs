//! Notification rules, counters and local notification state.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Authoritative wire shape for notification counters lives in the SDK's
// `client_api` module; the manager reuses it instead of keeping a
// field-subset copy.
pub use crate::client_api::NotificationCounts;
use crate::{Did, EventId, RealmId};

/// Notification action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationAction {
    /// Notify normally.
    Notify,
    /// Highlight the notification.
    Highlight,
    /// Suppress notification.
    DontNotify,
}

/// Notification rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRule {
    /// Rule ID.
    pub rule_id: String,
    /// Whether rule is enabled.
    pub enabled: bool,
    /// Optional event kind match.
    pub event_kind: Option<String>,
    /// Optional sender match.
    pub sender: Option<Did>,
    /// Action to apply.
    pub action: NotificationAction,
}

/// Notification item.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationItem {
    /// Notification ID.
    pub id: String,
    /// Realm ID.
    pub realm_id: Option<RealmId>,
    /// Event ID.
    pub event_id: EventId,
    /// Event sender.
    pub sender: Did,
    /// Event kind.
    pub event_kind: String,
    /// Preview payload.
    pub preview: Option<Value>,
    /// Highlight flag.
    pub highlight: bool,
    /// Read/dismissed flag.
    pub cleared: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Notification manager.
#[derive(Clone, Debug, Default)]
pub struct NotificationManager {
    rules: BTreeMap<String, NotificationRule>,
    notifications: BTreeMap<String, NotificationItem>,
    counts: BTreeMap<Option<RealmId>, NotificationCounts>,
}

impl NotificationManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a rule.
    pub fn upsert_rule(&mut self, rule: NotificationRule) {
        self.rules.insert(rule.rule_id.clone(), rule);
    }

    /// Remove a rule.
    pub fn remove_rule(&mut self, rule_id: &str) -> Option<NotificationRule> {
        self.rules.remove(rule_id)
    }

    /// List active rules.
    pub fn rules(&self) -> Vec<&NotificationRule> {
        self.rules.values().collect()
    }

    /// Evaluate rules for an event.
    pub fn evaluate(&self, event_kind: &str, sender: &Did) -> NotificationAction {
        self.rules
            .values()
            .find(|rule| {
                rule.enabled
                    && rule
                        .event_kind
                        .as_deref()
                        .map(|kind| kind == event_kind)
                        .unwrap_or(true)
                    && rule
                        .sender
                        .as_ref()
                        .map(|did| did == sender)
                        .unwrap_or(true)
            })
            .map(|rule| rule.action)
            .unwrap_or(NotificationAction::Notify)
    }

    /// Add a notification after rule evaluation.
    pub fn add_notification(
        &mut self,
        id: impl Into<String>,
        realm_id: Option<RealmId>,
        event_id: EventId,
        sender: Did,
        event_kind: impl Into<String>,
        preview: Option<Value>,
    ) -> Option<NotificationItem> {
        let event_kind = event_kind.into();
        let action = self.evaluate(&event_kind, &sender);
        if action == NotificationAction::DontNotify {
            return None;
        }

        let item = NotificationItem {
            id: id.into(),
            realm_id: realm_id.clone(),
            event_id,
            sender,
            event_kind,
            preview,
            highlight: action == NotificationAction::Highlight,
            cleared: false,
            created_at: Utc::now(),
        };
        self.increment(realm_id, item.highlight);
        self.notifications.insert(item.id.clone(), item.clone());
        Some(item)
    }

    /// Get counts for one Realm or global notifications.
    ///
    /// The in-memory manager treats every un-cleared notification as
    /// unread, so `unread_count` tracks `notification_count`.
    pub fn counts(&self, realm_id: Option<&RealmId>) -> NotificationCounts {
        self.counts
            .get(&realm_id.cloned())
            .cloned()
            .unwrap_or_default()
    }

    /// Clear one notification and decrement counts.
    pub fn clear_notification(&mut self, id: &str) -> bool {
        let Some(item) = self.notifications.get_mut(id) else {
            return false;
        };
        if item.cleared {
            return false;
        }
        item.cleared = true;
        let realm_id = item.realm_id.clone();
        let highlight = item.highlight;
        self.decrement(realm_id, highlight);
        true
    }

    /// Clear all notifications in a Realm.
    pub fn clear_realm(&mut self, realm_id: &RealmId) -> usize {
        let ids: Vec<_> = self
            .notifications
            .values()
            .filter(|item| item.realm_id.as_ref() == Some(realm_id) && !item.cleared)
            .map(|item| item.id.clone())
            .collect();
        let cleared = ids.len();
        for id in ids {
            self.clear_notification(&id);
        }
        cleared
    }

    fn increment(&mut self, realm_id: Option<RealmId>, highlight: bool) {
        let counts = self.counts.entry(realm_id).or_default();
        counts.notification_count += 1;
        counts.unread_count += 1;
        if highlight {
            counts.highlight_count += 1;
        }
    }

    fn decrement(&mut self, realm_id: Option<RealmId>, highlight: bool) {
        let counts = self.counts.entry(realm_id).or_default();
        counts.notification_count = counts.notification_count.saturating_sub(1);
        counts.unread_count = counts.unread_count.saturating_sub(1);
        if highlight {
            counts.highlight_count = counts.highlight_count.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn notifications_apply_rules_counts_highlights_and_clear() {
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let mut manager = NotificationManager::new();
        manager.upsert_rule(NotificationRule {
            rule_id: "mentions".to_owned(),
            enabled: true,
            event_kind: Some("ck.mention".to_owned()),
            sender: None,
            action: NotificationAction::Highlight,
        });

        let item = manager
            .add_notification(
                "n1",
                Some(realm_id.clone()),
                EventId::new("ck:event:01904100-0000-7000-8000-834e21b98552").unwrap(),
                alice,
                "ck.mention",
                Some(json!({"body":"hi"})),
            )
            .unwrap();
        assert!(item.highlight);
        assert_eq!(manager.counts(Some(&realm_id)).notification_count, 1);
        assert_eq!(manager.counts(Some(&realm_id)).highlight_count, 1);

        assert!(manager.clear_notification("n1"));
        assert_eq!(manager.counts(Some(&realm_id)).notification_count, 0);
    }

    #[test]
    fn notifications_can_suppress_and_clear_realm() {
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut manager = NotificationManager::new();
        manager.upsert_rule(NotificationRule {
            rule_id: "suppress".to_owned(),
            enabled: true,
            event_kind: Some("ck.noisy".to_owned()),
            sender: None,
            action: NotificationAction::DontNotify,
        });

        assert!(
            manager
                .add_notification(
                    "n0",
                    Some(realm_id.clone()),
                    EventId::new("ck:event:01904100-0000-7000-8000-155d51e9508a").unwrap(),
                    did("alice"),
                    "ck.noisy",
                    None,
                )
                .is_none()
        );

        manager.add_notification(
            "n1",
            Some(realm_id.clone()),
            EventId::new("ck:event:01904100-0000-7000-8000-834e21b98552").unwrap(),
            did("bob"),
            "ck.message.create",
            None,
        );
        manager.add_notification(
            "n2",
            Some(realm_id.clone()),
            EventId::new("ck:event:01904100-0000-7000-8000-6008ddd67225").unwrap(),
            did("carol"),
            "ck.message.create",
            None,
        );

        assert_eq!(manager.clear_realm(&realm_id), 2);
        assert_eq!(manager.counts(Some(&realm_id)).notification_count, 0);
    }
}
