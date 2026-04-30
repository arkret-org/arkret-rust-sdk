//! UI projection contracts for Contrix clients.

use std::collections::{BTreeMap, BTreeSet};

use contrix_core::{Did, Error, Event, EventId, Hlc, Result, SpaceId};
use contrix_crypto::UnableToDecryptReason;
use contrix_events::{
    EventClass, MESSAGE_EDIT, MESSAGE_REACTION, MESSAGE_REDACTION, classify_event_kind,
};
use contrix_push_gateway_api::{PushPriority, PushRuleSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineItemKind {
    Message,
    State,
    Ephemeral,
    AccountData,
    Call,
    Collaboration,
    Event,
    Redacted,
    UnableToDecrypt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineReactionSummary {
    pub key: String,
    pub count: u64,
    pub senders: BTreeSet<Did>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimelineItem {
    pub item_id: String,
    pub event_id: EventId,
    pub latest_event_id: EventId,
    pub space_id: SpaceId,
    pub sender: Did,
    pub event_kind: String,
    pub kind: TimelineItemKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default)]
    pub redacted: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reactions: BTreeMap<String, TimelineReactionSummary>,
    pub order: Hlc,
}

impl TimelineItem {
    pub fn from_event(event: &Event) -> Self {
        Self {
            item_id: event.event_id.to_string(),
            event_id: event.event_id.clone(),
            latest_event_id: event.event_id.clone(),
            space_id: event.space_id.clone(),
            sender: event.actor_id.clone(),
            event_kind: event.kind.clone(),
            kind: timeline_kind_for_event(&event.kind),
            body: event.content.get("body").and_then(Value::as_str).map(str::to_owned),
            redacted: false,
            reactions: BTreeMap::new(),
            order: event.hlc.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineGap {
    pub space_id: SpaceId,
    pub prev_batch: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TimelineProjection {
    items: BTreeMap<EventId, TimelineItem>,
    order: Vec<EventId>,
    gaps: Vec<TimelineGap>,
}

impl TimelineProjection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_event(&mut self, event: Event) -> Result<()> {
        if event.kind == MESSAGE_REDACTION {
            return self.apply_redaction(&event);
        }
        if event.kind == MESSAGE_EDIT {
            return self.apply_edit(&event);
        }
        if event.kind == MESSAGE_REACTION {
            return self.apply_reaction(&event);
        }

        if !self.items.contains_key(&event.event_id) {
            self.order.push(event.event_id.clone());
        }
        self.items.insert(event.event_id.clone(), TimelineItem::from_event(&event));
        self.order.sort_by(|left, right| {
            let left_item = self.items.get(left).expect("order ids are present");
            let right_item = self.items.get(right).expect("order ids are present");
            left_item.order.cmp(&right_item.order).then_with(|| left.cmp(right))
        });
        Ok(())
    }

    pub fn apply_unable_to_decrypt(
        &mut self,
        event_id: EventId,
        space_id: SpaceId,
        sender: Did,
        reason: UnableToDecryptReason,
        order: Hlc,
    ) {
        let item = TimelineItem {
            item_id: event_id.to_string(),
            event_id: event_id.clone(),
            latest_event_id: event_id.clone(),
            space_id,
            sender,
            event_kind: format!("unable_to_decrypt:{reason:?}"),
            kind: TimelineItemKind::UnableToDecrypt,
            body: None,
            redacted: false,
            reactions: BTreeMap::new(),
            order,
        };
        if !self.items.contains_key(&event_id) {
            self.order.push(event_id.clone());
        }
        self.items.insert(event_id, item);
    }

    pub fn add_gap(&mut self, gap: TimelineGap) {
        self.gaps.push(gap);
    }

    pub fn items(&self) -> Vec<&TimelineItem> {
        self.order.iter().filter_map(|event_id| self.items.get(event_id)).collect()
    }

    pub fn gaps(&self) -> &[TimelineGap] {
        &self.gaps
    }

    fn apply_redaction(&mut self, event: &Event) -> Result<()> {
        if let Some(target) = target_event_id(event)? {
            if let Some(item) = self.items.get_mut(&target) {
                item.redacted = true;
                item.kind = TimelineItemKind::Redacted;
                item.body = None;
                item.latest_event_id = event.event_id.clone();
            }
        }
        Ok(())
    }

    fn apply_edit(&mut self, event: &Event) -> Result<()> {
        if let Some(target) = target_event_id(event)? {
            if let Some(item) = self.items.get_mut(&target) {
                item.body = event.content.get("body").and_then(Value::as_str).map(str::to_owned);
                item.latest_event_id = event.event_id.clone();
            }
        }
        Ok(())
    }

    fn apply_reaction(&mut self, event: &Event) -> Result<()> {
        let Some(target) = target_event_id(event)? else {
            return Ok(());
        };
        let key = event.content.get("key").and_then(Value::as_str).unwrap_or("+1").to_owned();
        if let Some(item) = self.items.get_mut(&target) {
            let summary = item.reactions.entry(key.clone()).or_insert_with(|| {
                TimelineReactionSummary { key, count: 0, senders: BTreeSet::new() }
            });
            if summary.senders.insert(event.actor_id.clone()) {
                summary.count += 1;
            }
            item.latest_event_id = event.event_id.clone();
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceListEntry {
    pub space_id: SpaceId,
    pub name: String,
    pub membership: String,
    pub last_activity: Option<Hlc>,
    pub notification_count: u64,
    pub highlight_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SpaceListService {
    entries: BTreeMap<SpaceId, SpaceListEntry>,
}

impl SpaceListService {
    pub fn upsert(&mut self, entry: SpaceListEntry) {
        self.entries.insert(entry.space_id.clone(), entry);
    }

    pub fn apply_notification_counts(
        &mut self,
        space_id: &SpaceId,
        notification_count: u64,
        highlight_count: u64,
    ) -> Result<()> {
        let Some(entry) = self.entries.get_mut(space_id) else {
            return Err(Error::Protocol(format!("space list entry '{}' is missing", space_id)));
        };
        entry.notification_count = notification_count;
        entry.highlight_count = highlight_count;
        Ok(())
    }

    pub fn sorted_by_activity(&self) -> Vec<&SpaceListEntry> {
        let mut entries = self.entries.values().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            right
                .last_activity
                .cmp(&left.last_activity)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.space_id.cmp(&right.space_id))
        });
        entries
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationEvaluation {
    pub notify: bool,
    pub highlight: bool,
    pub priority: PushPriority,
    pub redacted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NotificationClient {
    pub rules: PushRuleSet,
}

impl NotificationClient {
    pub fn evaluate_event(&self, event: &Event) -> NotificationEvaluation {
        let rule = self.rules.matching_rule(&event.kind);
        let priority = rule.map(|rule| rule.priority).unwrap_or(PushPriority::Normal);
        NotificationEvaluation {
            notify: rule.is_some()
                || matches!(classify_event_kind(&event.kind), EventClass::Message),
            highlight: priority >= PushPriority::High,
            priority,
            redacted: rule.map(|rule| rule.redact_content).unwrap_or(false),
        }
    }
}

fn timeline_kind_for_event(kind: &str) -> TimelineItemKind {
    match classify_event_kind(kind) {
        EventClass::Message => TimelineItemKind::Message,
        EventClass::State => TimelineItemKind::State,
        EventClass::Ephemeral => TimelineItemKind::Ephemeral,
        EventClass::AccountData => TimelineItemKind::AccountData,
        EventClass::Call => TimelineItemKind::Call,
        EventClass::Collaboration => TimelineItemKind::Collaboration,
        EventClass::Rtc | EventClass::E2ee | EventClass::Custom(_) => TimelineItemKind::Event,
    }
}

fn target_event_id(event: &Event) -> Result<Option<EventId>> {
    event
        .content
        .get("target_event_id")
        .and_then(Value::as_str)
        .map(EventId::new)
        .transpose()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use contrix_events::{MESSAGE_TEXT, STATE_MEMBERSHIP};
    use contrix_push_gateway_api::{PushRule, PushRuleSet};
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn event(id: &str, kind: &str, body: Value, seq: u64) -> Event {
        Event::new(
            kind,
            SpaceId::new("cx:space:ui").unwrap(),
            did("alice"),
            seq,
            Hlc::new(format!("01970e589d21-{seq:08x}-a13f9c2e")).unwrap(),
            body,
        )
        .unwrap()
        .with_event_id(EventId::new(id).unwrap())
    }

    trait WithEventId {
        fn with_event_id(self, event_id: EventId) -> Self;
    }

    impl WithEventId for Event {
        fn with_event_id(mut self, event_id: EventId) -> Self {
            self.event_id = event_id;
            self
        }
    }

    #[test]
    fn timeline_projects_edits_redactions_and_reactions() {
        let mut projection = TimelineProjection::new();
        projection
            .apply_event(event("cx:event:01", MESSAGE_TEXT, json!({"body": "hello"}), 1))
            .unwrap();
        projection
            .apply_event(event(
                "cx:event:02",
                MESSAGE_EDIT,
                json!({"target_event_id": "cx:event:01", "body": "hello edited"}),
                2,
            ))
            .unwrap();
        projection
            .apply_event(event(
                "cx:event:03",
                MESSAGE_REACTION,
                json!({"target_event_id": "cx:event:01", "key": "+1"}),
                3,
            ))
            .unwrap();

        let item = projection.items()[0];
        assert_eq!(item.body.as_deref(), Some("hello edited"));
        assert_eq!(item.reactions["+1"].count, 1);

        projection
            .apply_event(event(
                "cx:event:04",
                MESSAGE_REDACTION,
                json!({"target_event_id": "cx:event:01"}),
                4,
            ))
            .unwrap();
        let item = projection.items()[0];
        assert!(item.redacted);
        assert_eq!(item.kind, TimelineItemKind::Redacted);
    }

    #[test]
    fn space_list_sorts_by_activity_and_tracks_counts() {
        let space_a = SpaceId::new("cx:space:a").unwrap();
        let space_b = SpaceId::new("cx:space:b").unwrap();
        let mut service = SpaceListService::default();
        service.upsert(SpaceListEntry {
            space_id: space_a.clone(),
            name: "A".to_owned(),
            membership: "join".to_owned(),
            last_activity: Some(Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap()),
            notification_count: 0,
            highlight_count: 0,
            preview: None,
        });
        service.upsert(SpaceListEntry {
            space_id: space_b.clone(),
            name: "B".to_owned(),
            membership: "join".to_owned(),
            last_activity: Some(Hlc::new("01970e589d22-00000001-a13f9c2e").unwrap()),
            notification_count: 0,
            highlight_count: 0,
            preview: None,
        });
        service.apply_notification_counts(&space_b, 3, 1).unwrap();
        let sorted = service.sorted_by_activity();
        assert_eq!(sorted[0].space_id, space_b);
        assert_eq!(sorted[0].highlight_count, 1);
    }

    #[test]
    fn notification_client_uses_push_rules_and_message_default() {
        let mut rules = PushRuleSet::default();
        rules.rules.insert(
            "mentions".to_owned(),
            PushRule {
                rule_id: "mentions".to_owned(),
                enabled: true,
                event_kind: Some(MESSAGE_TEXT.to_owned()),
                priority: PushPriority::High,
                redact_content: true,
            },
        );
        let client = NotificationClient { rules };
        let message = event("cx:event:notify", MESSAGE_TEXT, json!({"body": "hi"}), 1);
        let evaluation = client.evaluate_event(&message);
        assert!(evaluation.notify);
        assert!(evaluation.highlight);
        assert!(evaluation.redacted);

        let state = event("cx:event:state", STATE_MEMBERSHIP, json!({}), 2);
        assert!(!NotificationClient::default().evaluate_event(&state).notify);
    }
}
