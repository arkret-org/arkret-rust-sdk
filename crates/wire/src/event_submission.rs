//! Actor-supplied Event submission bodies for
//! `ak.self.events.command.submit.v1`.
//!
//! A shared durable Event is handed to the current governance Station, which
//! answers with an authority-signed `RealmCommit`. The only submission shape
//! is [`EventCommitSubmission`]: these bodies carry producer Events and
//! nothing else, and never a predecessor pointer or stream position of their
//! own.

use serde::{Deserialize, Serialize};

use crate::authority_commit::EventCommitSubmission;
use crate::error::{Result, WireError};
use crate::event_envelope::Event;

/// Largest batch one `ak.self.events.command.submit.v1` request may carry
/// (`service-operation-dtos.schema.json#/$defs/EventsSubmitBatchRequestBody`
/// `events.maxItems`).
pub const EVENTS_SUBMIT_BATCH_MAX_EVENTS: usize = 500;

/// Actor-supplied `ak.self.events.command.submit.v1` input envelope.
///
/// It reuses the complete canonical [`Event`] shape, including the required
/// producer-signed `scope_ref`. Object payload schemas independently forbid an
/// actor-supplied `effective_scope` wherever that name is reserved for a
/// read-only materialized object projection.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/EventSubmitEnvelope (a `$ref` to
// the complete event-envelope.schema.json document).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventSubmitEnvelope(pub Event);

impl EventSubmitEnvelope {
    #[must_use]
    pub fn event(&self) -> &Event {
        &self.0
    }

    #[must_use]
    pub fn into_event(self) -> Event {
        self.0
    }

    /// Lift this envelope into the sole Station submission shape.
    #[must_use]
    pub fn into_commit_submission(self) -> EventCommitSubmission {
        EventCommitSubmission::new(self.0)
    }
}

impl From<Event> for EventSubmitEnvelope {
    fn from(event: Event) -> Self {
        Self(event)
    }
}

impl From<EventSubmitEnvelope> for EventCommitSubmission {
    fn from(envelope: EventSubmitEnvelope) -> Self {
        envelope.into_commit_submission()
    }
}

impl From<EventCommitSubmission> for EventSubmitEnvelope {
    fn from(submission: EventCommitSubmission) -> Self {
        Self(submission.event)
    }
}

/// Batch `ak.self.events.command.submit.v1` request used by account clients.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/EventsSubmitBatchRequestBody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubmitBatchRequestBody {
    pub events: Vec<EventCommitSubmission>,
}

impl EventsSubmitBatchRequestBody {
    pub fn new(events: Vec<EventCommitSubmission>) -> Result<Self> {
        let body = Self { events };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<()> {
        if self.events.is_empty() {
            return Err(WireError::Protocol(
                "events submit batch must carry at least one Event".to_owned(),
            ));
        }
        if self.events.len() > EVENTS_SUBMIT_BATCH_MAX_EVENTS {
            return Err(WireError::Protocol(format!(
                "events submit batch must carry at most {EVENTS_SUBMIT_BATCH_MAX_EVENTS} Events"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::{DidCoreId, EventKind, RealmId, ScopeRef, test_support};

    fn fixture_event() -> Event {
        let realm_id =
            RealmId::new("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5").unwrap();
        test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            ScopeRef::Realm { realm_id },
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({}),
            Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn submit_envelope_round_trips_as_the_complete_event() {
        let envelope = EventSubmitEnvelope::from(fixture_event());
        let encoded = serde_json::to_value(&envelope).unwrap();
        assert!(encoded.get("event").is_none());
        assert_eq!(
            encoded.get("scope_ref").expect("producer-signed scope_ref"),
            &serde_json::to_value(&envelope.event().scope_ref).unwrap()
        );

        let decoded: EventSubmitEnvelope = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn submit_envelope_rejects_unknown_members() {
        let mut encoded = serde_json::to_value(EventSubmitEnvelope::from(fixture_event())).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unregistered_member".to_owned(), json!(1));
        assert!(serde_json::from_value::<EventSubmitEnvelope>(encoded).is_err());
    }

    #[test]
    fn submit_envelope_rejects_a_missing_required_member() {
        for required in ["event_id", "kind", "scope_ref", "actor_id", "payload"] {
            let mut encoded =
                serde_json::to_value(EventSubmitEnvelope::from(fixture_event())).unwrap();
            encoded.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<EventSubmitEnvelope>(encoded).is_err(),
                "{required} must be required"
            );
        }
    }

    #[test]
    fn submit_envelope_is_the_only_commit_submission_shape() {
        let envelope = EventSubmitEnvelope::from(fixture_event());
        let submission = EventCommitSubmission::from(envelope.clone());
        assert_eq!(submission.event, *envelope.event());
        assert_eq!(EventSubmitEnvelope::from(submission), envelope);
    }

    #[test]
    fn batch_body_round_trips_over_commit_submissions() {
        let body =
            EventsSubmitBatchRequestBody::new(vec![EventCommitSubmission::new(fixture_event())])
                .unwrap();
        let encoded = serde_json::to_value(&body).unwrap();
        assert!(encoded["events"][0].get("event").is_some());

        let decoded: EventsSubmitBatchRequestBody = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, body);
        decoded.validate().unwrap();
    }

    #[test]
    fn batch_body_rejects_unknown_members() {
        let encoded = json!({
            "events": [{"event": serde_json::to_value(fixture_event()).unwrap()}],
            "lane": "standard"
        });
        assert!(serde_json::from_value::<EventsSubmitBatchRequestBody>(encoded).is_err());
    }

    #[test]
    fn batch_body_rejects_a_missing_required_member() {
        assert!(serde_json::from_value::<EventsSubmitBatchRequestBody>(json!({})).is_err());
    }

    #[test]
    fn batch_body_rejects_a_bare_event_instead_of_a_commit_submission() {
        let encoded = json!({"events": [serde_json::to_value(fixture_event()).unwrap()]});
        assert!(serde_json::from_value::<EventsSubmitBatchRequestBody>(encoded).is_err());
    }

    #[test]
    fn batch_body_bounds_the_event_count() {
        assert!(EventsSubmitBatchRequestBody::new(Vec::new()).is_err());
        let oversized = (0..=EVENTS_SUBMIT_BATCH_MAX_EVENTS)
            .map(|_| EventCommitSubmission::new(fixture_event()))
            .collect::<Vec<_>>();
        assert!(EventsSubmitBatchRequestBody::new(oversized).is_err());
    }
}
