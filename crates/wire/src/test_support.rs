//! Raw Event fixtures for conformance and deliberately invalid test inputs.
//!
//! Production authoring must use `arkret_event_draft::TypedEventDraft` or the
//! validated extension boundary. Keeping these helpers out of `impl Event`
//! makes the standard raw constructor unavailable as an ordinary API.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::{ActorId, Did, Event, EventId, Hlc, Result, ScopeRef};

/// Envelope metadata historically embedded in raw projection fixture payloads.
///
/// Serde owns the split so fixture callers do not hand-edit an Event digest
/// preimage or maintain another list of excluded Event members.
#[derive(Deserialize)]
struct RawProjectionFixtureEnvelope {
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(flatten)]
    payload: serde_json::Map<String, Value>,
}

#[doc(hidden)]
pub struct RawProjectionFixtureParts {
    pub actor_id: Option<Did>,
    pub event_id: Option<EventId>,
    pub payload: Value,
}

/// Decode the legacy test-only projection fixture overlay into explicit
/// envelope metadata and a clean Event payload object.
#[doc(hidden)]
pub fn split_raw_projection_fixture_payload(payload: Value) -> Result<RawProjectionFixtureParts> {
    let fixture: RawProjectionFixtureEnvelope =
        serde_json::from_value(payload).map_err(|error| {
            crate::Error::Protocol(format!("invalid raw projection fixture: {error}"))
        })?;
    Ok(RawProjectionFixtureParts {
        actor_id: fixture.sender.and_then(|value| Did::new(value).ok()),
        event_id: fixture.event_id.and_then(|value| EventId::new(value).ok()),
        payload: Value::Object(fixture.payload),
    })
}

#[doc(hidden)]
pub fn raw_event(
    kind: impl Into<String>,
    scope_ref: ScopeRef,
    actor_id: ActorId,
    actor_seq: u64,
    hlc: Hlc,
    payload: Value,
) -> Result<Event> {
    Event::new(kind, scope_ref, actor_id, actor_seq, hlc, payload)
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn raw_event_at(
    kind: impl Into<String>,
    scope_ref: ScopeRef,
    actor_id: ActorId,
    actor_seq: u64,
    hlc: Hlc,
    payload: Value,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    Event::new_at(
        kind, scope_ref, actor_id, actor_seq, hlc, payload, created_at,
    )
}
