//! Complete typed Event admission before verification or consumption.

use arkret_wire::Event;
use serde_json::Value;

use crate::{EventDraftError, Result, validate_event_payload};

fn schema_violation(error: impl std::fmt::Display) -> EventDraftError {
    EventDraftError::Protocol(format!("schema_violation: {error}"))
}

/// Decode the closed Event root and its kind-selected payload as one gate.
/// No caller may repair a rejected value or consume its partially decoded root.
pub fn decode_event_for_submit(value: Value) -> Result<Event> {
    let event: Event = serde_json::from_value(value).map_err(schema_violation)?;
    validate_event_for_submit(&event)?;
    Ok(event)
}

/// Validate the complete typed Event contract before any downstream effect.
pub fn validate_event_for_submit(event: &Event) -> Result<()> {
    event
        .validate_for_submit_structural()
        .map_err(schema_violation)?;
    let value = serde_json::to_value(event).map_err(schema_violation)?;
    let _: Event = serde_json::from_value(value).map_err(schema_violation)?;
    validate_event_payload(
        &event.kind,
        &Value::Object(event.payload.clone().into_iter().collect()),
    )
    .map_err(schema_violation)?;
    Ok(())
}
