use arkret_identifiers::{Did, Hlc};
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_wire::{Event, ScopeRef};
use chrono::{DateTime, Utc};

use crate::Result;

/// Author a canonical `ak.device.authorize` control Event.
pub fn build_device_authorize_event_at(
    scope_ref: ScopeRef,
    actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
    payload: DeviceAuthorizePayload,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    let payload_value = serde_json::to_value(&payload)?;
    let event = Event::new_at(
        arkret_wire::EventKind::DeviceAuthorize.to_string(),
        scope_ref,
        actor_id,
        actor_seq,
        hlc,
        payload_value,
        created_at,
    )?;
    Ok(event)
}
