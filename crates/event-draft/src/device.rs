use arkret_identifiers::{Did, Hlc};
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_wire::{Event, ScopeRef, event_spec};
use chrono::{DateTime, Utc};

use crate::{Result, TypedEventDraft};

/// Author a canonical `ak.device.authorize` control Event.
pub fn build_device_authorize_event_at(
    scope_ref: ScopeRef,
    actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
    payload: DeviceAuthorizePayload,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    let event = TypedEventDraft::<event_spec::DeviceAuthorize>::new(scope_ref, actor_id, payload)?
        .author(actor_seq, hlc, created_at)?;
    Ok(event)
}
