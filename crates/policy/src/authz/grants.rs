//! Capability grant event builders.

use arkret_wire::ActorId;
use chrono::{DateTime, Utc};

use super::*;

/// Build a `ak.capability.relinquish` intent for `subject` under `scope_ref`.
pub fn build_capability_relinquish_intent(
    scope_ref: arkret_wire::ScopeRef,
    subject: ActorId,
    created_at: DateTime<Utc>,
    payload: arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload,
) -> Result<arkret_event_draft::EventIntent> {
    arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::CapabilityRelinquish>::new(
        scope_ref, subject, payload,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?
    .into_intent(created_at)
    .map_err(|error| WireError::Protocol(error.to_string()))
}
