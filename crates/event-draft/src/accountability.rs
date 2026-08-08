//! Accountability-grant Event materialization.

use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_integration::applet::AppletDelegatedEventAuthorization;
use arkret_wire::{Event, EventKind, Hlc, ScopeRef};

use crate::Result;

/// Materialize an accountability-grant payload as an unsigned Event draft.
pub fn accountability_grant_event(
    payload: &AccountabilityGrantPayload,
    scope_ref: ScopeRef,
    actor_seq: u64,
    hlc: Hlc,
    authorization: Option<&AppletDelegatedEventAuthorization>,
) -> Result<Event> {
    let payload_value = serde_json::to_value(payload)?;
    let mut event = Event::new(
        EventKind::IdentityAccountabilityGrant.to_string(),
        scope_ref,
        payload.issuer.clone(),
        actor_seq,
        hlc,
        payload_value,
    )?;
    if let Some(authorization) = authorization {
        authorization.apply_to_event(&mut event)?;
    }
    Ok(event)
}
