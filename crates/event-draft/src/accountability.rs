//! Accountability-grant Event materialization.

use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_integration::applet::AppletDelegatedEventAuthorization;
use arkret_wire::{Event, EventKind, Hlc, RealmId};

use crate::Result;

/// Materialize an accountability-grant payload as an unsigned Event draft.
pub fn accountability_grant_event(
    payload: &AccountabilityGrantPayload,
    realm_id: RealmId,
    actor_seq: u64,
    hlc: Hlc,
    authorization: Option<&AppletDelegatedEventAuthorization>,
) -> Result<Event> {
    let mut event = Event::new(
        EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        realm_id,
        payload.issuer.clone(),
        actor_seq,
        hlc,
        serde_json::to_value(payload)?,
    )?;
    if let Some(authorization) = authorization {
        authorization.apply_to_event(&mut event)?;
    }
    Ok(event)
}
