//! Accountability-grant Event materialization.

use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_integration::applet::AppletDelegatedEventAuthorization;
use arkret_wire::{CellRef, Effect, Event, EventKind, Hlc, LatticeOp, LatticeOpType, RealmId};

use crate::Result;

/// Materialize an accountability-grant payload as an unsigned Event draft.
pub fn accountability_grant_event(
    payload: &AccountabilityGrantPayload,
    realm_id: RealmId,
    actor_seq: u64,
    hlc: Hlc,
    authorization: Option<&AppletDelegatedEventAuthorization>,
) -> Result<Event> {
    let payload_value = serde_json::to_value(payload)?;
    let mut event = Event::new(
        EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        realm_id,
        payload.issuer.clone(),
        actor_seq,
        hlc,
        payload_value.clone(),
    )?;
    event.effects = vec![Effect {
        cell: CellRef::new(format!(
            "ak:cell:ak.component.identity.accountability.v1:{}",
            payload.cell_subject()?
        ))?,
        op: LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(payload_value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    }];
    if let Some(authorization) = authorization {
        authorization.apply_to_event(&mut event)?;
    }
    Ok(event)
}
