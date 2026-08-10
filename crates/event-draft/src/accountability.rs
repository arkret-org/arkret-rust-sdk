//! Accountability-grant Event materialization.

use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_integration::applet::AppletDelegatedEventAuthorization;
use arkret_wire::{ActorId, Event, Hlc, ScopeRef, event_spec, project_full_id_to_core_id};

use crate::{Result, TypedEventDraft};

/// Materialize an accountability-grant payload as an unsigned Event draft.
pub fn accountability_grant_event(
    payload: &AccountabilityGrantPayload,
    scope_ref: ScopeRef,
    actor_seq: u64,
    hlc: Hlc,
    authorization: Option<&AppletDelegatedEventAuthorization>,
) -> Result<Event> {
    let mut draft = TypedEventDraft::<event_spec::IdentityAccountabilityGrant>::new(
        scope_ref,
        ActorId::from(project_full_id_to_core_id(&payload.issuer)?),
        payload.clone(),
    )?;
    if let Some(authorization) = authorization {
        authorization.validate()?;
        draft = draft
            .with_executed_by(authorization.executed_by.clone())
            .with_authorization_ref(authorization.authorization_ref.clone())
            .with_applet_id(authorization.applet_id.clone());
    }
    draft.author_now(actor_seq, hlc)
}
