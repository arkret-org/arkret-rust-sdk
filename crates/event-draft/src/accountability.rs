//! Accountability-grant Event materialization.

use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_integration::applet::AppletDelegatedEventAuthorization;
use arkret_wire::{ActorId, ScopeRef, event_spec};
use chrono::{DateTime, Utc};

use crate::{EventIntent, Result, TypedEventDraft};

/// Materialize an accountability-grant payload as a write.
pub fn accountability_grant_intent(
    payload: &AccountabilityGrantPayload,
    scope_ref: ScopeRef,
    issuer_actor_id: ActorId,
    created_at: DateTime<Utc>,
    authorization: Option<&AppletDelegatedEventAuthorization>,
) -> Result<EventIntent> {
    let mut draft = TypedEventDraft::<event_spec::IdentityAccountabilityGrant>::new(
        scope_ref,
        issuer_actor_id,
        payload.clone(),
    )?;
    if let Some(authorization) = authorization {
        authorization.validate()?;
        draft = draft
            .with_executed_by(ActorId::service(authorization.executed_by.clone()))
            .with_authorization_ref(authorization.authorization_ref.clone())
            .with_applet_id(authorization.applet_id.clone());
    }
    draft.into_intent(created_at)
}
