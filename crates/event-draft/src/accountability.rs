//! Accountability-grant Event materialization.

use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_integration::applet::AppletDelegatedEventAuthorization;
use arkret_wire::{ScopeRef, event_spec};
use chrono::{DateTime, Utc};

use crate::{EventIntent, Result, TypedEventDraft};

/// Materialize an accountability-grant payload as a write.
pub fn accountability_grant_intent(
    payload: &AccountabilityGrantPayload,
    scope_ref: ScopeRef,
    created_at: DateTime<Utc>,
    authorization: Option<&AppletDelegatedEventAuthorization>,
) -> Result<EventIntent> {
    let principal_server_id = authorization
        .map(|authorization| authorization.executed_by.clone())
        .unwrap_or_else(|| payload.issuer.clone());
    let mut draft = TypedEventDraft::<event_spec::IdentityAccountabilityGrant>::new(
        scope_ref,
        payload.issuer.clone(),
        principal_server_id,
        payload.clone(),
    )?;
    if let Some(authorization) = authorization {
        authorization.validate()?;
        draft = draft
            .with_executed_by(authorization.executed_by.clone())
            .with_authorization_ref(authorization.authorization_ref.clone())
            .with_applet_id(authorization.applet_id.clone());
    }
    draft.into_intent(created_at)
}
