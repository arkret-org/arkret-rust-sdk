//! Installation-bound origin validation, independent of current liveness.

use arkret_models_collaboration::applet_installation_authority::AppletInstallationAuthority;
use arkret_models_collaboration::events_payloads::CapabilityGrantPayload;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_integration::AppletRegistrationPayload;
use arkret_wire::{
    ActorId, DidCoreId, Event, GrantId, ResourceMatchScope, Result, ScopeRef, WireError,
    WireResourceSelector,
};

/// Authenticate the frozen authority Events with the caller's historical
/// verifier, then derive the only permitted admission Station. No Station ID
/// supplied by the caller participates in this derivation.
pub fn verify_applet_installation_authority<F>(
    event: &Event,
    authority: &AppletInstallationAuthority,
    mut verify_accepted: F,
) -> Result<DidCoreId>
where
    F: FnMut(&Event) -> Result<()>,
{
    authority.validate_structural()?;
    for dependency in [
        &authority.registration_event,
        &authority.capability_grant_event,
    ] {
        verify_accepted(dependency)?;
    }
    validate_applet_installation_coordinates(event, authority)
}

/// Coordinate validation for evidence whose accepted signatures have already
/// been authenticated. This does not check current revocation or Realm policy.
pub fn validate_applet_installation_coordinates(
    event: &Event,
    authority: &AppletInstallationAuthority,
) -> Result<DidCoreId> {
    authority.validate_structural()?;
    let registration_event = &authority.registration_event;
    let grant_event = &authority.capability_grant_event;
    let registration: AppletRegistrationPayload =
        serde_json::from_value(serde_json::to_value(&registration_event.payload)?)?;
    let payload: CapabilityGrantPayload =
        serde_json::from_value(serde_json::to_value(&grant_event.payload)?)?;
    let grant = payload.grant;
    let service = ActorId::service(registration.service_id.clone());
    let producer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    let target = registration_event.actor_id.route_service_id();
    let fail = || WireError::Protocol("Applet installation authority binding mismatch".to_owned());
    let resource = match &event.scope_ref {
        ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            let mut resource = WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
            resource.match_scope = Some(ResourceMatchScope::Exact);
            resource
        }
        _ => return Err(fail()),
    };
    let bindings = grant
        .constraints
        .iter()
        .filter(|constraint| {
            constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return Err(fail());
    };
    let CapabilitySubject::Actor(grant_executor) = &grant.subject else {
        return Err(fail());
    };
    if event.applet_id.as_ref() != Some(&registration.applet_id)
        || event.scope_ref != registration_event.scope_ref
        || event.realm_id != registration_event.realm_id
        || event.authorization_ref.as_deref()
            != Some(GrantId::from_event_id(&grant_event.event_id).as_str())
        || grant.issuer_id != grant_event.actor_id
        || grant.realm_id.as_ref() != Some(&event.realm_id)
        || !grant
            .actions
            .iter()
            .any(|action| action == event.kind.as_str())
        || grant.resources.as_slice() != [resource]
        || binding.constraint_kind != GrantConstraintKind::AuthorityControl
        || binding.effect != GrantConstraintEffect::Allow
        || binding.applet_id.as_ref() != Some(&registration.applet_id)
        || binding.registration_epoch.as_ref() != Some(&registration.registration_epoch)
        || binding.executed_by.as_ref() != Some(grant_executor)
        || grant_executor != producer
        || (producer != &service
            && (!matches!(producer, ActorId::Account { .. })
                || producer.route_service_id() != target))
        || (matches!(&event.actor_id, ActorId::Account { .. })
            && event.actor_id.route_service_id() != target)
        || registration.bot_actor_id.route_service_id() != target
    {
        return Err(fail());
    }
    let [producer_proof] = event.proofs.as_slice() else {
        return Err(fail());
    };
    if producer == &service
        && !registration
            .manifest
            .registration_epoch_evidence
            .contains_signing_key(producer_proof.verification_method.as_str())
    {
        return Err(fail());
    }
    Ok(target.clone())
}
