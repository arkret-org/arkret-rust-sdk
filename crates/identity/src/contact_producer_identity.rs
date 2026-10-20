//! Public native identity checks for the registered Contact source projection.
//!
//! The enclosing carrier must authenticate the expected source service and
//! verify the exact original Event with its source-frozen producer descriptor.
//! Public identity history does not supply a private runtime scope or grant.
use arkret_models_collaboration::contact_operations::{ContactPeer, ContactProducerSigner};
use arkret_wire::{Did, Event, EventId, project_did_to_core_id};

use crate::{IdentityError, Result, VerifiedDidWebvhLog};

fn invalid(detail: impl std::fmt::Display) -> IdentityError {
    IdentityError::Protocol(format!("Contact Agent native identity: {detail}"))
}

/// Select only a source-authenticated locator; never derive a URL from a core.
pub fn agent_contact_identity_did(
    event: &Event,
    holder: &ContactPeer,
    signer: &ContactProducerSigner,
) -> Result<Did> {
    if !matches!(
        event.kind.as_str(),
        arkret_wire::event_kind_str::CONTACT_REQUESTED
            | arkret_wire::event_kind_str::CONTACT_ACCEPTED
            | arkret_wire::event_kind_str::CONTACT_REJECTED
            | arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE
            | arkret_wire::event_kind_str::CONTACT_TOMBSTONE
    ) {
        return Err(invalid(
            "source projection is not registered for this Event kind",
        ));
    }
    signer.validate_for_event(event, holder).map_err(invalid)?;
    let ContactPeer::Agent { actor_id, .. } = holder else {
        return Err(invalid("holder is not an Agent"));
    };
    let did = match signer.delegated_actor_did() {
        Some(did) => did.clone(),
        None => crate::verification_method_did(signer.verification_method().as_str())?,
    };
    if did.method() != "webvh"
        || project_did_to_core_id(&did).map_err(invalid)? != *actor_id.signing_principal_id()
    {
        return Err(invalid("locator does not bind the complete Agent actor"));
    }
    Ok(did)
}

/// Verify the complete native chain, then its create-locked binding at the
/// original Event time. Later identity changes do not erase earlier facts.
/// Resolver trust, egress and required witness policy remain caller obligations.
pub fn validate_agent_contact_native_history(
    event: &Event,
    holder: &ContactPeer,
    signer: &ContactProducerSigner,
    history: &VerifiedDidWebvhLog,
) -> Result<()> {
    let did = agent_contact_identity_did(event, holder, signer)?;
    validate_agent_contact_identity_at(event, holder, &did, history)
}

/// Authenticate historical public identity for pre-admission authoring as well
/// as verified carriers. This does not authenticate an Event's producer or
/// assert that its command was accepted by the source Station.
pub fn validate_agent_contact_identity_at(
    event: &Event,
    holder: &ContactPeer,
    did: &Did,
    history: &VerifiedDidWebvhLog,
) -> Result<()> {
    let ContactPeer::Agent {
        controller_account_id: controller,
        actor_id: actor,
    } = holder
    else {
        return Err(invalid("holder is not an Agent"));
    };
    if actor.as_account_id().is_none()
        || actor != &event.actor_id
        || did.method() != "webvh"
        || project_did_to_core_id(did).map_err(invalid)? != *actor.signing_principal_id()
        || event
            .executed_by
            .as_ref()
            .is_some_and(|executor| executor != &arkret_wire::ActorId::account(controller.clone()))
    {
        return Err(invalid(
            "native identity does not bind the exact Agent actor/controller",
        ));
    }
    let head_did = Did::new(
        history.head_state["id"]
            .as_str()
            .ok_or_else(|| invalid("missing native head DID"))?
            .to_owned(),
    )
    .map_err(invalid)?;
    if project_did_to_core_id(&head_did).map_err(invalid)?
        != project_did_to_core_id(did).map_err(invalid)?
        || actor.fixed_route_service_id() != Some(&controller.station_id)
    {
        return Err(invalid("native head or controller Station differs"));
    }
    let verified = crate::verify_did_webvh_v1_chain(&head_did, &history.raw_entries)?;
    if &verified != history {
        return Err(invalid("verified chain differs from supplied snapshot"));
    }
    // The shared historical selector also checks monotonic times and deactivation.
    let point = arkret_signatures::webvh::validate_webvh_history_at(
        did,
        &history.raw_entries,
        event.created_at,
    )
    .map_err(invalid)?;
    arkret_signatures::webvh::validate_agent_did_document_profile(
        did.as_str(),
        &point.document,
        &[],
    )
    .map_err(invalid)?;
    // The complete native chain was authenticated above. Later binding changes
    // affect new authorization, not the historical identity of this Event.
    // Exact eligibility at command confirmation is the independently signed
    // source projection's responsibility; created_at is not live authority.
    let historical_end = history
        .raw_entries
        .iter()
        .position(|entry| {
            entry.get("versionId").and_then(serde_json::Value::as_str)
                == Some(point.version_id.as_str())
        })
        .ok_or_else(|| invalid("verified Agent history point is absent from its chain"))?;
    let historical_entries = &history.raw_entries[..=historical_end];
    let inception_delegation = historical_entries[0].pointer("/state/service/1");
    let initial_binding = historical_entries
        .get(1)
        .and_then(|e| e.pointer("/state/service/2/serviceEndpoint"));
    if historical_entries[0].pointer("/state/service/2").is_some() || initial_binding.is_none() {
        return Err(invalid("Agent binding must first appear in entry one"));
    }
    for (index, entry) in historical_entries.iter().enumerate() {
        let document = entry
            .get("state")
            .ok_or_else(|| invalid("Agent history entry has no document"))?;
        arkret_signatures::webvh::validate_agent_did_document_profile(did.as_str(), document, &[])
            .map_err(invalid)?;
        if entry.pointer("/state/service/1") != inception_delegation
            || (index > 0 && entry.pointer("/state/service/2/serviceEndpoint") != initial_binding)
        {
            return Err(invalid(
                "Agent history rewrites its create-locked delegation or PCR tuple",
            ));
        }
    }
    let services = point
        .document
        .get("service")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("verified Agent document has no services"))?;
    let binding = services
        .get(2)
        .and_then(|s| s.get("serviceEndpoint"))
        .ok_or_else(|| invalid("Agent PCR binding is absent at publication"))?;
    if binding.get("realm_id").and_then(serde_json::Value::as_str) != Some(event.realm_id.as_str())
        || binding
            .get("controller_did")
            .and_then(serde_json::Value::as_str)
            != Some(controller.principal_id.as_str())
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid(
            "Contact management exceeds the accepted Agent PCR delegation",
        ));
    }
    if event.executed_by.is_some() {
        let reference = event
            .authorization_ref
            .as_ref()
            .ok_or_else(|| invalid("controller Contact Event omits its authorization source"))?;
        if arkret_wire::DidUrl::new(reference.as_str()).is_ok()
            && binding
                .get("authorization_ref")
                .and_then(serde_json::Value::as_str)
                != Some(reference.as_str())
        {
            return Err(invalid(
                "controller DID delegation differs from the locked Agent binding",
            ));
        }
        if arkret_wire::DidUrl::new(reference.as_str()).is_err()
            && arkret_wire::GrantId::new(reference.as_str()).is_err()
            && EventId::new(reference.as_str()).is_err()
        {
            return Err(invalid(
                "controller authorization is not the accepted delegation or a materialized grant",
            ));
        }
    }
    // Source confirmation attests the exact command's internal authorization.
    // Private key/grant/scope histories do not cross this Contact boundary.
    Ok(())
}
