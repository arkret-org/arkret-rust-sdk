//! Realm genesis and governance-Station change helpers.
//!
//! Realm creation is one producer-signed `ak.realm.create` Event. Its
//! immutable genesis payload names the initial governance Station and initial
//! policy. Stream position, predecessor binding, and admission are supplied
//! only by the governance Station's [`arkret_wire::RealmCommit`].

use arkret_event_draft::{EventIntent, EventPayloadExt, TypedEventDraft};
use arkret_models_collaboration::events_payloads::{
    RealmCreatePayload, RealmGovernanceStationChangePayload, RealmOwnerTransferPayload,
};
use arkret_wire::{ActorId, Event, EventKind, RealmId, Result, ScopeRef, WireError, event_spec};
use chrono::{DateTime, Utc};

/// Validated immutable facts extracted from the Realm genesis Event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRealmGenesis {
    pub realm_id: RealmId,
    pub creator_actor_id: ActorId,
    pub governance_station_id: arkret_wire::DidCoreId,
}

/// Validate the sole Event accepted at position zero of a Realm stream.
///
/// The caller still verifies the producer proof and the enclosing
/// [`arkret_wire::RealmCommit`]. This function deliberately performs no
/// ordering or predecessor work: those are properties of the commit stream,
/// not of the producer Event.
pub fn validate_realm_genesis_event(
    event: &Event,
) -> std::result::Result<ValidatedRealmGenesis, WireError> {
    let expected_scope = ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if event.kind != EventKind::RealmCreate || event.scope_ref != expected_scope {
        return Err(WireError::Protocol(
            "realm genesis must be a Realm-scoped ak.realm.create Event".to_owned(),
        ));
    }

    let payload: RealmCreatePayload = event.typed_payload::<event_spec::RealmCreate>()?;
    payload.object.validate()?;
    Ok(ValidatedRealmGenesis {
        realm_id: event.realm_id.clone(),
        creator_actor_id: event.actor_id.clone(),
        governance_station_id: payload.object.governance_station_id,
    })
}

/// Draft a Realm owner transfer Event.
///
/// Authorization is evaluated by the current governance Station against the
/// current committed Realm projection; the producer Event carries no state
/// predecessor or embedded projection authorization reference.
pub fn build_realm_owner_transfer_intent(
    scope_ref: ScopeRef,
    actor_id: ActorId,
    created_at: DateTime<Utc>,
    payload: RealmOwnerTransferPayload,
) -> Result<EventIntent> {
    if scope_ref.realm_id() != &payload.realm_id
        || !payload
            .expected_state_digest
            .as_str()
            .starts_with("sha256:")
    {
        return Err(WireError::Protocol(
            "schema_violation: invalid Realm owner transfer payload".to_owned(),
        ));
    }
    let acceptance = serde_json::to_value(&payload.successor_acceptance)?;
    if match acceptance {
        serde_json::Value::String(value) => value.is_empty(),
        serde_json::Value::Object(value) => value.is_empty(),
        _ => true,
    } {
        return Err(WireError::Protocol(
            "schema_violation: successor_acceptance must be non-empty".to_owned(),
        ));
    }
    TypedEventDraft::<event_spec::RealmOwnerTransfer>::new(scope_ref, actor_id, payload)
        .map_err(|error| WireError::Protocol(error.to_string()))?
        .into_intent(created_at)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

/// Draft the Realm-stream Event that authorizes a planned governance-Station
/// handoff. The expected generation and Realm-stream head prevent a stale
/// administrator decision from changing the authority route.
pub fn build_governance_station_change_intent(
    scope_ref: ScopeRef,
    actor_id: ActorId,
    created_at: DateTime<Utc>,
    payload: RealmGovernanceStationChangePayload,
) -> Result<EventIntent> {
    if !matches!(scope_ref, ScopeRef::Realm { .. })
        || payload.expected_governance_generation == u64::MAX
    {
        return Err(WireError::Protocol(
            "schema_violation: invalid governance Station change payload".to_owned(),
        ));
    }
    TypedEventDraft::<event_spec::RealmGovernanceStationChange>::new(scope_ref, actor_id, payload)
        .map_err(|error| WireError::Protocol(error.to_string()))?
        .into_intent(created_at)
        .map_err(|error| WireError::Protocol(error.to_string()))
}
