//! Test-only raw projection fixtures.

use arkret_wire::{DidCoreId, EventKind, Hlc, OperationId, OperationKind, RealmId, ScopeRef};
use serde_json::Value;

use crate::ProjectedEventOperation;

/// Build a raw accepted-operation fixture without exposing a production
/// `EventKind + Value` constructor.
pub fn raw_projected_operation(
    operation_id: OperationId,
    realm_id: RealmId,
    kind: impl Into<EventKind>,
    payload: Value,
) -> ProjectedEventOperation {
    let kind = kind.into();
    let fixture = arkret_wire::test_support::split_raw_projection_fixture_payload(payload)
        .expect("raw projection fixture payload is valid");
    let actor = fixture.actor_id.unwrap_or_else(|| {
        DidCoreId::new("ak:did_core:web:fixture.example")
            .expect("fixed fixture actor is a core DID id")
    });
    let event = arkret_wire::test_support::raw_event(
        kind.as_str(),
        ScopeRef::Realm { realm_id },
        actor.clone(),
        actor,
        1,
        Hlc::new("01970e589d21-0000-a13f9c2e").expect("fixed fixture HLC is valid"),
        fixture.payload,
    )
    .expect("raw fixture Event is valid");
    let mut operation = ProjectedEventOperation::from_accepted_event(
        operation_id,
        OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("raw fixture operation is valid");
    if let Some(event_id) = fixture.event_id {
        operation.context.event_id = event_id.clone();
        operation.context.accepted_event_id = event_id;
    }
    operation
}
