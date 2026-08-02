use arkret_wire::events::kinds::{EventWireScope, event_wire_scope};
use arkret_wire::generated::{
    DurableEffectKind, DurableEventTarget, SERVICE_OPERATION_DESCRIPTORS, ServiceOperationId,
};

#[test]
fn every_write_operation_has_a_closed_durable_effect_descriptor() {
    let writes = SERVICE_OPERATION_DESCRIPTORS
        .iter()
        .filter(|row| row.idempotency_mechanism.is_some() || row.retry_safe.is_some())
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 122);

    for operation in writes {
        let effect = operation
            .durable_effect
            .unwrap_or_else(|| panic!("{} omits durable_effect", operation.id));
        match (effect.kind, effect.target) {
            (DurableEffectKind::EventLog, Some(DurableEventTarget::Static(kinds))) => {
                assert!(!kinds.is_empty());
                for kind in kinds {
                    assert_eq!(
                        event_wire_scope(kind),
                        EventWireScope::DurableEvent,
                        "{} references non-durable Event {kind}",
                        operation.id
                    );
                }
            }
            (DurableEffectKind::EventLog, Some(DurableEventTarget::Dynamic(source))) => {
                assert!(!source.is_empty());
            }
            (DurableEffectKind::EventLog, Some(DurableEventTarget::DynamicMany(sources))) => {
                assert!(!sources.is_empty());
                assert!(sources.iter().all(|source| !source.is_empty()));
            }
            (DurableEffectKind::ActorPrivateEvent, Some(DurableEventTarget::Static([kind]))) => {
                assert_eq!(event_wire_scope(kind), EventWireScope::ActorPrivateEvent);
            }
            (DurableEffectKind::None, None) => {
                assert!(effect.rationale.is_some_and(|value| !value.is_empty()));
            }
            other => panic!("{} has malformed durable_effect {other:?}", operation.id),
        }
    }
}

#[test]
fn moderation_report_operation_names_its_durable_event() {
    let effect = ServiceOperationId::SelfModerationCommandReport
        .descriptor()
        .durable_effect
        .unwrap();
    assert_eq!(effect.kind, DurableEffectKind::EventLog);
    assert_eq!(
        effect.target,
        Some(DurableEventTarget::Static(&["ak.self.moderation.report"]))
    );
}
