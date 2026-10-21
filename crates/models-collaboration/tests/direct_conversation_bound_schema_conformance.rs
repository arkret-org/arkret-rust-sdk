//! The single accepted binding preserves its original participant Event.

use std::fs;

use arkret_models_collaboration::events_payloads::DirectConversationBoundPayload;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::Value;

fn registry() -> arkret_schema::ProtocolSchemaRegistry {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/event-payload.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            "test:direct-conversation-bound",
            schema,
            "#/$defs/direct_conversation_bound_payload",
        )
        .unwrap();
    registry
}

fn fixture_payload() -> Value {
    use arkret_wire::{AccountId, ActorId, DidCoreId, EventId};
    let event = |seed| EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]);
    let station: DidCoreId = "ak:did_core:web:station.example".parse().unwrap();
    let actor = |name: &str| {
        ActorId::account(AccountId::new(
            format!("ak:did_core:web:{name}.example").parse().unwrap(),
            station.clone(),
        ))
    };
    serde_json::json!({
        "pair_key": format!("sha256:{}", "12".repeat(32)),
        "unordered_participant_ids": [actor("alice"),actor("bob")],
        "realm_id": arkret_wire::RealmId::from_event_id(&event(1)),
        "main_strand_id": arkret_wire::StrandId::from_event_id(&event(2)),
        "founding_unit_digest":format!("sha256:{}", "34".repeat(32)),
        "authorization_basis":{"kind":"accepted_contact","event_refs":[event(3),event(4)]},
        "initial_exact_pair_group_state_ref":event(5),
        "created_at":"2026-10-21T00:00:00.000Z"
    })
}

#[test]
fn bound_payload_matches_formal_schema_and_rejects_derived_digest_on_wire() {
    let registry = registry();
    let payload = fixture_payload();
    registry
        .validate_value("test:direct-conversation-bound", &payload)
        .unwrap();
    let typed: DirectConversationBoundPayload = serde_json::from_value(payload.clone()).unwrap();
    typed.validate_shape().unwrap();
    assert_eq!(serde_json::to_value(typed).unwrap(), payload);

    let mut with_derived_digest = payload;
    with_derived_digest["binding_digest"] =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
    assert!(
        registry
            .validate_value("test:direct-conversation-bound", &with_derived_digest)
            .is_err()
    );
    assert!(serde_json::from_value::<DirectConversationBoundPayload>(with_derived_digest).is_err());
}

#[test]
fn bound_payload_required_fields_and_exact_pair_fail_closed() {
    let registry = registry();
    for field in [
        "pair_key",
        "unordered_participant_ids",
        "realm_id",
        "main_strand_id",
        "founding_unit_digest",
        "authorization_basis",
        "initial_exact_pair_group_state_ref",
        "created_at",
    ] {
        let mut missing = fixture_payload();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            registry
                .validate_value("test:direct-conversation-bound", &missing)
                .is_err(),
            "schema accepted missing {field}"
        );
        assert!(serde_json::from_value::<DirectConversationBoundPayload>(missing).is_err());
    }
    let mut duplicate = fixture_payload();
    duplicate["unordered_participant_ids"][1] = duplicate["unordered_participant_ids"][0].clone();
    assert!(
        registry
            .validate_value("test:direct-conversation-bound", &duplicate)
            .is_err()
    );
    let typed: DirectConversationBoundPayload = serde_json::from_value(duplicate).unwrap();
    assert!(typed.validate_shape().is_err());
}

fn binding_value_registry() -> arkret_schema::ProtocolSchemaRegistry {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    for document in [
        "event-payload.schema.json",
        "typed-current-result.schema.json",
    ] {
        let schema: Value =
            serde_json::from_slice(&fs::read(artifacts.join("schemas").join(document)).unwrap())
                .unwrap();
        registry.register_reference_document(schema).unwrap();
    }
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/typed-current-result.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_fragment(
            "test:direct-conversation-binding-value",
            schema,
            "#/$defs/direct_conversation_binding_value",
        )
        .unwrap();
    registry
}

#[test]
fn binding_current_value_contains_one_original_event_and_rejects_endorsement_sets() {
    use arkret_models_collaboration::events_payloads::DirectConversationBindingCurrentValue;
    use serde_json::json;
    let event = arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [8; 32]);
    let value = json!({"binding_event_ref":event,"binding":fixture_payload()});
    let registry = binding_value_registry();
    registry
        .validate_value("test:direct-conversation-binding-value", &value)
        .unwrap();
    let parsed: DirectConversationBindingCurrentValue =
        serde_json::from_value(value.clone()).unwrap();
    parsed.validate_shape().unwrap();
    assert_eq!(parsed.binding_event_ref, event);
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    for legacy in [
        json!({"endorsements":[]}),
        json!({"binding_event_ref":event,"binding":fixture_payload(),"endorsements":[]}),
    ] {
        assert!(
            registry
                .validate_value("test:direct-conversation-binding-value", &legacy)
                .is_err()
        );
        assert!(serde_json::from_value::<DirectConversationBindingCurrentValue>(legacy).is_err());
    }
}
