//! The participant endorsement remains a closed Event payload, not a service receipt.

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
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/encoding-fixture.json")).unwrap(),
    )
    .unwrap();
    let vector = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["vector_id"] == "ak.vector.direct_conversation.binding_digest.v1")
        .unwrap();
    let mut payload = vector["input"].clone();
    payload["created_at"] = "2026-09-21T00:00:00.000Z".into();
    payload
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
