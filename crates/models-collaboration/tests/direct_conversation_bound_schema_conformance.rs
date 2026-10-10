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
    let vector = binding_vector();
    let mut payload = vector["input"].clone();
    payload["created_at"] = "2026-09-21T00:00:00.000Z".into();
    payload
}

fn binding_vector() -> Value {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/encoding-fixture.json")).unwrap(),
    )
    .unwrap();
    fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["vector_id"] == "ak.vector.direct_conversation.binding_digest.v1")
        .unwrap()
        .clone()
}

#[test]
fn binding_digest_matches_domain_separated_canonical_vector() {
    let vector = binding_vector();
    let payload: DirectConversationBoundPayload =
        serde_json::from_value(fixture_payload()).unwrap();
    let canonical = payload.binding_object_canonical_bytes().unwrap();
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        vector["expected_canonical_bytes_utf8"].as_str().unwrap()
    );
    let mut preimage = vector["domain_separator_utf8"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    preimage.extend_from_slice(&canonical);
    let preimage_hex: String = preimage.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(preimage_hex, vector["digest_input_hex"].as_str().unwrap());
    assert_eq!(
        payload.binding_digest().unwrap().as_str(),
        vector["expected_digest"].as_str().unwrap()
    );

    for case in vector["normalization_cases"].as_array().unwrap() {
        let normalized: DirectConversationBoundPayload =
            serde_json::from_value(case["payload"].clone()).unwrap();
        assert_eq!(
            normalized.binding_digest().unwrap().as_str(),
            case["expected_digest"].as_str().unwrap()
        );
    }
    for case in vector["mutation_cases"].as_array().unwrap() {
        if let Some(input) = case.get("input") {
            let mut payload = input.clone();
            payload["created_at"] = "2026-09-21T00:00:00.000Z".into();
            let changed: DirectConversationBoundPayload = serde_json::from_value(payload).unwrap();
            assert_eq!(
                changed.binding_digest().unwrap().as_str(),
                case["expected_digest"].as_str().unwrap()
            );
            assert_ne!(
                changed.binding_digest().unwrap(),
                payload_binding_digest(&vector)
            );
        }
    }
}

fn payload_binding_digest(vector: &Value) -> arkret_wire::Hash {
    let mut payload = vector["input"].clone();
    payload["created_at"] = "2026-09-21T00:00:00.000Z".into();
    let payload: DirectConversationBoundPayload = serde_json::from_value(payload).unwrap();
    payload.binding_digest().unwrap()
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
fn binding_current_value_is_an_add_only_dot_set_of_one_digest() {
    use arkret_models_collaboration::events_payloads::{
        DirectConversationBindingCurrentValue, DirectConversationBindingEndorsementEntry,
    };
    use arkret_models_collaboration::exact_current_results::CanonicalEventDot;

    let payload: DirectConversationBoundPayload =
        serde_json::from_value(fixture_payload()).unwrap();
    let dot = |seed: &str| {
        CanonicalEventDot::new(
            arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                arkret_canonical::sha256_bytes(seed.as_bytes()),
            ),
            0,
        )
        .unwrap()
    };
    let first = DirectConversationBindingEndorsementEntry {
        tag_id: dot("first"),
        value: payload.clone(),
    };
    let value = DirectConversationBindingCurrentValue {
        endorsements: vec![first.clone()],
    };
    let mut later = payload.clone();
    later.created_at += chrono::Duration::seconds(1);
    let value = value
        .with_endorsement(DirectConversationBindingEndorsementEntry {
            tag_id: dot("second"),
            value: later,
        })
        .unwrap();
    assert_eq!(value.endorsements.len(), 2);
    assert!(value.endorsements[0].tag_id.to_string() < value.endorsements[1].tag_id.to_string());
    assert_eq!(
        value.binding_digest().unwrap(),
        payload.binding_digest().unwrap()
    );
    assert!(value.endorsed_by(first.tag_id.event_id()));
    binding_value_registry()
        .validate_value(
            "test:direct-conversation-binding-value",
            &serde_json::to_value(&value).unwrap(),
        )
        .unwrap();

    assert!(value.clone().with_endorsement(first).is_err());
    let mut other = payload;
    other.pair_key = arkret_wire::Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap();
    assert!(
        value
            .with_endorsement(DirectConversationBindingEndorsementEntry {
                tag_id: dot("third"),
                value: other,
            })
            .is_err()
    );
}
