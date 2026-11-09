//! Local message authoring intent stays aligned with the canonical schema.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::message_authoring::MessageAuthoringIntent;
use arkret_models_crypto::ContentEndpoint;
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{Event, EventId};
use serde_json::{Value, json};

const FILE: &str = "message-authoring.schema.json";
const FRAGMENT: &str = "#/$defs/message_authoring_intent";

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn registry() -> ProtocolSchemaRegistry {
    let artifacts = artifacts_dir();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts)
        .expect("the spec artifacts must produce a schema registry");
    let path = artifacts.join("schemas").join(FILE);
    let schema: Value = serde_json::from_slice(
        &fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .expect("message authoring schema must be JSON");
    registry
        .register_reference_document(schema.clone())
        .expect("message authoring schema must have an absolute id");
    registry
        .register_fragment("test:message-authoring-intent", schema, FRAGMENT)
        .expect("message prepare request fragment must register");
    registry
}

fn request() -> Value {
    json!({
        "strand_id":"ak:strand:AUOjN8M8xm-W1G1Ve9UR6sHKJh7JPG7bM8ZDnzcGJ2Vh",
        "track_name":"discussion",
        "content":{"kind":"plaintext","content":{"kind":"ak.content.text","body":"hello","format":"plain"}}
    })
}

#[test]
fn request_round_trips_and_validates_against_the_formal_fragment() {
    let value = request();
    registry()
        .validate_value("test:message-authoring-intent", &value)
        .expect("canonical request must validate against the formal fragment");
    let parsed: MessageAuthoringIntent =
        serde_json::from_value(value.clone()).expect("SDK must accept the canonical request");
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

#[test]
fn schema_and_sdk_both_reject_missing_and_unknown_members() {
    for member in ["strand_id", "track_name", "content"] {
        let mut missing = request();
        missing.as_object_mut().unwrap().remove(member);
        assert!(
            registry()
                .validate_value("test:message-authoring-intent", &missing)
                .is_err(),
            "schema must reject missing {member}"
        );
        assert!(serde_json::from_value::<MessageAuthoringIntent>(missing).is_err());
    }

    let mut unknown = request();
    unknown["reservation_handle"] = json!("forbidden");
    assert!(
        registry()
            .validate_value("test:message-authoring-intent", &unknown)
            .is_err()
    );
    assert!(serde_json::from_value::<MessageAuthoringIntent>(unknown).is_err());
}

fn encrypted_fixture() -> Value {
    arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json").unwrap()
}

// A primitive fixture Event, not native admission or current producer authority.
fn original_event(fixture: &Value, intent: &MessageAuthoringIntent) -> Event {
    let mut value = fixture["kat"]["outer_event"].clone();
    value["event_id"] = json!(EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [9; 32]
    ));
    value["payload"] = serde_json::to_value(intent.payload()).unwrap();
    serde_json::from_value(value).unwrap()
}

#[test]
fn frozen_encrypted_carrier_matches_independent_formal_outer_and_endpoint() {
    let fixture = encrypted_fixture();
    let value = fixture["local_message_authoring"].clone();
    registry()
        .validate_value("test:message-authoring-intent", &value)
        .unwrap();
    let intent: MessageAuthoringIntent = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&intent).unwrap(), value);
    let producer: ContentEndpoint =
        serde_json::from_value(fixture["kat"]["content_context"]["producer"].clone()).unwrap();
    intent
        .validate_encryption_binding(&original_event(&fixture, &intent), &producer)
        .unwrap();
}

#[test]
fn current_encrypted_carrier_requires_closed_endpoint_and_outer_digest() {
    let fixture = encrypted_fixture();
    let registry = registry();
    for field in ["producer", "outer_event_digest"] {
        for missing in [true, false] {
            let mut value = fixture["local_message_authoring"].clone();
            let context = value["content"]["encryption_context"]
                .as_object_mut()
                .unwrap();
            if missing {
                context.remove(field);
            } else {
                context.insert(field.to_owned(), Value::Null);
            }
            assert!(
                registry
                    .validate_value("test:message-authoring-intent", &value)
                    .is_err()
            );
            assert!(serde_json::from_value::<MessageAuthoringIntent>(value).is_err());
        }
    }
    for scheme in [
        Value::Null,
        json!("mls_rfc9420"),
        json!("ak.encryption.unknown.v1"),
    ] {
        let mut value = fixture["local_message_authoring"].clone();
        value["content"]["encryption_context"]["scheme"] = scheme;
        assert!(
            registry
                .validate_value("test:message-authoring-intent", &value)
                .is_err()
        );
        assert!(serde_json::from_value::<MessageAuthoringIntent>(value).is_err());
    }
    let mut value = fixture["local_message_authoring"].clone();
    value["content"]["encryption_context"]["native_authorized"] = json!(true);
    assert!(
        registry
            .validate_value("test:message-authoring-intent", &value)
            .is_err()
    );
    assert!(serde_json::from_value::<MessageAuthoringIntent>(value).is_err());
}

#[test]
fn changed_original_or_actual_endpoint_cannot_rebind_a_sealed_message() {
    let fixture = encrypted_fixture();
    let intent: MessageAuthoringIntent =
        serde_json::from_value(fixture["local_message_authoring"].clone()).unwrap();
    let producer: ContentEndpoint =
        serde_json::from_value(fixture["kat"]["content_context"]["producer"].clone()).unwrap();
    let event = original_event(&fixture, &intent);
    let mut changed = event.clone();
    changed.created_at += chrono::Duration::milliseconds(1);
    assert!(
        intent
            .validate_encryption_binding(&changed, &producer)
            .is_err()
    );
    let mut changed_producer = producer.clone();
    changed_producer.authorization_event_ref =
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [8; 32]);
    assert!(
        intent
            .validate_encryption_binding(&event, &changed_producer)
            .is_err()
    );
    let mut changed = event;
    changed
        .payload
        .insert("reply_to_id".to_owned(), json!("changed-local-intent"));
    assert!(
        intent
            .validate_encryption_binding(&changed, &producer)
            .is_err()
    );
    let mut value = fixture["local_message_authoring"].clone();
    let sender = value["content"]["encryption_context"]["sender_domain"]
        .as_str()
        .unwrap();
    value["content"]["encryption_context"]["sender_domain"] = json!(format!(" {sender}"));
    let changed_intent: MessageAuthoringIntent = serde_json::from_value(value).unwrap();
    assert!(
        changed_intent
            .validate_encryption_binding(&original_event(&fixture, &changed_intent), &producer)
            .is_err()
    );
}

#[test]
fn sealed_slots_reject_mixed_original_roots_and_reused_key_domain() {
    let fixture = encrypted_fixture();
    let producer: ContentEndpoint =
        serde_json::from_value(fixture["kat"]["content_context"]["producer"].clone()).unwrap();
    for field in ["epoch", "group_state_ref", "root_ref", "content_key_salt"] {
        let mut value = fixture["local_message_authoring"].clone();
        let replacement = match field {
            "epoch" => json!("13"),
            "group_state_ref" => json!(EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [8; 32]
            )),
            "root_ref" => json!(format!("sha256:{}", "0".repeat(64))),
            _ => value["content"]["encrypted_content"]["encryption_context"][field].clone(),
        };
        value["content"]["encrypted_metadata"]["encryption_context"][field] = replacement.clone();
        if field == "root_ref" {
            value["content"]["encrypted_metadata"]["encryption_context"]["protection"]["root_refs"] =
                json!([replacement]);
        }
        let intent: MessageAuthoringIntent = serde_json::from_value(value).unwrap();
        assert!(
            intent
                .validate_encryption_binding(&original_event(&fixture, &intent), &producer)
                .is_err(),
            "{field}"
        );
    }
}
