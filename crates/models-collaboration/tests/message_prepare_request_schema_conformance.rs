//! Optional message prepare requests stay aligned with the canonical schema.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::message_authoring::MessagePrepareRequestBody;
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

const FILE: &str = "message-authoring.schema.json";
const FRAGMENT: &str = "#/$defs/message_prepare_request_body";

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
        .register_fragment("test:message-prepare-request", schema, FRAGMENT)
        .expect("message prepare request fragment must register");
    registry
}

fn request() -> Value {
    json!({
        "request_id": "ak:request:019b6a40-0000-7000-8000-000000000001",
        "account_id": {
            "principal_id": "ak:did_core:webvh:z6mkauthor",
            "station_id": "ak:did_core:webvh:z6mkstation"
        },
        "realm_id": "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
        "intent": {
            "strand_id": "ak:strand:AUOjN8M8xm-W1G1Ve9UR6sHKJh7JPG7bM8ZDnzcGJ2Vh",
            "track_name": "discussion",
            "content": {
                "kind": "plaintext",
                "content": {
                    "kind": "ak.content.text",
                    "body": "hello",
                    "format": "plain"
                }
            }
        },
        "created_at": "2026-09-16T00:00:00.000Z"
    })
}

#[test]
fn request_round_trips_and_validates_against_the_formal_fragment() {
    let value = request();
    registry()
        .validate_value("test:message-prepare-request", &value)
        .expect("canonical request must validate against the formal fragment");
    let parsed: MessagePrepareRequestBody =
        serde_json::from_value(value.clone()).expect("SDK must accept the canonical request");
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

#[test]
fn schema_and_sdk_both_reject_missing_and_unknown_members() {
    for member in [
        "request_id",
        "account_id",
        "realm_id",
        "intent",
        "created_at",
    ] {
        let mut missing = request();
        missing.as_object_mut().unwrap().remove(member);
        assert!(
            registry()
                .validate_value("test:message-prepare-request", &missing)
                .is_err(),
            "schema must reject missing {member}"
        );
        assert!(serde_json::from_value::<MessagePrepareRequestBody>(missing).is_err());
    }

    let mut unknown = request();
    unknown["reservation_handle"] = json!("forbidden");
    assert!(
        registry()
            .validate_value("test:message-prepare-request", &unknown)
            .is_err()
    );
    assert!(serde_json::from_value::<MessagePrepareRequestBody>(unknown).is_err());
}
