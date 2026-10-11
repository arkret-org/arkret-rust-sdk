//! Current Event service DTOs stay bound to the published operation schemas.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::event_query::{
    CommittedEventView, EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody,
};
use arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrame;
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{AuthoritySubmitRequest, StreamScanRequest};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn schema_value(file: &str) -> Value {
    let path = artifacts_dir().join("schemas").join(file);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text).expect("schema artifact must be valid JSON")
}

fn registry() -> ProtocolSchemaRegistry {
    schema_registry_from_spec_artifacts(artifacts_dir())
        .expect("the spec artifacts must produce a schema registry")
}

fn validate_fragment(file: &str, fragment: &str, value: &Value) {
    let mut registry = registry();
    let schema = schema_value(file);
    registry
        .register_reference_document(schema.clone())
        .expect("schema document declares an absolute $id");
    let schema_id = format!("test:{file}{}", fragment.replace('#', "@"));
    registry
        .register_fragment(schema_id.clone(), schema, fragment)
        .unwrap_or_else(|error| panic!("{file}{fragment}: {error}"));
    registry
        .validate_value(&schema_id, value)
        .unwrap_or_else(|error| panic!("{file}{fragment} rejected the document: {error}"));
}

fn assert_schema_and_serde<T>(file: &str, fragment: &str, value: Value)
where
    T: DeserializeOwned + serde::Serialize,
{
    validate_fragment(file, fragment, &value);
    let parsed: T = serde_json::from_value(value.clone()).expect("SDK must accept schema value");
    assert_eq!(
        serde_json::to_value(parsed).expect("SDK value serializes"),
        value
    );
}

#[test]
fn delivery_status_dtos_match_the_published_closed_fragments() {
    const FILE: &str = "service-operation-dtos.schema.json";
    const EVENT: &str = "ak:event:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";

    assert_schema_and_serde::<EventDeliveryStatusRequestBody>(
        FILE,
        "#/$defs/EventDeliveryStatusRequestBody",
        json!({"event_id": EVENT}),
    );
    assert_schema_and_serde::<EventDeliveryStatusOutcome>(
        FILE,
        "#/$defs/EventDeliveryStatusOutcome",
        json!({
            "event_id": EVENT,
            "targets": [
                {
                    "target_id": "A_frozen_target_0001",
                    "status": "delivered",
                    "service_id": "ak:did_core:web:station.example"
                },
                {
                    "target_id": "B_frozen_target_0002",
                    "status": "pending_delivery"
                }
            ]
        }),
    );
}

#[test]
fn resource_get_and_subscribe_stay_on_the_current_models() {
    assert!(serde_json::from_value::<CommittedEventView>(json!({})).is_err());
    assert_schema_and_serde::<CommittedEventSubscribeFrame>(
        "committed-event-subscribe-frame.schema.json",
        "#",
        json!({"kind": "heartbeat"}),
    );
}

#[test]
fn submit_and_peer_read_operations_use_the_current_authority_commit_types() {
    fn assert_closed_empty<T: DeserializeOwned>() {
        assert!(serde_json::from_value::<T>(json!({})).is_err());
    }

    assert_closed_empty::<AuthoritySubmitRequest>();
    assert_closed_empty::<StreamScanRequest>();
}
