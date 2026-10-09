//! Agent lifecycle operations return exactly the registered status-only shape.

use std::fs;

use arkret_models_collaboration::agent_operations::AgentLifecycleOutcome;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/agent-operations.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            "test:agent-lifecycle-outcome".to_owned(),
            schema,
            "#/$defs/agent_lifecycle_state".to_owned(),
        )
        .unwrap();
    registry
        .validate_value("test:agent-lifecycle-outcome", value)
        .is_ok()
}

#[test]
fn all_lifecycle_statuses_roundtrip_against_the_closed_schema() {
    for status in ["active", "paused", "deactivated"] {
        let value = json!({"status": status});
        assert!(schema_accepts(&value), "schema rejected {status}");
        let outcome: AgentLifecycleOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(outcome).unwrap(), value);
    }
}

#[test]
fn lifecycle_ref_is_not_an_operation_response_field() {
    let value = json!({
        "status": "deactivated",
        "lifecycle_ref": {
            "event_id": "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "commit_id": "ak:realm_commit:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "stream_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "stream_position": 1
        }
    });
    assert!(!schema_accepts(&value));
    assert!(serde_json::from_value::<AgentLifecycleOutcome>(value).is_err());
}

#[test]
fn missing_status_and_unknown_lifecycle_words_fail_closed() {
    for value in [
        json!({}),
        json!({"status": null}),
        json!({"status": "accepted"}),
        json!({"status": "ready"}),
    ] {
        assert!(!schema_accepts(&value), "schema accepted {value}");
        assert!(serde_json::from_value::<AgentLifecycleOutcome>(value.clone()).is_err());
    }
}
