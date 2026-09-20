//! The exact watch read must preserve never-written versus written-null.

use std::fs;

use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody, StrandWatchCurrentValue,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const STRAND: &str = "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const COMMIT: &str = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";

fn actor() -> Value {
    json!({
        "kind": "account",
        "account_id": {
            "principal_id": "ak:did_core:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey",
            "station_id": "ak:did_core:web:station.example"
        }
    })
}

fn request() -> Value {
    json!({"realm_id": REALM, "strand_id": STRAND, "watcher_actor_id": actor()})
}

fn selector() -> Value {
    json!({"kind": "strand_watch", "strand_id": STRAND, "watcher_actor_id": actor()})
}

fn head() -> Value {
    json!({
        "stream_ref": {"kind": "realm", "realm_id": REALM},
        "stream_position": 12,
        "commit_id": COMMIT
    })
}

fn never_written() -> Value {
    json!({
        "status": "never_written", "realm_id": REALM,
        "governance_generation": 2, "stream_head": head(), "selector": selector()
    })
}

fn current(value: Value) -> Value {
    json!({
        "status": "current", "realm_id": REALM,
        "governance_generation": 2, "stream_head": head(),
        "result": {
            "selector": selector(),
            "revision": {"commit_id": COMMIT, "stream_position": 12},
            "value": value
        }
    })
}

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/service-operation-dtos.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let id = format!("test:strand-watch-{}", fragment.replace('#', "@"));
    registry
        .register_fragment(id.clone(), schema, fragment)
        .unwrap();
    registry.validate_value(&id, value).is_ok()
}

#[test]
fn exact_request_matches_formal_closed_schema() {
    let value = request();
    assert!(schema_accepts(
        "#/$defs/StrandWatchCurrentRequestBody",
        &value
    ));
    let parsed: StrandWatchCurrentRequestBody = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);

    let mut invalid = value;
    invalid["expected_value"] = Value::Null;
    assert!(!schema_accepts(
        "#/$defs/StrandWatchCurrentRequestBody",
        &invalid
    ));
    assert!(serde_json::from_value::<StrandWatchCurrentRequestBody>(invalid).is_err());
}

#[test]
fn never_written_and_written_clear_remain_distinct() {
    let request: StrandWatchCurrentRequestBody = serde_json::from_value(request()).unwrap();
    for value in [
        never_written(),
        current(Value::Null),
        current(json!({"level":"all", "level_public":true})),
    ] {
        assert!(schema_accepts("#/$defs/StrandWatchCurrentOutcome", &value));
        let parsed: StrandWatchCurrentOutcome = serde_json::from_value(value.clone()).unwrap();
        parsed.validate_for_request(&request).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    }
    assert!(matches!(
        serde_json::from_value::<StrandWatchCurrentOutcome>(current(Value::Null)).unwrap(),
        StrandWatchCurrentOutcome::Current { result, .. } if result.value == StrandWatchCurrentValue::Cleared(())
    ));
}

#[test]
fn malformed_or_mismatched_outcome_fails_closed() {
    let request: StrandWatchCurrentRequestBody = serde_json::from_value(request()).unwrap();
    let mut missing_value = current(Value::Null);
    missing_value["result"]
        .as_object_mut()
        .unwrap()
        .remove("value");
    assert!(!schema_accepts(
        "#/$defs/StrandWatchCurrentOutcome",
        &missing_value
    ));
    assert!(serde_json::from_value::<StrandWatchCurrentOutcome>(missing_value).is_err());

    let mut wrong_kind = never_written();
    wrong_kind["selector"]["kind"] = json!("strand");
    assert!(!schema_accepts(
        "#/$defs/StrandWatchCurrentOutcome",
        &wrong_kind
    ));
    assert!(serde_json::from_value::<StrandWatchCurrentOutcome>(wrong_kind).is_err());

    let mut future = current(Value::Null);
    future["result"]["revision"]["stream_position"] = json!(13);
    let parsed: StrandWatchCurrentOutcome = serde_json::from_value(future).unwrap();
    assert!(parsed.validate_for_request(&request).is_err());

    let mut different_cell = never_written();
    different_cell["selector"]["strand_id"] =
        json!("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9");
    let parsed: StrandWatchCurrentOutcome = serde_json::from_value(different_cell).unwrap();
    assert!(parsed.validate_for_request(&request).is_err());
}
