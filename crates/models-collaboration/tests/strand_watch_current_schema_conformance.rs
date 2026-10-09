//! The exact watch read must preserve never-written versus written-null.

use std::fs;

use arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload;
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
            "source_stream_ref": {"kind": "realm", "realm_id": REALM},
            "revision": {"commit_id": COMMIT, "stream_position": 12},
            "value": value
        }
    })
}

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    schema_accepts_in("service-operation-dtos.schema.json", fragment, value)
}

fn schema_accepts_in(document: &str, fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value =
        serde_json::from_slice(&fs::read(artifacts.join("schemas").join(document)).unwrap())
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
fn watch_write_preserves_missing_null_and_complete_preimages() {
    let base = json!({"strand_id": STRAND, "watcher_actor_id": actor(), "level": "all"});
    for expected in [
        None,
        Some(Value::Null),
        Some(json!({"level":"all"})),
        Some(json!({"level":"all", "level_public":false})),
        Some(json!({"level":"all", "level_public":true})),
    ] {
        let mut wire = base.clone();
        if let Some(value) = expected.clone() {
            wire["expected_value"] = value;
        }
        assert!(schema_accepts_in(
            "event-payload.schema.json",
            "#/$defs/strand_watch_set_payload",
            &wire
        ));
        let payload: StrandWatchSetPayload = serde_json::from_value(wire.clone()).unwrap();
        match expected {
            None => assert!(payload.expected_value.is_none()),
            Some(Value::Null) => assert_eq!(
                payload.expected_value,
                Some(StrandWatchCurrentValue::Cleared(()))
            ),
            Some(_) => assert!(matches!(
                payload.expected_value,
                Some(StrandWatchCurrentValue::Set(_))
            )),
        }
        assert_eq!(payload.to_value().unwrap(), wire);
    }
}

#[test]
fn watch_write_can_reset_a_written_null_without_asserting_never_written() {
    let wire = json!({"strand_id": STRAND, "watcher_actor_id": actor(), "level": "participating"});
    let payload: StrandWatchSetPayload = serde_json::from_value(wire).unwrap();
    let guarded = payload.with_expected_value(StrandWatchCurrentValue::Cleared(()));
    assert_eq!(guarded.to_value().unwrap()["expected_value"], Value::Null);
    assert_eq!(
        serde_json::from_value::<StrandWatchSetPayload>(guarded.to_value().unwrap()).unwrap(),
        guarded
    );
}

#[test]
fn watch_write_rejects_malformed_complete_preimages() {
    for expected in [
        json!({}),
        json!({"level":null}),
        json!({"level":"all", "extra":true}),
        json!({"level":"invalid"}),
    ] {
        let wire = json!({"strand_id": STRAND, "watcher_actor_id": actor(), "level":"all", "expected_value":expected});
        assert!(!schema_accepts_in(
            "event-payload.schema.json",
            "#/$defs/strand_watch_set_payload",
            &wire
        ));
        assert!(serde_json::from_value::<StrandWatchSetPayload>(wire).is_err());
    }
}

#[test]
fn watch_write_requires_explicit_level_to_clear() {
    let mut wire = json!({"strand_id":STRAND, "watcher_actor_id":actor()});
    assert!(!schema_accepts_in(
        "event-payload.schema.json",
        "#/$defs/strand_watch_set_payload",
        &wire
    ));
    assert!(serde_json::from_value::<StrandWatchSetPayload>(wire.clone()).is_err());
    wire["level"] = Value::Null;
    assert!(schema_accepts_in(
        "event-payload.schema.json",
        "#/$defs/strand_watch_set_payload",
        &wire
    ));
    assert!(
        serde_json::from_value::<StrandWatchSetPayload>(wire)
            .unwrap()
            .level
            .is_none()
    );
}

#[test]
fn generic_typed_watch_result_matches_registered_schema_and_full_actor_selector() {
    for value in [
        Value::Null,
        json!({"level":"muted"}),
        json!({"level":"all","level_public":true}),
    ] {
        let wire = json!({"selector":selector(),
            "source_stream_ref":{"kind":"realm","realm_id":REALM},
            "revision":{"commit_id":COMMIT,"stream_position":12}, "value":value});
        assert!(schema_accepts_in(
            "typed-current-result.schema.json",
            "#/$defs/strand_watch_result",
            &wire
        ));
        let parsed: arkret_wire::TypedCurrentRow = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), wire);
    }
    let parsed: arkret_wire::CurrentSelector = serde_json::from_value(selector()).unwrap();
    let mut remote_wire = selector();
    remote_wire["watcher_actor_id"]["account_id"]["station_id"] =
        json!("ak:did_core:web:other.example");
    assert_ne!(
        parsed,
        serde_json::from_value::<arkret_wire::CurrentSelector>(remote_wire).unwrap()
    );
    for invalid in [
        json!({"kind":"strand_watch","strand_id":STRAND}),
        json!({"kind":"strand_watch","strand_id":STRAND,"watcher_actor_id":actor(),"subject":"extra"}),
    ] {
        assert!(serde_json::from_value::<arkret_wire::CurrentSelector>(invalid).is_err());
    }
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

    let mut missing_source = current(Value::Null);
    missing_source["result"]
        .as_object_mut()
        .unwrap()
        .remove("source_stream_ref");
    assert!(!schema_accepts(
        "#/$defs/StrandWatchCurrentOutcome",
        &missing_source
    ));
    assert!(serde_json::from_value::<StrandWatchCurrentOutcome>(missing_source).is_err());

    let mut other_stream = current(Value::Null);
    other_stream["result"]["source_stream_ref"] = json!({
        "kind": "circle",
        "realm_id": REALM,
        "circle_id": "ak:circle:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9"
    });
    assert!(schema_accepts(
        "#/$defs/StrandWatchCurrentOutcome",
        &other_stream
    ));
    let parsed: StrandWatchCurrentOutcome = serde_json::from_value(other_stream).unwrap();
    assert!(parsed.validate_for_request(&request).is_err());

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
