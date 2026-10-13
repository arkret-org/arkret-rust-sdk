//! Schema and runtime binding checks for the exact current-result read.

use std::fs;

use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn fixture() -> Value {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/exact-current-results-read-fixture.json")).unwrap(),
    )
    .unwrap()
}

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/exact-current-results-read.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let id = format!("test:exact-current-results-{}", fragment.replace('#', "@"));
    registry
        .register_fragment(id.clone(), schema, fragment)
        .unwrap();
    registry.validate_value(&id, value).is_ok()
}

fn moderation_request(outcome: &Value) -> Value {
    json!({
        "realm_id": outcome["realm_id"].clone(),
        "selector": outcome["entry"]["selector"].clone()
    })
}

fn moderation_outcome(fixture: &Value) -> Value {
    fixture["valid_outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "authorized_moderation_present")
        .expect("the formal fixture must include an authorized moderation result")["value"]
        .clone()
}

fn policy_outcome() -> Value {
    let mut value = moderation_outcome(&fixture());
    let policy = "ak:policy:0198ff00-0000-7000-8000-000000000001";
    value["entry"]["selector"] = json!({"kind":"policy", "policy_id":policy});
    value["entry"]["value"] = json!({
        "schema":"ak.schema.policy.v1", "id":policy, "realm_id":value["realm_id"],
        "policy_kind":"agent", "default_effect":"deny",
        "rules":[{"rule_id":"owned_join", "kind":"agent", "effect":"allow",
            "agent_target":{"kind":"all"}, "agent_operations":["join"]}],
        "created_by":{"kind":"service", "service_id":"ak:did_core:web:policy.example"},
        "created_at":"2026-09-16T00:00:00.000Z"
    });
    value
}

#[test]
fn managed_policy_current_is_the_whole_document_in_its_realm_or_circle_stream() {
    for circle in [false, true] {
        let mut value = policy_outcome();
        if circle {
            let stream = json!({"kind":"circle", "realm_id":value["realm_id"],
                "circle_id":"ak:circle:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9"});
            value["entry"]["source_stream_ref"] = stream.clone();
            value["effective_stream_head"]["stream_ref"] = stream;
        }
        assert!(schema_accepts(
            "#/$defs/exact_current_results_read_outcome",
            &value
        ));
        let request = serde_json::from_value(moderation_request(&value)).unwrap();
        let outcome: ExactCurrentResultsReadOutcome =
            serde_json::from_value(value.clone()).unwrap();
        outcome.validate_for_request(&request, 4).unwrap();
        assert_eq!(serde_json::to_value(outcome).unwrap(), value);
    }
}

#[test]
fn policy_current_rejects_submit_payload_wrappers_and_other_policy_identity() {
    let value = policy_outcome();
    let mut wrapped = value.clone();
    wrapped["entry"]["value"] = json!({
        "policy_id":value["entry"]["selector"]["policy_id"],
        "expected_revision":null, "value":value["entry"]["value"]
    });
    assert!(!schema_accepts(
        "#/$defs/exact_current_results_read_outcome",
        &wrapped
    ));
    assert!(serde_json::from_value::<ExactCurrentResultsReadOutcome>(wrapped).is_err());
    let request = serde_json::from_value(moderation_request(&value)).unwrap();
    let mut wrong_id = value;
    wrong_id["entry"]["value"]["id"] = json!("ak:policy:0198ff00-0000-7000-8000-000000000002");
    let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(wrong_id).unwrap();
    assert!(outcome.validate_for_request(&request, 4).is_err());
}

#[test]
fn formal_fixture_round_trips_through_strong_types() {
    let fixture = fixture();
    let request_value = fixture["request"].clone();
    assert!(schema_accepts(
        "#/$defs/exact_current_results_read_request",
        &request_value
    ));
    let relation_request: ExactCurrentResultsReadRequestBody =
        serde_json::from_value(request_value.clone()).unwrap();
    relation_request.validate().unwrap();
    assert_eq!(
        serde_json::to_value(&relation_request).unwrap(),
        request_value
    );

    for case in fixture["valid_outcomes"].as_array().unwrap() {
        let value = case["value"].clone();
        assert!(schema_accepts(
            "#/$defs/exact_current_results_read_outcome",
            &value
        ));
        let outcome: ExactCurrentResultsReadOutcome =
            serde_json::from_value(value.clone()).unwrap();
        let request = if case["name"] == "authorized_relation_never_written" {
            relation_request.clone()
        } else {
            serde_json::from_value(moderation_request(&value)).unwrap()
        };
        outcome.validate_for_request(&request, 4).unwrap();
        assert_eq!(serde_json::to_value(outcome).unwrap(), value);
    }
}

#[test]
fn moderation_never_written_is_rejected_by_schema_and_sdk() {
    let fixture = fixture();
    let case = &fixture["schema_validation_cases"][0];
    assert_eq!(case["expect_valid"], false);
    let value = case["instance"].clone();
    assert!(!schema_accepts(
        "#/$defs/exact_current_results_read_outcome",
        &value
    ));
    assert!(serde_json::from_value::<ExactCurrentResultsReadOutcome>(value).is_err());
}

#[test]
fn missing_source_stream_is_rejected_by_schema_and_sdk() {
    let fixture = fixture();
    let mut value = moderation_outcome(&fixture);
    value["entry"]
        .as_object_mut()
        .unwrap()
        .remove("source_stream_ref");
    assert!(!schema_accepts(
        "#/$defs/exact_current_results_read_outcome",
        &value
    ));
    assert!(serde_json::from_value::<ExactCurrentResultsReadOutcome>(value).is_err());
}

#[test]
fn stale_or_mismatched_same_cut_response_fails_closed() {
    let fixture = fixture();
    let value = moderation_outcome(&fixture);
    let request: ExactCurrentResultsReadRequestBody =
        serde_json::from_value(moderation_request(&value)).unwrap();

    let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(value.clone()).unwrap();
    assert!(outcome.validate_for_request(&request, 5).is_err());

    let mut wrong_selector = value.clone();
    wrong_selector["entry"]["selector"]["target_ref"] =
        json!("ak:message:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9");
    let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(wrong_selector).unwrap();
    assert!(outcome.validate_for_request(&request, 4).is_err());

    let mut future_revision = value.clone();
    future_revision["entry"]["revision"]["stream_position"] = json!(13);
    let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(future_revision).unwrap();
    assert!(outcome.validate_for_request(&request, 4).is_err());

    let mut other_stream = value.clone();
    other_stream["entry"]["source_stream_ref"] = json!({
        "kind": "circle",
        "realm_id": value["realm_id"].clone(),
        "circle_id": "ak:circle:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9"
    });
    assert!(schema_accepts(
        "#/$defs/exact_current_results_read_outcome",
        &other_stream
    ));
    let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(other_stream).unwrap();
    assert!(outcome.validate_for_request(&request, 4).is_err());

    let mut wrong_head_commit = value;
    wrong_head_commit["effective_stream_head"]["commit_id"] =
        json!("ak:realm_commit:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD");
    let outcome: ExactCurrentResultsReadOutcome =
        serde_json::from_value(wrong_head_commit).unwrap();
    assert!(outcome.validate_for_request(&request, 4).is_err());
}

#[test]
fn target_and_event_dot_are_validated_without_raw_json_carriers() {
    let fixture = fixture();
    let value = moderation_outcome(&fixture);

    let mut bad_target = moderation_request(&value);
    bad_target["selector"]["target_ref"] = json!("not-an-object-ref");
    assert!(serde_json::from_value::<ExactCurrentResultsReadRequestBody>(bad_target).is_err());

    let mut bare_event = value.clone();
    bare_event["entry"]["value"]["assertions"][0]["tag_id"] =
        json!("ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD");
    assert!(serde_json::from_value::<ExactCurrentResultsReadOutcome>(bare_event).is_err());

    let mut leading_zero = value;
    leading_zero["entry"]["value"]["assertions"][0]["tag_id"] =
        json!("ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD:00");
    assert!(serde_json::from_value::<ExactCurrentResultsReadOutcome>(leading_zero).is_err());
}
