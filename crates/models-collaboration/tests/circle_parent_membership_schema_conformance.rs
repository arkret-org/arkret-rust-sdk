//! `ak.vector.circle.parent_membership_revision.v1`: a Circle join binds the
//! exact parent Realm join revision, and effective Circle membership compares
//! the two typed currents of one durable cut by Commit identity.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::events_payloads::circle::CircleMemberStatePayload;
use arkret_models_collaboration::sync_frames::current_results::{
    CircleMemberStateCurrent, CurrentRevision, MemberStateCurrent, MembershipState, TypedCurrentRow,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{CommitStreamRef, ErrorCode, RealmId};
use serde_json::{Value, json};

const FIXTURE: &str = "circle-parent-membership-fixture.json";
const VECTOR: &str = "ak.vector.circle.parent_membership_revision.v1";

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn read_json(path: PathBuf) -> Value {
    serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .unwrap()
}

fn fixture() -> Value {
    read_json(artifacts_dir().join("fixtures").join(FIXTURE))
}

fn registry() -> ProtocolSchemaRegistry {
    let mut registry = schema_registry_from_spec_artifacts(artifacts_dir()).unwrap();
    for file in [
        "event-payload.schema.json",
        "typed-current-result.schema.json",
    ] {
        registry
            .register_reference_document(read_json(artifacts_dir().join("schemas").join(file)))
            .unwrap();
    }
    registry
}

fn schema_accepts(registry: &mut ProtocolSchemaRegistry, schema_ref: &str, value: &Value) -> bool {
    let (file, fragment) = schema_ref
        .strip_prefix("schemas/")
        .and_then(|rest| rest.split_once('#'))
        .unwrap();
    let schema_id = format!("test:{file}@{fragment}");
    registry
        .register_fragment(
            schema_id.clone(),
            read_json(artifacts_dir().join("schemas").join(file)),
            &format!("#{fragment}"),
        )
        .unwrap();
    registry.validate_value(&schema_id, value).is_ok()
}

fn apply_mutations(mut value: Value, mutations: &[Value]) -> Value {
    for mutation in mutations {
        let path = mutation["path"].as_str().unwrap();
        let (parent, key) = path.rsplit_once('/').unwrap();
        let target = value.pointer_mut(parent).unwrap().as_object_mut().unwrap();
        match mutation["op"].as_str().unwrap() {
            "remove" => {
                assert!(target.remove(key).is_some(), "{path} is absent");
            }
            "add" | "replace" => {
                target.insert(key.to_owned(), mutation["value"].clone());
            }
            op => panic!("unsupported fixture mutation {op}"),
        }
    }
    value
}

fn case_instance(cases: &[Value], case: &Value) -> Value {
    if let Some(instance) = case.get("instance") {
        return instance.clone();
    }
    let base_name = case["instance_from"].as_str().unwrap();
    let base = cases
        .iter()
        .find(|candidate| candidate["name"] == base_name)
        .unwrap();
    apply_mutations(
        case_instance(cases, base),
        case["mutations"].as_array().unwrap(),
    )
}

/// The SDK decodes every schema-valid instance and refuses every
/// schema-invalid one, naming the same field the fixture names.
fn sdk_decode(schema_ref: &str, value: &Value) -> Result<Value, String> {
    match schema_ref.rsplit_once('/').unwrap().1 {
        "circle_member_state_payload" => {
            serde_json::from_value::<CircleMemberStatePayload>(value.clone())
                .map(|payload| serde_json::to_value(payload).unwrap())
                .map_err(|error| error.to_string())
        }
        "circle_member_state_result" => {
            let result: TypedCurrentRow =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
            let TypedCurrentRow::Value {
                source_stream_ref,
                value: current,
                ..
            } = &result;
            if !matches!(source_stream_ref, CommitStreamRef::Circle { .. }) {
                return Err("circle_member_state is written on its Circle stream".to_owned());
            }
            serde_json::from_value::<CircleMemberStateCurrent>(current.clone())
                .map_err(|error| error.to_string())?;
            Ok(serde_json::to_value(result).unwrap())
        }
        "member_state_result" => {
            let result: TypedCurrentRow =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
            let TypedCurrentRow::Value { value: current, .. } = &result;
            serde_json::from_value::<MemberStateCurrent>(current.clone())
                .map_err(|error| error.to_string())?;
            Ok(serde_json::to_value(result).unwrap())
        }
        other => panic!("fixture names an unmapped schema fragment {other}"),
    }
}

#[test]
fn vector_is_registered_active_for_this_fixture() {
    let registry = read_json(artifacts_dir().join("registry/vector-registry.json"));
    let row = registry["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["vector_id"] == VECTOR)
        .unwrap();
    assert_eq!(row["status"], "active");
    assert_eq!(row["applies_to_fixtures"], json!([FIXTURE]));
    assert_eq!(fixture()["covers_vectors"], json!([VECTOR]));
}

#[test]
fn schema_validation_cases_agree_with_sdk_types() {
    let fixture = fixture();
    let cases = fixture["schema_validation_cases"].as_array().unwrap();
    let mut registry = registry();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let schema_ref = case["schema_ref"].as_str().unwrap();
        let instance = case_instance(cases, case);
        let expect_valid = case["expect_valid"].as_bool().unwrap();
        assert_eq!(
            schema_accepts(&mut registry, schema_ref, &instance),
            expect_valid,
            "schema verdict for {name}"
        );
        match sdk_decode(schema_ref, &instance) {
            Ok(round_trip) => {
                assert!(expect_valid, "SDK accepted invalid case {name}");
                assert_eq!(round_trip, instance, "SDK round trip of {name}");
            }
            Err(error) => {
                assert!(!expect_valid, "SDK refused valid case {name}: {error}");
                let token = case["first_expected_error"]
                    .as_str()
                    .and_then(|expected| expected.strip_prefix("contains:"))
                    .unwrap();
                assert!(error.contains(token), "{name}: {error} lacks {token}");
            }
        }
    }
}

#[test]
fn locally_built_payloads_follow_the_same_presence_rule() {
    let fixture = fixture();
    let join = fixture["schema_validation_cases"][0]["instance"].clone();
    let mut payload: CircleMemberStatePayload = serde_json::from_value(join).unwrap();
    payload.validate().unwrap();
    let revision = payload.parent_membership_revision.take();
    assert_eq!(
        payload.validate().unwrap_err().error_code(),
        Some(ErrorCode::SchemaViolation)
    );
    payload.membership = arkret_models_collaboration::governance::circle::CircleMembership::Leave;
    payload.validate().unwrap();
    payload.parent_membership_revision = revision;
    assert_eq!(
        payload.validate().unwrap_err().error_code(),
        Some(ErrorCode::SchemaViolation)
    );
}

fn revision(value: &Value) -> CurrentRevision {
    serde_json::from_value(value.clone()).unwrap()
}

fn membership(value: &Value) -> MembershipState {
    serde_json::from_value(value.clone()).unwrap()
}

fn circle_current(entry: &Value) -> CircleMemberStateCurrent {
    let mut value = json!({
        "membership": entry["membership"],
        "effective_at": "2026-09-29T02:00:00.000Z"
    });
    if let Some(bound) = entry.get("parent_membership_revision") {
        value["parent_membership_revision"] = bound.clone();
    }
    serde_json::from_value(value).unwrap()
}

/// Effective Circle ids of one member in one cut.
fn effective_circle_ids(realm_id: &RealmId, parent: &Value, circles: &[(String, Value)]) -> Value {
    let parent_stream: CommitStreamRef =
        serde_json::from_value(parent["source_stream_ref"].clone()).unwrap();
    let parent_revision = revision(&parent["revision"]);
    let parent_membership = membership(&parent["membership"]);
    Value::Array(
        circles
            .iter()
            .filter(|(_, entry)| {
                circle_current(entry).is_effective_under_parent(
                    realm_id,
                    &parent_stream,
                    &parent_revision,
                    parent_membership,
                )
            })
            .map(|(circle_id, _)| Value::String(circle_id.clone()))
            .collect(),
    )
}

fn realm_of(parent: &Value) -> RealmId {
    serde_json::from_value(parent["source_stream_ref"]["realm_id"].clone()).unwrap()
}

fn cut_circles(cut: &Value) -> Vec<(String, Value)> {
    if let Some(entries) = cut.get("circle_member_states") {
        return entries
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["circle_id"].as_str().unwrap().to_owned(),
                    entry.clone(),
                )
            })
            .collect();
    }
    let current = &cut["circle_member_state_current"];
    vec![(
        current["source_stream_ref"]["circle_id"]
            .as_str()
            .unwrap()
            .to_owned(),
        current["value"].clone(),
    )]
}

fn admission_verdict(parent: &Value, payload: &Value) -> Value {
    let payload: CircleMemberStatePayload = serde_json::from_value(payload.clone()).unwrap();
    let realm_id = realm_of(parent);
    let parent_stream: CommitStreamRef =
        serde_json::from_value(parent["source_stream_ref"].clone()).unwrap();
    let bound = CircleMemberStateCurrent {
        membership: MembershipState::Join,
        parent_membership_revision: payload.parent_membership_revision.clone(),
        effective_at: chrono::Utc::now(),
    };
    if bound.is_effective_under_parent(
        &realm_id,
        &parent_stream,
        &revision(&parent["revision"]),
        membership(&parent["membership"]),
    ) {
        json!({"result": "accepted"})
    } else {
        json!({
            "result": "failed_precondition",
            "reason": "circle_member_must_be_realm_member",
            "write_count": 0
        })
    }
}

fn history_cut_results(case: &Value) -> (u64, Vec<Value>) {
    let parent_current = revision(&case["parent_current_revision"]);
    let joins = case["circle_stream_joins"].as_array().unwrap();
    let current = joins.iter().find(|join| join["current"] == true).unwrap();
    assert_eq!(
        revision(&current["parent_membership_revision"]),
        parent_current
    );
    let floor = current["position"].as_u64().unwrap();
    let results = case["expected"]["target_cut_results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| {
            let position = target["target_position"].as_u64().unwrap();
            let instance = joins
                .iter()
                .filter(|join| join["position"].as_u64().unwrap() <= position)
                .max_by_key(|join| join["position"].as_u64().unwrap());
            let continuous = position >= floor
                || instance.is_some_and(|join| {
                    revision(&join["parent_membership_revision"]) == parent_current
                });
            json!({
                "target_position": position,
                "result": if continuous { "continuous" } else { "not_found" }
            })
        })
        .collect();
    (floor, results)
}

#[test]
fn semantic_cases_follow_effective_circle_membership() {
    let fixture = fixture();
    let mut seen = BTreeSet::new();
    for case in fixture["semantic_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        seen.insert(name.to_owned());
        let expected = &case["expected"];
        if let Some(cut) = case.get("cut").or_else(|| case.get("replica")) {
            let parent = &cut["parent_member_state"];
            assert_eq!(
                effective_circle_ids(&realm_of(parent), parent, &cut_circles(cut)),
                expected["effective_circle_ids"],
                "{name}"
            );
            for count in [
                "synthesized_circle_event_count",
                "rewritten_canonical_circle_row_count",
            ] {
                if let Some(value) = expected.get(count) {
                    assert_eq!(value, &json!(0), "{name}.{count}");
                }
            }
            if let Some(head) = cut.get("realm_stream_head_position") {
                let bound = revision(&cut["circle_member_states"][0]["parent_membership_revision"]);
                assert!(
                    head.as_u64().unwrap() < bound.stream_position,
                    "{name}: the Realm replica lags the bound revision on the Realm stream"
                );
                assert_eq!(
                    expected["circle_join_bootstrap_result"],
                    "dependency_missing"
                );
                assert_eq!(expected["accepted_circle_event_retained"], true);
            }
            if let Some(events) = case.get("circle_events_in_order") {
                for event in events.as_array().unwrap() {
                    circle_current(event).validate().unwrap();
                }
            }
        } else if let Some(parent) = case.get("admission_cut_parent_member_state") {
            assert_eq!(
                admission_verdict(parent, &case["submitted_payload"]),
                *expected,
                "{name}"
            );
        } else if let Some(payloads) = case.get("submitted_payloads") {
            assert_eq!(expected["result"], "schema_violation");
            for payload in payloads.as_array().unwrap() {
                let error = serde_json::from_value::<CircleMemberStatePayload>(payload.clone())
                    .unwrap_err();
                assert!(
                    error.to_string().contains("parent_membership_revision"),
                    "{name}: {error}"
                );
            }
        } else if let Some(mls) = case.get("mls") {
            assert_eq!(mls["leaf_owner_effective_after_parent_leave"], false);
            let before = &mls["key_access_revision_before_parent_leave"];
            assert_eq!(&expected["key_access_revision_after_parent_leave"], before);
            assert_eq!(
                &expected["clearing_commit_covers_key_access_revision"],
                before
            );
            for gate in ["application_send", "add_submission"] {
                assert_eq!(
                    expected[gate],
                    json!({"result": "failed_precondition", "reason": "epoch_update_required"}),
                    "{name}.{gate}"
                );
            }
        } else if case.get("circle_stream_joins").is_some() {
            let (floor, results) = history_cut_results(case);
            assert_eq!(json!(floor), expected["readable_floor_position"], "{name}");
            assert_eq!(
                Value::Array(results),
                expected["target_cut_results"],
                "{name}"
            );
        } else {
            panic!("semantic case {name} has no evaluator");
        }
    }
    assert_eq!(seen.len(), 11, "{seen:?}");
}
