//! Realm join candidates stay the closed, untrusted locator core published by
//! `realm-join-candidate.schema.json`.

use std::fs;

use arkret_models_collaboration::governance::realm_join_intake::{
    RealmJoinApplicationStatus, RealmJoinApplicationStatusOutcome, RealmJoinCandidate,
    RealmJoinTarget,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

const SCHEMA_FILE: &str = "realm-join-candidate.schema.json";

fn registry() -> (ProtocolSchemaRegistry, Value) {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable");
    let path = artifacts.join("schemas").join(SCHEMA_FILE);
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .expect("realm join candidate schema must be valid JSON");
    let registry = schema_registry_from_spec_artifacts(artifacts)
        .expect("the spec artifacts must produce a schema registry");
    (registry, schema)
}

fn schema_accepts(value: &Value) -> bool {
    let (mut registry, schema) = registry();
    registry
        .register_reference_document(schema.clone())
        .expect("schema document declares an absolute $id");
    registry.register("test:realm-join-candidate", schema);
    registry
        .validate_value("test:realm-join-candidate", value)
        .is_ok()
}

fn accepted_candidate() -> Value {
    json!({
        "service_kind": "station",
        "service_id": "ak:did_core:webvh:zGUwpRSnyVCLzU7upsm9iSwEv",
        "endpoint_url": "https://candidate.example/_arkret",
        "source": "directory"
    })
}

#[test]
fn candidate_matches_the_published_closed_core() {
    let value = accepted_candidate();
    assert!(schema_accepts(&value));

    let candidate: RealmJoinCandidate =
        serde_json::from_value(value.clone()).expect("SDK accepts the canonical candidate");
    candidate.validate().expect("canonical candidate validates");
    assert_eq!(serde_json::to_value(candidate).unwrap(), value);
}

#[test]
fn realm_scope_and_freshness_are_not_candidate_members() {
    for (field, field_value) in [
        (
            "realm_id",
            json!("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"),
        ),
        ("observed_at", json!("2026-09-20T00:00:00.000Z")),
        ("expires_at", json!("2026-09-20T00:05:00.000Z")),
    ] {
        let mut value = accepted_candidate();
        value
            .as_object_mut()
            .expect("candidate is an object")
            .insert(field.to_owned(), field_value);

        assert!(!schema_accepts(&value), "schema accepted retired {field}");
        assert!(
            serde_json::from_value::<RealmJoinCandidate>(value).is_err(),
            "SDK accepted retired {field}"
        );
    }
}

#[test]
fn endpoint_url_is_optional_and_https_when_present() {
    let mut without_endpoint = accepted_candidate();
    without_endpoint
        .as_object_mut()
        .unwrap()
        .remove("endpoint_url");
    let candidate: RealmJoinCandidate = serde_json::from_value(without_endpoint).unwrap();
    candidate.validate().unwrap();

    let mut insecure = accepted_candidate();
    insecure["endpoint_url"] = json!("http://candidate.example/_arkret");
    assert!(!schema_accepts(&insecure));
    let candidate: RealmJoinCandidate = serde_json::from_value(insecure).unwrap();
    assert!(candidate.validate().is_err());
}

#[test]
fn join_target_requires_strict_service_id_order_and_unique_identity() {
    let target = |candidates: Value| -> RealmJoinTarget {
        serde_json::from_value(json!({
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "authority_locator_hints": candidates
        }))
        .unwrap()
    };
    let candidate = |service_id: &str, source: &str| {
        json!({
            "service_kind": "station",
            "service_id": service_id,
            "source": source
        })
    };

    let a = candidate("ak:did_core:web:a.example", "invite");
    let b = candidate("ak:did_core:web:b.example", "directory");
    target(json!([a.clone(), b.clone()])).validate().unwrap();
    assert!(target(json!([b, a.clone()])).validate().is_err());
    assert!(
        target(json!([a, candidate("ak:did_core:web:a.example", "cache")]))
            .validate()
            .is_err()
    );
}

#[test]
fn application_status_serializes_exactly_the_published_enum() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable");
    let path = artifacts
        .join("schemas")
        .join("realm-join-intake.schema.json");
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .expect("realm join intake schema must be valid JSON");
    let published =
        schema["$defs"]["application_status_outcome"]["properties"]["status"]["enum"].clone();
    let sdk = json!([
        RealmJoinApplicationStatus::Pending,
        RealmJoinApplicationStatus::Committed,
        RealmJoinApplicationStatus::Rejected,
    ]);
    assert_eq!(sdk, published);

    let pending: RealmJoinApplicationStatusOutcome = serde_json::from_value(json!({
        "request_id": "ak:request:01999999-0000-7000-8000-000000000001",
        "status": "pending"
    }))
    .expect("pending is the published non-terminal status");
    pending
        .validate()
        .expect("pending carries no commit or reason");
    assert!(
        serde_json::from_value::<RealmJoinApplicationStatusOutcome>(json!({
            "request_id": "ak:request:01999999-0000-7000-8000-000000000001",
            "status": "queued"
        }))
        .is_err()
    );
}
