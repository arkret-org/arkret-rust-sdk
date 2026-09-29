//! Applet revoke plans bind every Grant intent to its exact current revision.

use std::fs;

use arkret_models_integration::{AppletRevokePlan, AppletRevokeStep};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn fixture() -> Value {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/applet-revoke-saga-fixture.json")).unwrap(),
    )
    .unwrap()
}

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(
            artifacts
                .join("schemas")
                .join("applet-install-operations.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            "test:applet-revoke-plan",
            schema,
            "#/$defs/applet_revoke_plan",
        )
        .unwrap();
    registry
        .validate_value("test:applet-revoke-plan", value)
        .is_ok()
}

fn step_schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(
            artifacts
                .join("schemas")
                .join("applet-install-operations.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            "test:applet-revoke-step",
            schema,
            "#/$defs/applet_revoke_step",
        )
        .unwrap();
    registry
        .validate_value("test:applet-revoke-step", value)
        .is_ok()
}

#[test]
fn formal_plan_round_trips_exact_grant_revision_and_digest() {
    let fixture = fixture();
    let value = fixture["preview_plan_digest_kat"]["revoke_plan"].clone();
    assert!(schema_accepts(&value));

    let plan: AppletRevokePlan = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(plan.capability_revocations.len(), 1);
    assert_eq!(
        plan.capability_revocations[0]
            .expected_revision
            .stream_position,
        41
    );
    assert_eq!(serde_json::to_value(&plan).unwrap(), value);

    let digest = arkret_canonical::canonical_sha256(&value).unwrap();
    assert_eq!(
        digest.as_str(),
        fixture["preview_plan_digest_kat"]["expected_revoke_plan_digest"]
            .as_str()
            .unwrap()
    );

    let mut changed = value;
    changed["capability_revocations"][0]["expected_revision"]["stream_position"] = json!(42);
    assert_ne!(
        arkret_canonical::canonical_sha256(&changed).unwrap(),
        digest
    );
}

#[test]
fn missing_untyped_or_unknown_revision_carriers_are_rejected() {
    let value = fixture()["preview_plan_digest_kat"]["revoke_plan"].clone();

    let mut missing = value.clone();
    missing["capability_revocations"][0]
        .as_object_mut()
        .unwrap()
        .remove("expected_revision");
    assert!(!schema_accepts(&missing));
    assert!(serde_json::from_value::<AppletRevokePlan>(missing).is_err());

    let mut untyped = value.clone();
    untyped["capability_revocations"][0]["expected_revision"] = json!(41);
    assert!(!schema_accepts(&untyped));
    assert!(serde_json::from_value::<AppletRevokePlan>(untyped).is_err());

    let mut unknown = value;
    unknown["capability_revocations"][0]["expected_revision"]["event_id"] =
        json!("ak:event:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8");
    assert!(!schema_accepts(&unknown));
    assert!(serde_json::from_value::<AppletRevokePlan>(unknown).is_err());
}

#[test]
fn plan_carries_no_delegated_session_inventory() {
    let value = fixture()["preview_plan_digest_kat"]["revoke_plan"].clone();
    for (field, carrier) in [
        ("delegated_session_refs", json!([])),
        (
            "delegated_session_snapshot_digest",
            json!(format!("sha256:{}", "a".repeat(64))),
        ),
    ] {
        let mut extended = value.clone();
        extended[field] = carrier;
        assert!(!schema_accepts(&extended), "formal schema accepted {field}");
        assert!(
            serde_json::from_value::<AppletRevokePlan>(extended).is_err(),
            "SDK accepted {field}"
        );
    }

    let mut delegated_mode = value;
    delegated_mode["revoke_mode"] = json!("revoke_delegated_sessions");
    assert!(!schema_accepts(&delegated_mode));
    assert!(serde_json::from_value::<AppletRevokePlan>(delegated_mode).is_err());
}

#[test]
fn formal_step_reference_matrix_round_trips_through_closed_sdk_union() {
    let fixture = fixture();
    let cases = fixture["step_reference_kat"].as_object().unwrap();
    for name in [
        "submitted_pending",
        "submitted_rejected",
        "committed_accepted",
        "local_pending",
    ] {
        let value = cases[name].clone();
        assert!(step_schema_accepts(&value), "formal schema rejected {name}");
        let step: AppletRevokeStep = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(step).unwrap(), value, "{name}");
    }
}

#[test]
fn invalid_status_reference_combinations_and_event_disguises_are_rejected() {
    let fixture = fixture();
    for case in fixture["invalid_step_reference_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let value = &case["value"];
        assert!(!step_schema_accepts(value), "formal schema accepted {name}");
        assert!(
            serde_json::from_value::<AppletRevokeStep>(value.clone()).is_err(),
            "SDK accepted {name}"
        );
    }
}
