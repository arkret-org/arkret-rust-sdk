//! Both sides of the Agent provision prepare/commit exchange follow the
//! formal, closed two-phase request and four-stage outcome schema.

use std::fs;

use arkret_models_collaboration::agent_operations::{
    AgentProvisionOutcome, AgentProvisionRequestBody,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn registry() -> arkret_schema::ProtocolSchemaRegistry {
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
            "test:agent-provision-request",
            schema.clone(),
            "#/$defs/agent_provision_request_body",
        )
        .unwrap();
    registry
        .register_fragment(
            "test:agent-provision-outcome",
            schema,
            "#/$defs/agent_provision_outcome",
        )
        .unwrap();
    registry
}

fn prepare_request() -> Value {
    json!({
        "phase": "prepare",
        "operation_id": "ak:operation:01964137-0000-7000-8000-000000000000",
        "idempotency_key": "agent-provision-1",
        "did": "did:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey:agent.example",
        "slug": "agent-one",
        "requested_scope": {
            "actions": ["ak.self.committed_event.read.scan.v1"],
            "resources": [{"kind":"operation","operation":"ak.self.committed_event.read.scan.v1"}]
        },
        "controller_station_id": "ak:did_core:web:station.example"
    })
}

fn outcome(status: &str) -> Value {
    let mut value = json!({
        "status": status,
        "agent_id": "ak:did_core:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey",
        "did": "did:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey:agent.example",
        "initial_resolution": {
            "did": "did:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey:agent.example",
            "method_history_head": "sha256:49a25bc42670cf632b8ce25992626afb8604a9fb36c449b9e982f826af668c0f",
            "version_id": "1-QmXwxauG2VKw57Bbr7PmQPxKCfxw2TqdHeamzCu8jzXjbf"
        },
        "controller_authorization_ref": "did:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey:agent.example#managed-controller"
    });
    let map = value.as_object_mut().unwrap();
    match status {
        "awaiting_controller_event" => {
            map.insert(
                "controller_realm_id".into(),
                json!("ak:realm:ATH75ame6bMfYpXtcoLOVb7FKmgpWVniZZqVBz1dUdQa"),
            );
            map.insert("allocation_handle".into(), json!("allocation_handle_01"));
        }
        "awaiting_pcr_genesis" | "awaiting_did_binding" => {
            map.insert(
                "principal_control_realm_id".into(),
                json!("ak:realm:AYj1hkGaeWVFOEdto3Hsqc1nmIwSKd3TswkkqrnOkPa-"),
            );
            map.insert("allocation_handle".into(), json!("allocation_handle_01"));
        }
        "complete" => {
            map.insert(
                "principal_control_realm_id".into(),
                json!("ak:realm:AYj1hkGaeWVFOEdto3Hsqc1nmIwSKd3TswkkqrnOkPa-"),
            );
            map.insert(
                "pairing_request_id".into(),
                json!("pairing_request:01964137-0000-7000-8000-000000000000"),
            );
            map.insert("pairing_code".into(), json!("AAAAAAAAAAAAAAAAAAAAAA"));
            map.insert("expires_at".into(), json!("2026-07-17T13:50:07.734Z"));
        }
        _ => unreachable!(),
    }
    value
}

#[test]
fn prepare_request_round_trips_and_forbids_commit_only_members() {
    let registry = registry();
    let value = prepare_request();
    registry
        .validate_value("test:agent-provision-request", &value)
        .unwrap();
    let typed: AgentProvisionRequestBody = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(typed, AgentProvisionRequestBody::Prepare(_)));
    assert_eq!(serde_json::to_value(typed).unwrap(), value);

    for member in [
        "provision_event",
        "allocation_handle",
        "principal_control_realm_id",
        "requested_scope_digest",
    ] {
        let mut invalid = value.clone();
        invalid[member] = json!("stale");
        assert!(
            registry
                .validate_value("test:agent-provision-request", &invalid)
                .is_err(),
            "{member}"
        );
        assert!(
            serde_json::from_value::<AgentProvisionRequestBody>(invalid).is_err(),
            "{member}"
        );
    }
}

#[test]
fn four_outcomes_round_trip_flat_and_reject_cross_stage_members() {
    let registry = registry();
    for status in [
        "awaiting_controller_event",
        "awaiting_pcr_genesis",
        "awaiting_did_binding",
        "complete",
    ] {
        let value = outcome(status);
        registry
            .validate_value("test:agent-provision-outcome", &value)
            .unwrap();
        let typed: AgentProvisionOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), value, "{status}");
        let mut invalid = value;
        invalid["provision_ref"] = json!("retired");
        assert!(
            registry
                .validate_value("test:agent-provision-outcome", &invalid)
                .is_err()
        );
        assert!(serde_json::from_value::<AgentProvisionOutcome>(invalid).is_err());
    }
}

#[test]
fn awaiting_did_binding_cannot_claim_pairing_and_complete_cannot_keep_allocation() {
    let registry = registry();
    let mut premature = outcome("awaiting_did_binding");
    premature["pairing_request_id"] = json!("pairing_request:01964137-0000-7000-8000-000000000000");
    assert!(
        registry
            .validate_value("test:agent-provision-outcome", &premature)
            .is_err()
    );
    assert!(serde_json::from_value::<AgentProvisionOutcome>(premature).is_err());

    let mut stale = outcome("complete");
    stale["allocation_handle"] = json!("allocation_handle_01");
    assert!(
        registry
            .validate_value("test:agent-provision-outcome", &stale)
            .is_err()
    );
    assert!(serde_json::from_value::<AgentProvisionOutcome>(stale).is_err());
}
