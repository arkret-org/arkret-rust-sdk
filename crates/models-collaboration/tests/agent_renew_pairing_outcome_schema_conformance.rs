//! Renewed Agent pairing must retain the immutable controller binding.

use std::fs;

use arkret_models_collaboration::agent_operations::AgentRenewPairingOutcome;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn registry() -> arkret_schema::ProtocolSchemaRegistry {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/agent-operations.schema.json")).unwrap(),
    )
    .unwrap();
    registry.register_reference_document(schema.clone()).unwrap();
    registry
        .register_fragment(
            "test:agent-renew-pairing-outcome",
            schema,
            "#/$defs/agent_renew_pairing_outcome",
        )
        .unwrap();
    registry
}

fn outcome() -> Value {
    json!({
        "agent_id": "ak:did_core:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey",
        "principal_control_realm_id": "ak:realm:AYj1hkGaeWVFOEdto3Hsqc1nmIwSKd3TswkkqrnOkPa-",
        "controller_authorization_ref": "did:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey:agent.example#managed-controller",
        "requested_scope_digest": "sha256:fcdc0d9a579d073a680854d396140edf510ff90eff74f52124baca4cc2313e83",
        "pairing_request_id": "pairing_request:01964137-0000-7000-8000-000000000000",
        "pairing_code": "AAAAAAAAAAAAAAAAAAAAAA",
        "expires_at": "2026-07-17T13:50:07.734Z"
    })
}

#[test]
fn renewed_binding_round_trips_against_formal_schema() {
    let value = outcome();
    registry()
        .validate_value("test:agent-renew-pairing-outcome", &value)
        .unwrap();
    let typed: AgentRenewPairingOutcome = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(typed).unwrap(), value);
}

#[test]
fn missing_binding_fields_fail_closed_in_schema_and_sdk() {
    for field in [
        "principal_control_realm_id",
        "controller_authorization_ref",
        "requested_scope_digest",
    ] {
        let mut missing = outcome();
        missing.as_object_mut().unwrap().remove(field);
        assert!(registry()
            .validate_value("test:agent-renew-pairing-outcome", &missing)
            .is_err());
        assert!(serde_json::from_value::<AgentRenewPairingOutcome>(missing).is_err());
    }
}
