//! A scope disclosure is a non-Event signed object, so its proof binds
//! `payload_digest`, never an Event's `event_digest`.

use std::fs;

use arkret_models_collaboration::agent_scope::AgentRequestedScopeDisclosure;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::Value;

fn fixture() -> Value {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let suite: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/agent-vectors-fixture.json")).unwrap(),
    )
    .unwrap();
    suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "agent_requested_scope_privacy")
        .unwrap()["disclosure"]
        .clone()
}

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/agent-requested-scope-disclosure.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment("test:agent-scope-disclosure", schema, "#")
        .unwrap();
    registry
        .validate_value("test:agent-scope-disclosure", value)
        .is_ok()
}

#[test]
fn non_event_proof_matches_formal_schema_and_sdk() {
    let value = fixture();
    assert!(schema_accepts(&value));
    let parsed: AgentRequestedScopeDisclosure = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    let computed_digest = parsed.payload_digest().unwrap();
    assert_eq!(parsed.proofs[0].payload_digest, computed_digest);
    parsed.validate().unwrap();
    let binding: Value = serde_json::from_slice(
        &parsed
            .canonical_proof_binding_bytes(&parsed.proofs[0])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        binding["payload_digest"],
        serde_json::to_value(computed_digest).unwrap()
    );
    assert_eq!(
        binding["context"],
        "ak.agent_requested_scope_disclosure_proof.v1"
    );

    let mut event_proof = value;
    let proof = event_proof["proofs"][0].as_object_mut().unwrap();
    let digest = proof.remove("payload_digest").unwrap();
    proof.insert("event_digest".to_owned(), digest);
    assert!(!schema_accepts(&event_proof));
    assert!(serde_json::from_value::<AgentRequestedScopeDisclosure>(event_proof).is_err());
}
