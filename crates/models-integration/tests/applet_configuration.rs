//! Registered configuration transcripts and closed correlation boundaries.
use arkret_models_integration::{
    AppletConfigurationExecutionOutcome, AppletConfigurationExecutionRequest,
};
use serde_json::{Value, json};

#[test]
fn peer_configuration_carries_full_account_and_preserves_the_original_request() {
    use arkret_models_integration::AppletConfigurationPeerRequest;
    let corpus = fixtures();
    let execution = &corpus["signature_kats"][0]["unsigned_host"]["intent"];
    let body = json!({
        "requester_account_id": execution["originating_actor_id"]["account_id"],
        "request": {
            "command": "configure",
            "intent": {
                "request_id": execution["request_id"],
                "effective_scope": execution["effective_scope"],
                "selection": execution["selection"],
            }
        }
    });
    let request: AppletConfigurationPeerRequest = serde_json::from_value(body.clone()).unwrap();
    request.validate().unwrap();
    assert_eq!(serde_json::to_value(request).unwrap(), body);
    for invalid in [
        json!({"requester_account_id": null, "request": body["request"]}),
        json!({"requester_account_id": execution["originating_actor_id"], "request": body["request"]}),
        json!({"requester_account_id": body["requester_account_id"], "request": body["request"], "login_token": "forbidden"}),
    ] {
        assert!(serde_json::from_value::<AppletConfigurationPeerRequest>(invalid).is_err());
    }
}

fn fixtures() -> Value {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    serde_json::from_slice(
        &std::fs::read(artifacts.join("fixtures/applet-management-source-fixture.json")).unwrap(),
    )
    .unwrap()
}

fn signed(kat: &Value) -> Value {
    let mut value = kat["unsigned_host"].clone();
    value["proof"] = json!({
        "verification_method": kat["verification_method"],
        "jws": kat["jws"],
    });
    value
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn configuration_transcripts_match_formal_signature_vectors() {
    let corpus = fixtures();
    let command = &corpus["signature_kats"][0];
    let result = &corpus["signature_kats"][1];
    let request: AppletConfigurationExecutionRequest =
        serde_json::from_value(signed(command)).unwrap();
    let outcome: AppletConfigurationExecutionOutcome =
        serde_json::from_value(signed(result)).unwrap();
    request
        .validate_at("2026-10-19T08:02:00.000Z".parse().unwrap())
        .unwrap();
    outcome.validate_for(&request.intent).unwrap();
    assert_eq!(
        hex(&request.signature_payload().unwrap()),
        command["payload_hex"]
    );
    assert_eq!(
        hex(&outcome.signature_payload().unwrap()),
        result["payload_hex"]
    );
    assert_eq!(serde_json::to_value(&request).unwrap(), signed(command));
    assert_eq!(serde_json::to_value(&outcome).unwrap(), signed(result));
}

#[test]
fn handoff_refresh_preserves_intent_and_changes_the_signed_command() {
    let corpus = fixtures();
    let request: AppletConfigurationExecutionRequest =
        serde_json::from_value(signed(&corpus["signature_kats"][0])).unwrap();
    let mut refreshed = request.clone();
    refreshed.governance_generation += 1;
    assert_eq!(
        request.intent.digest().unwrap(),
        refreshed.intent.digest().unwrap()
    );
    assert_ne!(
        request.signature_payload().unwrap(),
        refreshed.signature_payload().unwrap()
    );
    refreshed.governance_generation = request.intent.governance_generation - 1;
    assert!(
        refreshed
            .validate_at("2026-10-19T08:02:00.000Z".parse().unwrap())
            .is_err()
    );
    assert!(
        request
            .validate_at("2026-10-19T08:05:00.000Z".parse().unwrap())
            .is_err()
    );
    let mut substituted = request.clone();
    substituted.intent.originating_actor_id =
        arkret_wire::ActorId::service(request.intent.service_id.clone());
    assert!(substituted.intent.validate().is_err());
}

#[test]
fn outcome_cannot_change_intent_or_claim_acceptance_without_original_refs() {
    let corpus = fixtures();
    let command: AppletConfigurationExecutionRequest =
        serde_json::from_value(signed(&corpus["signature_kats"][0])).unwrap();
    let value = signed(&corpus["signature_kats"][1]);
    for mutation in [
        json!({"intent_digest": format!("sha256:{}", "0".repeat(64))}),
        json!({"creation_refs": []}),
        json!({"status": "pending"}),
        json!({"service_id": "ak:did_core:web:substituted.example"}),
    ] {
        let mut changed = value.clone();
        changed
            .as_object_mut()
            .unwrap()
            .extend(mutation.as_object().unwrap().clone());
        let outcome: AppletConfigurationExecutionOutcome = serde_json::from_value(changed).unwrap();
        assert!(outcome.validate_for(&command.intent).is_err());
    }
    for field in ["actor_id", "creation_refs", "create_event"] {
        let mut changed = value.clone();
        changed[field] = Value::Null;
        assert!(serde_json::from_value::<AppletConfigurationExecutionOutcome>(changed).is_err());
    }
    let mut unknown = value;
    unknown["accepted"] = json!(true);
    assert!(serde_json::from_value::<AppletConfigurationExecutionOutcome>(unknown).is_err());
}
