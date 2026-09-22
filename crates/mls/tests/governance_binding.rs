use arkret_mls::{
    MlsCurrentSendState, MlsGovernanceBindingPublicState, MlsGovernanceBindingRejection,
    VerifiedMlsGovernanceBinding, verify_current_send_governance_binding,
    verify_governance_binding_against_public_state_and_payload,
    verify_governance_binding_transition, verify_historical_governance_binding,
    verify_mls_genesis_binding_proposal,
};
use arkret_models_collaboration::events_payloads::MlsGenesisBindingProposalCarrier;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_schema_conformance::spec_json_artifact;
use arkret_wire::{ErrorCode, EventId, ScopeRef};
use serde_json::Value;

fn fixture() -> Value {
    spec_json_artifact("fixtures/mls-governance-binding-closure-fixture.json").unwrap()
}

fn binding(value: &Value) -> MlsGovernanceBindingPayload {
    serde_json::from_value(value.clone()).unwrap()
}

fn expected_reason(sample: &Value) -> Option<&str> {
    sample["expected"]["reason"].as_str()
}

fn assert_semantic_result(
    sample: &Value,
    result: Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection>,
) {
    match expected_reason(sample) {
        None => assert!(result.is_ok(), "{} must be accepted", sample["name"]),
        Some(reason) => assert_eq!(result.unwrap_err().code(), reason, "{}", sample["name"]),
    }
}

#[test]
fn deterministic_cbor_case_uses_the_closed_production_decoder() {
    let fixture = fixture();
    let case = &fixture["cases"][0];
    for sample in case["accepted"].as_array().unwrap() {
        let encoded = hex::decode(sample["encoded_map_hex"].as_str().unwrap()).unwrap();
        let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap();
        assert_eq!(decoded, binding(&sample["binding"]));
        assert_eq!(decoded.to_deterministic_cbor().unwrap(), encoded);
    }
    for sample in case["rejection_samples"].as_array().unwrap() {
        let encoded = hex::decode(sample["encoded_map_hex"].as_str().unwrap()).unwrap();
        let error = MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap_err();
        assert_eq!(error.error_code(), Some(ErrorCode::SchemaViolation));
    }
}

#[test]
fn transition_case_uses_the_typed_production_gate() {
    let fixture = fixture();
    for sample in fixture["cases"][1]["samples"].as_array().unwrap() {
        let binding = binding(&sample["binding"]);
        let current_revision = sample["station_public_state"]["current_key_access_revision"]
            .as_u64()
            .unwrap_or_else(|| binding.key_access_revision());
        assert_semantic_result(
            sample,
            verify_governance_binding_transition(&binding, current_revision),
        );
    }
}

#[test]
fn public_state_and_payload_case_requires_field_for_field_equality() {
    let fixture = fixture();
    let case = &fixture["cases"][2];
    let event_payload_binding = binding(&case["event_payload_binding"]);
    let state_scope: ScopeRef =
        serde_json::from_value(case["station_public_state"]["effective_scope"].clone()).unwrap();
    let state_base: EventId =
        serde_json::from_value(case["station_public_state"]["base_group_state_ref"].clone())
            .unwrap();
    let public_state = MlsGovernanceBindingPublicState::new(
        state_scope,
        Some(state_base),
        event_payload_binding.previous_epoch(),
        case["station_public_state"]["current_key_access_revision"]
            .as_u64()
            .unwrap(),
    );
    for sample in case["samples"].as_array().unwrap() {
        assert_semantic_result(
            sample,
            verify_governance_binding_against_public_state_and_payload(
                &binding(&sample["binding"]),
                &public_state,
                &event_payload_binding,
            ),
        );
    }
}

#[test]
fn historical_acceptance_does_not_open_the_current_send_gate() {
    let fixture = fixture();
    let case = &fixture["cases"][3];
    let historical = binding(&case["historical_accepted_binding"]);
    assert!(verify_historical_governance_binding(&historical, &historical).is_ok());
    let current = MlsCurrentSendState::new(
        historical.effective_scope().clone(),
        historical.next_epoch(),
        case["current_public_state"]["current_key_access_revision"]
            .as_u64()
            .unwrap(),
    );
    let rejection = verify_current_send_governance_binding(&historical, &current).unwrap_err();
    assert_eq!(
        rejection.code(),
        case["expected"]["current_send_reason"].as_str().unwrap()
    );
}

#[test]
fn proposal_case_decodes_closed_input_before_semantic_evaluation() {
    let fixture = fixture();
    let case = &fixture["cases"][4];
    let accepted = serde_json::to_vec(&case["accepted_carrier"]).unwrap();
    let carrier = MlsGenesisBindingProposalCarrier::from_json_slice(&accepted).unwrap();
    assert!(verify_mls_genesis_binding_proposal(&carrier).is_ok());

    for sample in case["rejection_samples"].as_array().unwrap() {
        let encoded = serde_json::to_vec(&sample["carrier"]).unwrap();
        if expected_reason(sample) == Some("schema_violation") {
            let error = MlsGenesisBindingProposalCarrier::from_json_slice(&encoded).unwrap_err();
            assert_eq!(error.error_code(), Some(ErrorCode::SchemaViolation));
        } else {
            let carrier = MlsGenesisBindingProposalCarrier::from_json_slice(&encoded).unwrap();
            assert_semantic_result(sample, verify_mls_genesis_binding_proposal(&carrier));
        }
    }
}
