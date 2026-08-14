use arkret_schema::embedded_json_artifact;

#[test]
fn embedded_device_revocation_fixture_keeps_the_named_contract() {
    let fixture =
        embedded_json_artifact("fixtures/device-revocation-pending-fixture.json").unwrap();
    assert_eq!(fixture["suite"], "device_revocation_pending_state");
    assert_eq!(fixture["runner"]["kind"], "named_suite");
    assert_eq!(
        fixture["runner"]["entrypoint"],
        "ak.suite.device.revocation_pending_state.v1"
    );
    let cases = fixture["semantic_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    assert!(
        cases
            .iter()
            .any(|case| case["name"] == "first_human_issue_acquires_binding_from_the_allow_receipt")
    );
    let gate_case = cases
        .iter()
        .find(|case| case["name"] == "pending_blocks_closed_action_set_on_every_profile")
        .unwrap();
    assert_eq!(
        gate_case["denied_actions"],
        serde_json::json!([
            "session_grant_issue_or_refresh",
            "keypackage_claim",
            "to_device_write",
            "event_write",
            "principal_server_admission_proof_issue"
        ])
    );
}
