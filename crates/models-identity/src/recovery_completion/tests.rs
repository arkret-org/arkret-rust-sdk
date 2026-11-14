use super::*;

fn kat() -> serde_json::Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )
    .unwrap()["single_submit_recovery_kat"]
        .clone()
}

#[test]
fn fresh_holder_request_has_no_receipt_or_proof_digest_cycle() {
    let kat = kat();
    let request: RecoveryCompletionGrantRequestBody =
        serde_json::from_value(kat["completion_request"].clone()).unwrap();
    request.validate_structural().unwrap();
    let completion: RecoveryCompletionAttestation =
        serde_json::from_value(kat["expected_outcome"]["completion_attestation"].clone()).unwrap();
    let proof = &request.accepted_device_possession_proof;
    request
        .validate_first_issue(
            &completion,
            &proof.account_subject,
            &proof.account_handoff_grant_digest,
            &proof.holder_jkt,
            proof.issued_at,
        )
        .unwrap();
    assert!(
        request
            .validate_first_issue(
                &completion,
                &proof.account_subject,
                &proof.account_handoff_grant_digest,
                &proof.holder_jkt,
                proof.expires_at
            )
            .is_err()
    );
    assert_ne!(
        proof.holder_jkt,
        request.terminal_receipt.session_grant_cnf_jkt.as_str()
    );
}

#[test]
fn operation_identity_is_transaction_scoped_and_replay_retains_old_proof_history() {
    let kat = kat();
    let request: RecoveryCompletionGrantRequestBody =
        serde_json::from_value(kat["completion_request"].clone()).unwrap();
    let issuer = request.terminal_receipt.session_grant_ref.issuer_id.clone();
    let mut changed = request.clone();
    changed.accepted_device_possession_proof.request_id =
        arkret_wire::RequestId::new("ak:request:019ba000-0000-7000-8000-000000000099").unwrap();
    assert_eq!(
        request.operation_identity(&issuer).unwrap(),
        changed.operation_identity(&issuer).unwrap()
    );
    assert!(
        changed
            .validate_exact_replay(
                &request,
                &request.terminal_receipt.account_id,
                &request.accepted_device_possession_proof.holder_jkt
            )
            .is_err()
    );
    request
        .validate_exact_replay(
            &request,
            &request.terminal_receipt.account_id,
            &request.accepted_device_possession_proof.holder_jkt,
        )
        .unwrap();
    assert!(
        request
            .validate_exact_replay(
                &request,
                &request.terminal_receipt.account_id,
                "another-holder"
            )
            .is_err()
    );
}
