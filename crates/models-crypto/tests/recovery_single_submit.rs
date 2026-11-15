use arkret_models_crypto::{
    RecoveryReceipt, RecoveryTransactionCreateRequestBody, SecurityTransaction,
    SecurityTransactionContinueRequestBody,
};
use serde_json::{Value, json};

fn kat() -> Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )
    .unwrap()["single_submit_recovery_kat"]
        .clone()
}

#[test]
fn recovery_create_is_one_closed_receipt_and_response_replays_it_exactly() {
    let kat = kat();
    let receipt: RecoveryReceipt = serde_json::from_value(kat["receipt"].clone()).unwrap();
    let request = RecoveryTransactionCreateRequestBody::new(receipt).unwrap();
    let response: SecurityTransaction =
        serde_json::from_value(kat["expected_outcome"].clone()).unwrap();
    response.validate_structural().unwrap();
    let SecurityTransaction::Recovery(completed) = response else {
        panic!("wrong kind")
    };
    completed.validate_for_request(&request).unwrap();
    let body = serde_json::to_value(&request).unwrap();
    assert_eq!(
        body.as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["kind", "recovery_receipt"]
    );
    let mut old = body;
    old["prepared_plan"] = json!({});
    assert!(serde_json::from_value::<RecoveryTransactionCreateRequestBody>(old).is_err());
    let mut changed = completed;
    changed.recovery_receipt.signature_proof.signature =
        arkret_wire::Base64UrlString::new("A".repeat(86)).unwrap();
    assert!(changed.validate_for_request(&request).is_err());
}

#[test]
fn swapped_slots_or_old_outer_receipt_members_are_rejected() {
    let mut receipt = kat()["receipt"].clone();
    receipt["recovery_unit"]["events"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert!(
        serde_json::from_value::<RecoveryReceipt>(receipt)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut receipt = kat()["receipt"].clone();
    receipt["prepared_plan_digest"] = json!(format!("sha256:{}", "a".repeat(64)));
    assert!(serde_json::from_value::<RecoveryReceipt>(receipt).is_err());
}

#[test]
fn recovery_has_no_continue_path() {
    let transaction: SecurityTransaction =
        serde_json::from_value(kat()["expected_outcome"].clone()).unwrap();
    let old = json!({"request_digest":format!("sha256:{}","a".repeat(64)),"prepared_plan_digest":format!("sha256:{}","b".repeat(64)),"expected_accepted_step_count":0});
    assert!(serde_json::from_value::<SecurityTransactionContinueRequestBody>(old).is_err());
    assert!(matches!(transaction, SecurityTransaction::Recovery(_)));
}

#[test]
fn native_recovery_rejects_generic_approvals_without_stripping_the_signed_slot() {
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/approval-signature-kat-fixture.json",
    )
    .unwrap();
    let approval = fixture["vectors"][0]["approval_signature"].clone();
    for index in 0..2 {
        let mut value = kat()["receipt"].clone();
        value["recovery_unit"]["events"][index]["approval_signatures"] = json!([approval]);
        let receipt: RecoveryReceipt = serde_json::from_value(value.clone()).unwrap();
        assert!(receipt.validate().is_err());
        assert_eq!(serde_json::to_value(receipt).unwrap(), value);
    }
}
