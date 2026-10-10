use std::any::TypeId;

use arkret_models_crypto::KeyPackageClaimRecord;
use arkret_models_crypto::http_bodies::{
    KeyPackageConsumeReceipt, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeUnsignedRequest, PeerKeyPackagesClaimOutcome,
    PeerKeyPackagesClaimRequestBody, PeerKeyPackagesClaimUnsignedRequest,
};
use arkret_wire::DidCoreId;
use serde_json::json;

fn core_id(_name: &str) -> DidCoreId {
    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
}

#[test]
fn self_and_peer_keypackage_claim_dtos_have_distinct_schema_identities() {
    assert_ne!(
        TypeId::of::<KeyPackagesClaimRequestBody>(),
        TypeId::of::<PeerKeyPackagesClaimRequestBody>()
    );
    assert_ne!(
        TypeId::of::<KeyPackagesClaimOutcome>(),
        TypeId::of::<PeerKeyPackagesClaimOutcome>()
    );
}

#[test]
fn human_claim_account_station_is_bound() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/keypackage-lifecycle-fixture.json")
            .unwrap();
    let request = fixture["unsigned_selector_transcripts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["branch"] == "device")
        .unwrap()["unsigned_request"]
        .clone();
    let parsed: PeerKeyPackagesClaimUnsignedRequest =
        serde_json::from_value(request.clone()).unwrap();
    let canonical = arkret_canonical::canonical_json_bytes(&parsed).unwrap();

    let mut other_station = request;
    other_station["target_account_id"]["station_id"] =
        json!("ak:did_core:webvh:z6mkfixtureotherstation");
    let other_station: PeerKeyPackagesClaimUnsignedRequest =
        serde_json::from_value(other_station).unwrap();
    assert_ne!(
        canonical,
        arkret_canonical::canonical_json_bytes(&other_station).unwrap(),
        "same principal at another Station is a distinct claim target"
    );
}

#[test]
fn keypackage_claim_record_rejects_schema_invalid_scalars_and_mixed_authority() {
    let valid = json!({
        "claim_id": "ak:keypackage_claim:0199cccc-cccc-7ccc-8ccc-cccccccccccc",
        "keypackage_ref": "ak:mls:keypackage:test-01",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture","station_id":"ak:did_core:webvh:z6mkfixtureservice"}},
        "principal_id": "ak:did_core:webvh:z6mkfixture",
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "keypackage": "AQID",
        "capabilities": ["ak.mls.profile.full"],
        "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
        "expires_at": "2100-01-01T00:00:00.000Z",
        "revocation_status": "active"
    });
    assert!(serde_json::from_value::<KeyPackageClaimRecord>(valid.clone()).is_ok());

    for (field, invalid) in [
        ("claim_id", json!("")),
        ("claim_id", json!("ak:claim:retired-shape")),
        ("keypackage_ref", json!("")),
        ("keypackage", json!("not+base64url")),
        ("capabilities", json!([])),
        ("capabilities", json!(["duplicate", "duplicate"])),
        ("revocation_status", json!("unknown")),
    ] {
        let mut candidate = valid.clone();
        candidate[field] = invalid;
        assert!(
            serde_json::from_value::<KeyPackageClaimRecord>(candidate).is_err(),
            "field {field} accepted a schema-invalid value"
        );
    }

    let mut mixed = valid;
    mixed["agent_id"] = json!("ak:did_core:webvh:z6mkfixture");
    mixed["agent_verification_method"] = json!("did:webvh:z6mkfixture#runtime");
    mixed["agent_key_authorize_event_id"] =
        json!("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM");
    assert!(serde_json::from_value::<KeyPackageClaimRecord>(mixed).is_err());
}

#[test]
fn keypackages_claim_outcome_uses_typed_records_and_failures() {
    let outcome = json!({
        "claim_request_id": "Y2xhaW0tbm9uY2U",
        "claims": [{
            "claim_id": "ak:keypackage_claim:0199cccc-cccc-7ccc-8ccc-cccccccccccc",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture","station_id":"ak:did_core:webvh:z6mkfixtureservice"}},
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "keypackage": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "revocation_status": "active"
        }],
        "claim_receipt": {
            "claim_request_id": "Y2xhaW0tbm9uY2U",
            "request_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "claims_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "source_id": "ak:did_core:webvh:z6mkfixtureservice",
            "destination_id": "ak:did_core:webvh:z6mkfixtureservice",
            "request": {
                "claim_request_id": "Y2xhaW0tbm9uY2U",
                "target_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixtureservice"
                },
                "intended_realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "requester_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixtureservice"
                },
                "mls_group_id": "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4",
                "claim_purpose": "realm_membership",
                "required_capabilities": ["ak.mls.profile.full"],
                "target_device_ids": ["ak:device:01904100-0000-7000-8000-000000000001"],
                "expires_at": "2099-01-01T00:00:00.000Z"
            },
            "claimed_at": "2098-12-31T23:59:30.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z",
            "signature": {
                "kid": "did:webvh:z6mkfixtureservice:service.example#key-1",
                "signature_algorithm": "Ed25519",
                "sig": "c2ln"
            }
        }
    });
    let parsed: KeyPackagesClaimOutcome = serde_json::from_value(outcome).unwrap();
    assert_eq!(parsed.claims[0].principal_id, core_id("alice"));
    assert!(parsed.claims[0].device_authorize_event_id.is_some());

    let malformed_claim = json!({
        "claims": [{
            "claim_id": "keypackage-t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture","station_id":"ak:did_core:webvh:z6mkfixtureservice"}},
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "keypackage": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "unexpected": true
        }]
    });
    assert!(serde_json::from_value::<KeyPackagesClaimOutcome>(malformed_claim).is_err());

    let malformed_failure = json!({
        "claims": [],
        "failures": [{
            "reason_code": "not_found",
            "unexpected": true
        }]
    });
    assert!(serde_json::from_value::<KeyPackagesClaimOutcome>(malformed_failure).is_err());
}

#[test]
fn consume_receipt_coordinates_have_one_nested_carrier() {
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap();
    let receipt = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "consume_receipt_single_source_coordinates")
        .unwrap()["signed_receipt"]
        .clone();

    let parsed: KeyPackageConsumeReceipt = serde_json::from_value(receipt.clone()).unwrap();
    parsed.validate_shape().unwrap();
    for forbidden in [
        "claim_request_id",
        "keypackage_ref",
        "welcome_ref",
        "realm_id",
        "mls_group_id",
        "mls_epoch",
        "source_id",
    ] {
        let mut with_forbidden = receipt.clone();
        with_forbidden
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<KeyPackageConsumeReceipt>(with_forbidden).is_err());
    }

    let outcome = json!({"consume_receipt": receipt});
    assert!(serde_json::from_value::<KeyPackagesConsumeOutcome>(outcome.clone()).is_ok());
    let mut outcome_with_forbidden = outcome;
    outcome_with_forbidden.as_object_mut().unwrap().insert(
        "consumed_keypackage_ref".to_owned(),
        json!("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
    );
    assert!(serde_json::from_value::<KeyPackagesConsumeOutcome>(outcome_with_forbidden).is_err());
}

#[test]
fn consume_command_has_only_claim_and_durable_receipt() {
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap();
    let request = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "consume_single_claim")
        .unwrap()["unsigned_request"]
        .clone();
    let parsed: KeyPackagesConsumeUnsignedRequest =
        serde_json::from_value(request.clone()).unwrap();
    parsed.validate_shape().unwrap();

    for forbidden in [
        "owner_principal_id",
        "keypackage_ref",
        "welcome_ref",
        "consumer_device_id",
        "consumer_agent_id",
        "consumer_agent_verification_method",
        "consumer_agent_key_authorize_event_id",
        "consumer_pairwise_verification_method",
    ] {
        let mut with_forbidden = request.clone();
        with_forbidden
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<KeyPackagesConsumeUnsignedRequest>(with_forbidden).is_err()
        );
    }
}

#[test]
fn claim_query_request_carries_only_the_typed_claim_id() {
    use arkret_models_crypto::http_bodies::KeyPackagesClaimQueryRequestBody;

    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/schema-validation-fixture.json")
            .unwrap();
    let cases = fixture["schema_validation_cases"].as_array().unwrap();
    let instance =
        |name: &str| cases.iter().find(|case| case["name"] == name).unwrap()["instance"].clone();
    let valid: KeyPackagesClaimQueryRequestBody =
        serde_json::from_value(instance("keypackages_claim_query_request_valid")).unwrap();
    assert_eq!(
        serde_json::to_value(&valid).unwrap(),
        instance("keypackages_claim_query_request_valid")
    );
    for rejected in [
        "keypackages_claim_query_request_rejects_request_digest",
        "keypackages_claim_query_request_rejects_untyped_claim_id",
    ] {
        assert!(
            serde_json::from_value::<KeyPackagesClaimQueryRequestBody>(instance(rejected)).is_err(),
            "{rejected}"
        );
    }
}
