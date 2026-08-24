use std::any::TypeId;

use arkret_models_crypto::http_bodies::{
    KeyPackageConsumeReceipt, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeUnsignedRequest, PeerKeyPackageClaimReceipt,
    PeerKeyPackagesClaimOutcome, PeerKeyPackagesClaimRequestBody,
};
use arkret_models_crypto::{KeyOperationSignature, KeyPackageClaimRecord};
use arkret_wire::{Base64UrlString, DidCoreId, DidUrl, Hash, NonEmptyString};
use serde_json::json;

fn did(_name: &str) -> DidCoreId {
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
fn pairwise_claim_evidence_binds_every_signed_target_selector() {
    let fixture =
        arkret_schema::embedded_json_artifact("fixtures/keypackage-lifecycle-fixture.json")
            .unwrap();
    let cases = fixture["schema_validation_cases"].as_array().unwrap();
    let instance =
        |name: &str| cases.iter().find(|case| case["name"] == name).unwrap()["instance"].clone();
    let request: KeyPackagesClaimRequestBody = serde_json::from_value(instance(
        "minimal_metadata_pairwise_claim_selects_exact_target_authority",
    ))
    .unwrap();
    let claim: KeyPackageClaimRecord = serde_json::from_value(instance(
        "minimal_metadata_pairwise_claim_record_has_reconstructible_facts_only",
    ))
    .unwrap();
    let receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: request.claim_request_id.clone(),
        request_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
        claims_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
        source_service_id: request.service_binding.source_service_id.clone(),
        destination_service_id: request.service_binding.destination_service_id.clone(),
        request: request.unsigned_request(),
        claimed_at: chrono::DateTime::parse_from_rfc3339("2026-08-24T00:00:01.000Z")
            .unwrap()
            .to_utc(),
        expires_at: chrono::DateTime::parse_from_rfc3339("2026-08-24T00:05:00.000Z")
            .unwrap()
            .to_utc(),
        signature: KeyOperationSignature {
            kid: NonEmptyString::new("did:webvh:z6mkfixturepsexample:ps.example#notary").unwrap(),
            signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
            sig: Base64UrlString::new("AA").unwrap(),
        },
    };
    arkret_models_crypto::validate_target_claim_evidence(&claim, &receipt).unwrap();

    let mut wrong_method = claim.clone();
    wrong_method.pairwise_verification_method = Some(
        DidUrl::new("did:key:z6Mkr4KQ7fQyVfQ7fQyVfQ7fQyVfQ7fQyVfQ7fQyVfQ7#z6Mkr4KQ7fQyVfQ7fQyVfQ7fQyVfQ7fQyVfQ7fQyVfQ7".to_owned()).unwrap(),
    );
    assert!(arkret_models_crypto::validate_target_claim_evidence(&wrong_method, &receipt).is_err());

    let mut wrong_ref_receipt = receipt.clone();
    wrong_ref_receipt.request.target_keypackage_ref =
        Some(arkret_wire::KeyPackageRef::new(format!("sha256:{}", "44".repeat(32))).unwrap());
    assert!(
        arkret_models_crypto::validate_target_claim_evidence(&claim, &wrong_ref_receipt).is_err()
    );

    let mut mixed = claim;
    mixed.agent_verification_method =
        Some(DidUrl::new("did:webvh:z6mkfixtureagent:agent.example#runtime".to_owned()).unwrap());
    assert!(arkret_models_crypto::validate_target_claim_evidence(&mixed, &receipt).is_err());
}

#[test]
fn keypackages_claim_outcome_uses_typed_records_and_failures() {
    let outcome = json!({
        "claim_request_id": "Y2xhaW0tbm9uY2U",
        "claims": [{
            "claim_id": "keypackage-t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "keypackage": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "endpoint_signature": {
                "kid": "did:webvh:z6mkfixture:alice.example#ak:device:01904100-0000-7000-8000-000000000001",
                "signature_algorithm": "Ed25519",
                "sig": "c2ln"
            },
            "revocation_status": "active"
        }],
        "claim_receipt": {
            "claim_request_id": "Y2xhaW0tbm9uY2U",
            "request_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "claims_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "source_service_id": "ak:did_core:webvh:z6mkfixtureservice",
            "destination_service_id": "ak:did_core:webvh:z6mkfixtureservice",
            "request": {
                "claim_request_id": "Y2xhaW0tbm9uY2U",
                "target_principal_id": "ak:did_core:webvh:z6mkfixture",
                "intended_realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "requester": "ak:did_core:webvh:z6mkfixture",
                "mls_group_id": "mls-group-fixture",
                "claim_purpose": "realm_membership",
                "required_capabilities": ["ak.mls.profile.full"],
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
    assert_eq!(parsed.claims[0].principal_id, did("alice"));
    assert!(parsed.claims[0].device_authorize_event_id.is_some());

    let malformed_claim = json!({
        "claims": [{
            "claim_id": "keypackage-t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "keypackage": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "endpoint_signature": {"kid": "did:webvh:z6mkfixture:alice.example#device", "sig": "c2ln"},
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
    let fixture =
        arkret_schema::embedded_json_artifact("fixtures/keypackage-write-transcript-fixture.json")
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
        "source_service_id",
    ] {
        let mut legacy = receipt.clone();
        legacy
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<KeyPackageConsumeReceipt>(legacy).is_err());
    }

    let outcome = json!({"consume_receipt": receipt});
    assert!(serde_json::from_value::<KeyPackagesConsumeOutcome>(outcome.clone()).is_ok());
    let mut legacy_outcome = outcome;
    legacy_outcome.as_object_mut().unwrap().insert(
        "consumed_keypackage_ref".to_owned(),
        json!("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
    );
    assert!(serde_json::from_value::<KeyPackagesConsumeOutcome>(legacy_outcome).is_err());
}

#[test]
fn consume_command_has_only_claim_and_durable_receipt() {
    let fixture =
        arkret_schema::embedded_json_artifact("fixtures/keypackage-write-transcript-fixture.json")
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
        let mut legacy = request.clone();
        legacy
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<KeyPackagesConsumeUnsignedRequest>(legacy).is_err());
    }
}
