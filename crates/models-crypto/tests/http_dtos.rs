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
fn keypackage_family_arrays_and_retry_minima_match_schema() {
    use arkret_models_crypto::http_bodies::{
        KeyPackagesRevokeUnsignedRequest, KeyPackagesUploadOutcome,
        PeerKeyPackagesClaimQueryOutcome,
    };
    use arkret_models_crypto::{Failure, KeyPackageUploadEntry};
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    let upload = &cases
        .iter()
        .find(|case| case["name"] == "upload_batch_required_fields")
        .unwrap()["unsigned_request"]["keypackages"][0];
    serde_json::from_value::<KeyPackageUploadEntry>(upload.clone()).unwrap();
    for field in ["cipher_suites", "capabilities"] {
        for value in [
            json!([]),
            json!([upload[field][0], upload[field][0]]),
            json!([""]),
            serde_json::Value::Null,
        ] {
            let mut invalid = upload.clone();
            invalid[field] = value;
            assert!(
                serde_json::from_value::<KeyPackageUploadEntry>(invalid).is_err(),
                "{field}"
            );
        }
    }
    let revoke = &cases
        .iter()
        .find(|case| case["name"] == "revoke_with_reason")
        .unwrap()["unsigned_request"];
    serde_json::from_value::<KeyPackagesRevokeUnsignedRequest>(revoke.clone()).unwrap();
    let outcome = json!({"accepted":1,"keypackage_refs":[revoke["keypackage_refs"][0]]});
    serde_json::from_value::<KeyPackagesUploadOutcome>(outcome.clone()).unwrap();
    serde_json::from_value::<KeyPackagesUploadOutcome>(json!({"accepted":0})).unwrap();
    for value in [
        json!([]),
        json!([revoke["keypackage_refs"][0], revoke["keypackage_refs"][0]]),
        json!([""]),
        serde_json::Value::Null,
    ] {
        let mut invalid = revoke.clone();
        invalid["keypackage_refs"] = value.clone();
        assert!(serde_json::from_value::<KeyPackagesRevokeUnsignedRequest>(invalid).is_err());
        let mut invalid = outcome.clone();
        invalid["keypackage_refs"] = value;
        assert!(serde_json::from_value::<KeyPackagesUploadOutcome>(invalid).is_err());
    }
    serde_json::from_value::<Failure>(json!({"reason_code":"not_found","retry_after_ms":1}))
        .unwrap();
    let pending =
        json!({"claim_request_id":"AAAAAAAAAAAAAAAAAAAAAQ","state":"pending","retry_after_ms":1});
    serde_json::from_value::<PeerKeyPackagesClaimQueryOutcome>(pending.clone())
        .unwrap()
        .validate_shape()
        .unwrap();
    for value in [json!(0), serde_json::Value::Null] {
        assert!(
            serde_json::from_value::<Failure>(
                json!({"reason_code":"not_found","retry_after_ms":value})
            )
            .is_err()
        );
        let mut invalid = pending.clone();
        invalid["retry_after_ms"] = value;
        assert!(serde_json::from_value::<PeerKeyPackagesClaimQueryOutcome>(invalid).is_err());
    }
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
    let mut empty = outcome.clone();
    empty["claims"] = json!([]);
    assert!(serde_json::from_value::<KeyPackagesClaimOutcome>(empty.clone()).is_err());
    assert!(serde_json::from_value::<PeerKeyPackagesClaimOutcome>(empty).is_err());
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
fn claim_selectors_and_authorization_reject_retired_members_and_null() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/keypackage-lifecycle-fixture.json")
            .unwrap();
    for row in fixture["unsigned_selector_transcripts"].as_array().unwrap() {
        let request = &row["unsigned_request"];
        let parsed: PeerKeyPackagesClaimUnsignedRequest =
            serde_json::from_value(request.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), *request);
        for value in [
            serde_json::Value::Null,
            json!("did:key:z6Mkretired#z6Mkretired"),
        ] {
            let mut retired = request.clone();
            retired["target_pairwise_verification_method"] = value;
            assert!(
                serde_json::from_value::<PeerKeyPackagesClaimUnsignedRequest>(retired).is_err()
            );
        }
        for field in [
            "target_account_id",
            "requester_account_id",
            "target_agent_id",
            "target_agent_verification_method",
            "target_agent_key_authorize_event_id",
            "timeout_ms",
            "strand_id",
            "pair_key",
            "last_resort_allowed",
        ] {
            let mut null = request.clone();
            null[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<PeerKeyPackagesClaimUnsignedRequest>(null).is_err(),
                "{field}"
            );
        }
    }
    let mut authorization =
        fixture["schema_validation_cases"][0]["instance"]["requester_authorization"].clone();
    authorization["kind"] = json!("minimal_metadata_pairwise");
    assert!(
        serde_json::from_value::<arkret_models_crypto::PeerKeyPackageRequesterAuthorization>(
            authorization
        )
        .is_err()
    );
}

#[test]
fn claim_arrays_preserve_presence_and_timeout_obeys_schema_minimum() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/keypackage-lifecycle-fixture.json")
            .unwrap();
    let authorization =
        fixture["schema_validation_cases"][0]["instance"]["requester_authorization"].clone();
    for row in fixture["unsigned_selector_transcripts"].as_array().unwrap() {
        let value = row["unsigned_request"].clone();
        let unsigned: PeerKeyPackagesClaimUnsignedRequest =
            serde_json::from_value(value.clone()).unwrap();
        unsigned.validate_shape().unwrap();
        assert_eq!(serde_json::to_value(&unsigned).unwrap(), value);
        let mut signed = value.clone();
        signed["requester_authorization"] = authorization.clone();
        signed["service_binding"] = json!({
            "source_id": value["requester_account_id"]["station_id"],
            "destination_id": "ak:did_core:webvh:z6mkfixturepsexample"
        });
        let self_body: KeyPackagesClaimRequestBody =
            serde_json::from_value(signed.clone()).unwrap();
        self_body.validate_shape().unwrap();
        let peer_body: PeerKeyPackagesClaimRequestBody =
            serde_json::from_value(signed.clone()).unwrap();
        peer_body.validate_shape().unwrap();
        let transcript = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
            &unsigned,
            &self_body.service_binding,
            &self_body.requester_authorization,
        )
        .unwrap();
        assert_eq!(
            transcript,
            arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
                &self_body.unsigned_request(),
                &peer_body.service_binding,
                &peer_body.requester_authorization,
            )
            .unwrap()
        );
        for (field, invalid) in [
            ("target_device_ids", json!([])),
            ("target_device_ids", serde_json::Value::Null),
            (
                "target_device_ids",
                json!([
                    "ak:device:0196419b-0000-7000-8000-000000000001",
                    "ak:device:0196419b-0000-7000-8000-000000000001"
                ]),
            ),
            ("required_capabilities", json!([])),
            (
                "required_capabilities",
                json!(["ak.content.v1", "ak.content.v1"]),
            ),
            ("timeout_ms", json!(0)),
            ("timeout_ms", serde_json::Value::Null),
        ] {
            let mut unsigned_invalid = value.clone();
            unsigned_invalid[field] = invalid.clone();
            let mut signed_invalid = signed.clone();
            signed_invalid[field] = invalid;
            assert!(
                serde_json::from_value::<PeerKeyPackagesClaimUnsignedRequest>(unsigned_invalid)
                    .is_err(),
                "unsigned {} {field}",
                row["branch"]
            );
            assert!(
                serde_json::from_value::<KeyPackagesClaimRequestBody>(signed_invalid.clone())
                    .is_err(),
                "self {} {field}",
                row["branch"]
            );
            assert!(
                serde_json::from_value::<PeerKeyPackagesClaimRequestBody>(signed_invalid).is_err(),
                "peer {} {field}",
                row["branch"]
            );
        }
        let mut smallest = value.clone();
        smallest["timeout_ms"] = json!(1);
        serde_json::from_value::<PeerKeyPackagesClaimUnsignedRequest>(smallest)
            .unwrap()
            .validate_shape()
            .unwrap();
        let mut zero_constructed = unsigned;
        zero_constructed.timeout_ms = Some(0);
        assert!(zero_constructed.validate_shape().is_err());
    }
    let mut mixed = fixture["unsigned_selector_transcripts"][1]["unsigned_request"].clone();
    mixed["target_device_ids"] = json!(["ak:device:0196419b-0000-7000-8000-000000000001"]);
    assert!(
        serde_json::from_value::<PeerKeyPackagesClaimUnsignedRequest>(mixed)
            .unwrap()
            .validate_shape()
            .is_err()
    );
    let mut missing_human = fixture["unsigned_selector_transcripts"][0]["unsigned_request"].clone();
    missing_human
        .as_object_mut()
        .unwrap()
        .remove("target_device_ids");
    assert!(
        serde_json::from_value::<PeerKeyPackagesClaimUnsignedRequest>(missing_human)
            .unwrap()
            .validate_shape()
            .is_err()
    );
}

#[test]
fn durable_recipient_receipt_rejects_retired_members_and_null() {
    use arkret_models_crypto::RecipientMlsDurableReceipt;
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
    let receipt = &request["recipient_durable_receipt"];
    let parsed: RecipientMlsDurableReceipt = serde_json::from_value(receipt.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), *receipt);
    for field in [
        "recipient_pairwise_verification_method",
        "recipient_account_id",
        "recipient_device_id",
        "device_verification_method",
        "recipient_agent_id",
        "recipient_agent_verification_method",
        "agent_key_authorize_event_id",
    ] {
        let mut invalid = receipt.clone();
        invalid[field] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<RecipientMlsDurableReceipt>(invalid).is_err(),
            "{field}"
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

#[test]
fn keypackage_optional_members_preserve_absence_and_reject_null() {
    use arkret_models_crypto::http_bodies::{
        KeyPackagesRevokeRequestBody, KeyPackagesRevokeUnsignedRequest,
        PeerKeyPackagesClaimQueryOutcome,
    };
    use arkret_models_crypto::{Failure, KeyOperationSignature};

    fn check<T: serde::de::DeserializeOwned + serde::Serialize>(
        value: serde_json::Value,
        fields: &[&str],
    ) {
        let parsed: T = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
        for field in fields {
            let mut invalid = value.clone();
            invalid[*field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<T>(invalid).is_err(), "{field}");
        }
    }

    let signature = json!({"kid":"did:key:z6Mkfixture#z6Mkfixture","sig":"AQID"});
    check::<KeyOperationSignature>(signature.clone(), &["signature_algorithm"]);
    let mut explicit_algorithm = signature.clone();
    explicit_algorithm["signature_algorithm"] = json!("Ed25519");
    check::<KeyOperationSignature>(explicit_algorithm, &["signature_algorithm"]);
    check::<Failure>(
        json!({"reason_code":"not_found"}),
        &["keypackage_ref", "device_id", "retry_after_ms"],
    );

    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap();
    let revoke = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "revoke_with_reason")
        .unwrap()["unsigned_request"]
        .clone();
    check::<KeyPackagesRevokeUnsignedRequest>(revoke.clone(), &["reason"]);
    let mut signed_revoke = revoke;
    signed_revoke["signature"] = signature;
    check::<KeyPackagesRevokeRequestBody>(signed_revoke, &["reason"]);

    let unknown = json!({"claim_request_id":"AAAAAAAAAAAAAAAAAAAAAQ","state":"unknown"});
    serde_json::from_value::<PeerKeyPackagesClaimQueryOutcome>(unknown.clone())
        .unwrap()
        .validate_shape()
        .unwrap();
    check::<PeerKeyPackagesClaimQueryOutcome>(
        unknown,
        &[
            "claim_outcome",
            "consume_receipt",
            "terminal_receipt",
            "retry_after_ms",
            "error_code",
        ],
    );
    let pending =
        json!({"claim_request_id":"AAAAAAAAAAAAAAAAAAAAAQ","state":"pending","retry_after_ms":100});
    serde_json::from_value::<PeerKeyPackagesClaimQueryOutcome>(pending.clone())
        .unwrap()
        .validate_shape()
        .unwrap();
    check::<PeerKeyPackagesClaimQueryOutcome>(pending, &["retry_after_ms"]);
}

#[test]
fn terminal_receipt_optional_refs_follow_the_terminal_state() {
    use arkret_models_crypto::http_bodies::KeyPackageClaimTerminalReceipt;
    use arkret_wire::DomainSeparationId;

    let mut receipt = json!({
        "domain": DomainSeparationId::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1,
        "claim_request_id":"AAAAAAAAAAAAAAAAAAAAAQ",
        "request_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "terminal_state":"never_claimed",
        "source_id":"ak:did_core:webvh:z6mkfixtureservice",
        "destination_id":"ak:did_core:webvh:z6mkfixtureservice",
        "terminal_at":"2099-01-01T00:00:00.000Z",
        "signature":{"kid":"did:webvh:z6mkfixtureservice:service.example#key-1","signature_algorithm":"Ed25519","sig":"AQID"}
    });
    let parsed: KeyPackageClaimTerminalReceipt = serde_json::from_value(receipt.clone()).unwrap();
    parsed.validate_shape().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), receipt);
    receipt["keypackage_refs"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<KeyPackageClaimTerminalReceipt>(receipt.clone()).is_err());
    receipt["keypackage_refs"] = json!(["ak:mls:keypackage:test-01"]);
    assert!(
        serde_json::from_value::<KeyPackageClaimTerminalReceipt>(receipt.clone())
            .unwrap()
            .validate_shape()
            .is_err()
    );
    receipt["terminal_state"] = json!("expired");
    serde_json::from_value::<KeyPackageClaimTerminalReceipt>(receipt)
        .unwrap()
        .validate_shape()
        .unwrap();
}

#[test]
fn keypackage_upload_identity_matches_registered_schema_and_precedes_signing() {
    use arkret_models_crypto::{KeyPackageUploadEntry, KeyPackagesUploadUnsignedRequest};
    let fixture = arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap();
    let unsigned = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "upload_batch_required_fields")
        .unwrap()["unsigned_request"]
        .clone();
    let entry = unsigned["keypackages"][0].clone();
    let mut registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
        .unwrap()
        .expect("this conformance test requires the formal spec checkout");
    let schema =
        arkret_schema_conformance::spec_json_artifact("schemas/keypackage-operations.schema.json")
            .unwrap();
    registry
        .register_fragment(
            "test:mls_keypackage_entry",
            schema,
            "#/$defs/keypackage_upload_entry",
        )
        .unwrap();
    registry
        .validate_value("test:mls_keypackage_entry", &entry)
        .unwrap();
    let original: KeyPackagesUploadUnsignedRequest = serde_json::from_value(unsigned).unwrap();
    assert!(arkret_models_crypto::keypackages_upload_signing_input(&original).is_ok());
    for invalid in [
        "opaque-package",
        "ak:mls:kp:",
        "ak:mls:kp:01964137-0000-4000-8000-000000000001",
        "ak:mls:kp:01964137-0000-7000-7000-000000000001",
        "ak:mls:kp:01964137-0000-7000-c000-000000000001",
        "ak:mls:kp:01964137-0000-7000-8000-00000000000A",
        "ak:mls:kp:01964137-0000-7000-8000-000000000001x",
        "ak:mls:kp:01964137000070008000000000000001",
    ] {
        let mut wire = entry.clone();
        wire["keypackage_id"] = json!(invalid);
        assert!(
            registry
                .validate_value("test:mls_keypackage_entry", &wire)
                .is_err(),
            "{invalid}"
        );
        assert!(
            serde_json::from_value::<KeyPackageUploadEntry>(wire).is_err(),
            "{invalid}"
        );
        let mut body = original.clone();
        body.keypackages[0].keypackage_id = invalid.to_owned();
        assert!(body.validate_shape().is_err(), "{invalid}");
        assert!(
            arkret_models_crypto::keypackages_upload_signing_input(&body).is_err(),
            "{invalid}"
        );
    }
    let mut duplicate = original;
    duplicate.keypackages.push(duplicate.keypackages[0].clone());
    assert!(duplicate.validate_shape().is_err());
    assert!(arkret_models_crypto::keypackages_upload_signing_input(&duplicate).is_err());
    assert!(
        serde_json::from_value::<KeyPackagesUploadUnsignedRequest>(
            serde_json::to_value(duplicate).unwrap()
        )
        .is_err()
    );
}
