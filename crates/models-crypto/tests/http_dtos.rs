use arkret_models_crypto::http_bodies::KeyPackagesClaimOutcome;
use arkret_wire::DidCoreId;
use serde_json::json;

fn did(_name: &str) -> DidCoreId {
    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
}

#[test]
fn keypackages_claim_outcome_uses_typed_records_and_failures() {
    let outcome = json!({
        "claims": [{
            "claim_id": "ak:mls_keypackage:t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "key_package": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "device_signature": {
                "kid": "did:webvh:z6mkfixture:alice.example#ak:device:01904100-0000-7000-8000-000000000001",
                "signature_algorithm": "Ed25519",
                "sig": "c2ln"
            },
            "revocation_status": "active"
        }],
        "claim_receipt": {
            "operation_id": "ak.self.keys.keypackages.command.claim",
            "claim_request_id": "Y2xhaW0tbm9uY2U",
            "request_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "claims_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "source_service_id": "ak:did_core:webvh:z6mkfixtureservice",
            "destination_service_id": "ak:did_core:webvh:z6mkfixtureservice",
            "request": {
                "target_principal_id": "ak:did_core:webvh:z6mkfixture",
                "intended_realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "requester": "ak:did_core:webvh:z6mkfixture",
                "required_capabilities": ["ak.mls.profile.full"],
                "claim_nonce": "Y2xhaW0tbm9uY2U",
                "expires_at": "2099-01-01T00:00:00.000Z",
                "holder_acceptance_proof": {
                    "kind": "detached_jws",
                    "verification_method": "did:webvh:z6mkfixture:alice.example#key-1",
                    "payload_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "created_at": "2098-12-31T23:59:00.000Z",
                    "audience": "ak:did_core:webvh:z6mkfixtureservice",
                    "proof_purpose": "holder_acceptance",
                    "jws": "a..b"
                }
            },
            "claimed_at": "2098-12-31T23:59:30.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z",
            "signature": {
                "kid": "did:webvh:z6mkfixtureservice:service.example#key-1",
                "signature_algorithm": "Ed25519",
                "sig": "c2ln"
            }
        },
        "failures": [{
            "keypackage_ref": "ak:mls:keypackage:missing",
            "reason_code": "not_found"
        }],
        "available_count": 1
    });
    let parsed: KeyPackagesClaimOutcome = serde_json::from_value(outcome).unwrap();
    assert_eq!(parsed.claims[0].principal_id, did("alice"));
    assert!(parsed.claims[0].device_authorize_event_id.is_some());
    assert_eq!(parsed.failures[0].reason_code.as_str(), "not_found");

    let malformed_claim = json!({
        "claims": [{
            "claim_id": "ak:mls_keypackage:t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "key_package": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "device_signature": {"kid": "did:webvh:z6mkfixture:alice.example#device", "sig": "c2ln"},
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
