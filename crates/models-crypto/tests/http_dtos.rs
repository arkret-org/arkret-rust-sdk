use arkret_models_crypto::http_bodies::KeyPackagesClaimOutcome;
use arkret_wire::Did;
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
}

#[test]
fn keypackages_claim_outcome_uses_typed_records_and_failures() {
    let outcome = json!({
        "claims": [{
            "claim_id": "ak:mls_keypackage:t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "key_package": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ssk_generation": 3,
            "expires_at": "2100-01-01T00:00:00.000Z",
            "device_signature": {
                "kid": "did:webvh:z6mkfixture:alice.example#ak:device:01904100-0000-7000-8000-000000000001",
                "alg": "EdDSA",
                "sig": "c2ln"
            },
            "revocation_status": "active"
        }],
        "failures": [{
            "keypackage_ref": "ak:mls:keypackage:missing",
            "reason_code": "not_found"
        }],
        "available_count": 1
    });
    let parsed: KeyPackagesClaimOutcome = serde_json::from_value(outcome).unwrap();
    assert_eq!(parsed.claims[0].principal_id, did("alice"));
    assert_eq!(parsed.claims[0].ssk_generation, Some(3));
    assert_eq!(parsed.claims[0].device_authorize_event_id, None);
    assert_eq!(parsed.failures[0].reason_code, "not_found");

    let malformed_claim = json!({
        "claims": [{
            "claim_id": "ak:mls_keypackage:t-01:Y2xhaW0tbm9uY2U",
            "keypackage_ref": "ak:mls:keypackage:test-01",
            "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "key_package": "AQID",
            "capabilities": ["ak.mls.profile.full"],
            "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ssk_generation": 3,
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
