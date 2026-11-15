use super::*;

fn fixture() -> serde_json::Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/detached-object-signature-kat-fixture.json",
    )
    .unwrap()["owner_transfer"]
        .clone()
}

#[test]
fn original_successor_signature_uses_the_registered_context_and_real_ed25519() {
    let sample = fixture();
    let intent = serde_json::from_value(sample["unsigned_projection"].clone()).unwrap();
    let acceptance = serde_json::from_value(sample["acceptance"].clone()).unwrap();
    let key = PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(sample["public_key_base64url"].as_str().unwrap())
            .unwrap(),
    };
    verify_realm_owner_transfer_acceptance(&intent, &acceptance, &key).unwrap();
    let wrong = PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(
            sample["outer_signer_basis"]["public_key_base64url"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    };
    assert!(verify_realm_owner_transfer_acceptance(&intent, &acceptance, &wrong).is_err());
    let mut changed = acceptance;
    changed.context = DetachedSignatureContext::RealmActorControlAcceptance;
    assert!(verify_realm_owner_transfer_acceptance(&intent, &changed, &key).is_err());
}

#[test]
fn signing_and_verification_share_the_finite_domain_without_resigning_the_event() {
    let sample = fixture();
    let intent: RealmOwnerTransferAcceptanceIntent =
        serde_json::from_value(sample["unsigned_projection"].clone()).unwrap();
    let original: DetachedObjectSignature =
        serde_json::from_value(sample["acceptance"].clone()).unwrap();
    let signing = SigningKey::from_bytes(&[103; 32]);
    // This proves the math helper only, not the native qualification of
    // this intentionally supplied test key as B's accepted Device.
    let signature = sign_realm_owner_transfer_acceptance(
        &intent,
        original.verification_method,
        original.created_at,
        &signing,
    )
    .unwrap();
    let key = PublicKeyMaterial::Ed25519Raw {
        bytes: signing.verifying_key().to_bytes().to_vec(),
    };
    verify_realm_owner_transfer_acceptance(&intent, &signature, &key).unwrap();
    let mut changed = intent;
    changed
        .payload_without_successor_acceptance
        .expected_state_digest =
        arkret_wire::Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
    assert!(verify_realm_owner_transfer_acceptance(&changed, &signature, &key).is_err());
}
