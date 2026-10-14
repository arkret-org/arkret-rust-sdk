use arkret_models_collaboration::objects::blob::SignatureValue;

#[test]
fn upload_receipt_signature_identifies_a_did_verification_method() {
    let value = serde_json::json!({
        "kid": "did:web:station.example#notary-key",
        "signature_algorithm": "Ed25519",
        "sig": "AQ",
    });
    let signature: SignatureValue = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(signature).unwrap(), value);

    let mut core_identity = value;
    core_identity["kid"] = serde_json::json!("ak:did_core:web:station.example");
    assert!(serde_json::from_value::<SignatureValue>(core_identity).is_err());
}
