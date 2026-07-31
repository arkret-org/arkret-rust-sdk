#[test]
fn payload_signature_extra_is_lossless_and_absent_by_default() {
    use arkret_wire::PayloadSignature;
    let plain = r#"{"verification_method":"did:web:a.example#k","alg":"EdDSA","payload_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","created_at":"2026-06-11T00:00:00.000Z","jws":"a.b.c"}"#;
    let parsed: PayloadSignature = serde_json::from_str(plain).unwrap();
    assert!(parsed.extra.is_empty());
    assert_eq!(serde_json::to_string(&parsed).unwrap(), plain);

    // `seal.schema.json#/$defs/signature` is `additionalProperties: true`;
    // unknown members must survive a round trip so canonical bytes are stable.
    let with_extra = r#"{"verification_method":"did:web:a.example#k","alg":"EdDSA","payload_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","created_at":"2026-06-11T00:00:00.000Z","jws":"a.b.c","x_vendor":42}"#;
    let parsed: PayloadSignature = serde_json::from_str(with_extra).unwrap();
    assert_eq!(parsed.extra.len(), 1);
    let round = serde_json::to_value(&parsed).unwrap();
    assert_eq!(round["x_vendor"], serde_json::json!(42));
}
