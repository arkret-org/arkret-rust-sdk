use arkret_wire::ProtocolSignature;

fn signature(jws: &str) -> serde_json::Value {
    serde_json::json!({
        "verification_method": "did:web:station.example#assertion-1",
        "created_at": "2026-09-22T00:00:00.000Z",
        "jws": jws,
    })
}

#[test]
fn protocol_signature_requires_compact_detached_jws() {
    let parsed: ProtocolSignature = serde_json::from_value(signature(
        "eyJhbGciOiJFZDI1NTE5In0..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ))
    .unwrap();
    assert!(parsed.jws.contains(".."));

    assert!(serde_json::from_value::<ProtocolSignature>(signature("c2lnbmF0dXJl")).is_err());
    assert!(
        serde_json::from_value::<ProtocolSignature>(signature("header.payload.signature")).is_err()
    );
}
