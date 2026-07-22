use arkret_canonical::{base64url, canonical};
use arkret_models_crypto::EncryptedPayload;
use arkret_schema::embedded_json_artifact;

fn encoding_vector(vector_id: &str) -> serde_json::Value {
    let fixture = embedded_json_artifact("fixtures/encoding-fixture.json").unwrap();
    fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["vector_id"] == vector_id)
        .unwrap_or_else(|| panic!("encoding fixture missing {vector_id}"))
        .clone()
}

#[test]
fn encrypted_envelope_digest_matches_spec_encoding_vector() {
    let vector = encoding_vector("ak.vector.encoding.encrypted_envelope_digest.v1");
    let metadata = &vector["payload_metadata"];

    let metadata_bytes = canonical::canonical_json_bytes(metadata).unwrap();
    assert_eq!(
        std::str::from_utf8(&metadata_bytes).unwrap(),
        vector["expected_metadata_canonical_bytes_utf8"]
            .as_str()
            .unwrap()
    );

    let ciphertext =
        base64url::base64url_decode(vector["ciphertext_base64url"].as_str().unwrap()).unwrap();
    assert_eq!(
        ciphertext,
        vector["ciphertext_bytes_utf8"].as_str().unwrap().as_bytes()
    );

    let mut digest_input = metadata_bytes;
    digest_input.extend_from_slice(&ciphertext);
    assert_eq!(
        canonical::sha256_digest(&digest_input),
        vector["expected_digest"].as_str().unwrap()
    );
    assert_eq!(
        canonical::canonical_sha256(&metadata["aad"]).unwrap(),
        vector["aad_digest"].as_str().unwrap()
    );
}

#[test]
fn mls_payload_digest_regression_anchor() {
    let digest = EncryptedPayload::mls_payload_digest(
        7,
        "application/json",
        None,
        b"ciphertext-example-001",
    )
    .unwrap();

    assert_eq!(
        digest.as_str(),
        "sha256:3bef5270548d5b2c14e46ac1c9a801376d243ca6d71b914ec1d3283268a981fa"
    );
}
