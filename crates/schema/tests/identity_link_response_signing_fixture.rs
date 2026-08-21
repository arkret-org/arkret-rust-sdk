use arkret_canonical::{DigestSuite, canonical_json_bytes, digest};
use arkret_schema::embedded_json_artifact;
use serde_json::Value;

#[test]
fn identity_link_proof_binds_history_response_signing_key() {
    let fixture = embedded_json_artifact("fixtures/privacy-security-fixture.json").unwrap();
    let vector = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["vector_id"].as_str()
                == Some("ak.vector.identity_link.minimal_metadata_author_credential.v1")
        })
        .unwrap();
    let binding = &vector["base"]["history_response_signing_binding"];
    let preimage = hex::decode(
        binding["identity_link_proof_preimage_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(preimage.starts_with(b"ak.identity-link-v1\n"));
    assert_eq!(
        digest(DigestSuite::Sha256, &preimage),
        binding["identity_link_proof_payload_digest"]
            .as_str()
            .unwrap()
    );

    let identity_link_bytes = &preimage[b"ak.identity-link-v1\n".len()..];
    let identity_link: Value = serde_json::from_slice(identity_link_bytes).unwrap();
    assert_eq!(
        canonical_json_bytes(&identity_link).unwrap(),
        identity_link_bytes
    );
    for field in [
        "response_signing_verification_method",
        "response_signing_algorithm",
        "response_signing_public_key_b64u",
        "response_signing_public_key_digest",
    ] {
        assert_eq!(identity_link[field], binding[field]);
    }

    let key = arkret_canonical::base64url_decode(
        binding["response_signing_public_key_b64u"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(
        digest(DigestSuite::Sha256, key),
        binding["response_signing_public_key_digest"]
            .as_str()
            .unwrap()
    );

    let mut mutated = identity_link;
    mutated["response_signing_public_key_b64u"] =
        Value::String("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned());
    let mut mutated_preimage = b"ak.identity-link-v1\n".to_vec();
    mutated_preimage.extend(canonical_json_bytes(&mutated).unwrap());
    assert_ne!(
        digest(DigestSuite::Sha256, mutated_preimage),
        binding["identity_link_proof_payload_digest"]
            .as_str()
            .unwrap()
    );
}
