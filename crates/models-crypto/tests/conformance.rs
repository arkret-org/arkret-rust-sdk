use arkret_canonical::{base64url, canonical};
use arkret_models_crypto::{
    EncryptedPayload, MlsCommitEnvelope, MlsCommitPayload, MlsGovernanceBindingPayload,
};
use arkret_schema::{embedded_json_artifact, event_payload_validator_catalog};
use arkret_wire::{EventId, Hash, ProfileId, RealmId};

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
        "sha256:ef078c8adf8433d7b3df36c58966acacbd53f8294d5223e9621d79b176644764"
    );
}

#[test]
fn mls_commit_payload_matches_registered_event_schema() {
    fn event(n: u8) -> EventId {
        EventId::new(format!("ak:event:0196419b-0000-7000-8000-00000000000{n}")).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    let group_id = base64url::base64url_encode(b"arkret-mls-test-group");
    let binding = MlsGovernanceBindingPayload::realm(
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000001").unwrap(),
        group_id.clone(),
        0,
        1,
        hash('2'),
        ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        arkret_wire::CORE_REDUCER_PROFILE,
    )
    .unwrap();
    let commit_bytes = b"canonical-commit";
    let commit = MlsCommitEnvelope {
        group_id,
        epoch: 1,
        commit: base64url::base64url_encode(commit_bytes),
        commit_digest: Hash::new(canonical::sha256_digest(commit_bytes)).unwrap(),
        ratchet_tree: None,
    };
    let payload =
        MlsCommitPayload::new(0, event(1).to_string(), Vec::new(), &commit, binding).unwrap();
    let value = serde_json::to_value(&payload).unwrap();

    event_payload_validator_catalog()
        .unwrap()
        .validate_payload(payload.event_kind(), &value)
        .unwrap();
    assert!(value.get("group_id").is_none());
    assert!(value.get("expected_prev_epoch").is_none());
    assert_eq!(
        value["commit_bytes_b64"],
        base64url::base64url_encode(commit_bytes)
    );
    let mut tampered = value;
    tampered["commit_digest"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));
    let error = serde_json::from_value::<MlsCommitPayload>(tampered).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("commit_digest does not match commit_bytes_b64")
    );
}
