use arkret_canonical::{base64url, canonical};
use arkret_models_crypto::{
    EncryptedEnvelope, MlsCommitEnvelope, MlsCommitPayload, MlsGovernanceBindingPayload,
};
use arkret_schema_conformance::{event_payload_validator_catalog, spec_json_artifact};
use arkret_wire::{EventId, Hash, ProfileId, RealmId};

fn encoding_vector(vector_id: &str) -> serde_json::Value {
    let fixture = spec_json_artifact("fixtures/encoding-fixture.json").unwrap();
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
    let mut envelope = metadata.clone();
    envelope["ciphertext"] = vector["ciphertext_base64url"].clone();
    let envelope: EncryptedEnvelope = serde_json::from_value(envelope).unwrap();
    assert_eq!(
        envelope.payload_digest().unwrap().as_str(),
        vector["expected_digest"].as_str().unwrap()
    );
}

#[test]
fn mls_commit_payload_matches_registered_event_schema() {
    fn event(n: u8) -> EventId {
        EventId::from_event_digest(&Hash::new(arkret_canonical::sha256_digest([n])).unwrap())
            .unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    let group_id = base64url::base64url_encode(b"arkret-mls-test-group");
    let binding = MlsGovernanceBindingPayload::realm(
        RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
        group_id.clone(),
        0,
        1,
        hash('2'),
        arkret_wire::ContentScheme::MlsRfc9420,
        None,
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
    assert!(value.get("commit_digest").is_none());
    let mut tampered = value;
    tampered["commit_digest"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));
    let error = serde_json::from_value::<MlsCommitPayload>(tampered).unwrap_err();
    assert!(error.to_string().contains("unknown field `commit_digest`"));
}
