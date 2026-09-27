use arkret_canonical::{base64url, canonical};
use arkret_models_crypto::{
    EncryptedEnvelope, MAX_EVENT_CONTENT_INTEGER, MlsCommitEnvelope, MlsCommitPayload,
    MlsGovernanceBindingPayload,
};
use arkret_schema_conformance::{event_payload_validator_catalog, spec_json_artifact};
use arkret_wire::{EncryptedPayloadScheme, EventId, Hash, RealmId, ScopeRef};

fn encrypted_envelope_wire() -> serde_json::Value {
    serde_json::json!({
        "version": "1.0",
        "content_type": "application/vnd.arkret.strand.patch-value+json",
        "encryption_context": {
            "epoch": 1,
            "group_state_ref": EventId::from_event_digest(
                &Hash::new(canonical::sha256_digest(b"winning-state")).unwrap()
            ).unwrap()
        },
        "ciphertext": "AA"
    })
}

#[test]
fn encrypted_envelope_wire_preserves_standard_mls_context() {
    let wire = encrypted_envelope_wire();
    let decoded: EncryptedEnvelope = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), wire);
    let scope = ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
    };
    decoded
        .reconstruct_pre_encryption_header(
            EncryptedPayloadScheme::MlsRfc9420,
            scope,
            "ak.strand.update",
            "sender.example",
            None,
        )
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn encrypted_envelope_exporter_counter_is_never_a_valid_context() {
    for counter in [
        serde_json::Value::Null,
        serde_json::json!(0),
        serde_json::json!(MAX_EVENT_CONTENT_INTEGER),
        serde_json::json!("0"),
        serde_json::json!(-1),
        serde_json::json!(0.5),
        serde_json::json!(MAX_EVENT_CONTENT_INTEGER + 1),
    ] {
        let mut wire = encrypted_envelope_wire();
        wire["encryption_context"]["counter"] = counter;
        assert!(serde_json::from_value::<EncryptedEnvelope>(wire).is_err());
    }
}

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

    let base = event(1);
    let binding = MlsGovernanceBindingPayload::realm(
        RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
        Some(base.clone()),
        0,
        1,
        0,
    )
    .unwrap();
    let commit_bytes = b"canonical-commit";
    let commit = MlsCommitEnvelope {
        group_id: binding.mls_group_id().unwrap(),
        epoch: 1,
        commit: base64url::base64url_encode(commit_bytes),
        commit_digest: Hash::new(canonical::sha256_digest(commit_bytes)).unwrap(),
        ratchet_tree: None,
    };
    let payload = MlsCommitPayload::new(base, 0, &commit, binding).unwrap();
    let value = serde_json::to_value(&payload).unwrap();

    event_payload_validator_catalog()
        .unwrap()
        .validate_payload(payload.event_kind(), &value)
        .unwrap();
    assert!(value.get("group_id").is_none());
    assert!(value.get("expected_prev_epoch").is_none());
    assert_eq!(value["previous_epoch"], 0);
    assert_eq!(value["next_epoch"], 1);
    assert_eq!(value["covers_key_access_revision"], 0);
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
