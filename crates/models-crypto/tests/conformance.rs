use arkret_canonical::{base64url, canonical};
use arkret_models_crypto::{
    EncryptedEnvelope, MAX_EVENT_CONTENT_INTEGER, MlsCommitEnvelope, MlsCommitPayload,
    MlsGovernanceBindingPayload,
};
use arkret_schema_conformance::{event_payload_validator_catalog, spec_json_artifact};
use arkret_wire::{EncryptedPayloadScheme, EventId, Hash, ProfileId, RealmId, ScopeRef};

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
fn encrypted_envelope_wire_preserves_scheme_branch_and_canonical_range_counter() {
    for counter in [None, Some(0), Some(1), Some(MAX_EVENT_CONTENT_INTEGER)] {
        let mut wire = encrypted_envelope_wire();
        if let Some(counter) = counter {
            wire["encryption_context"]["counter"] = counter.into();
        }
        let decoded: EncryptedEnvelope = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(decoded.encryption_context.counter(), counter);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), wire);
        let scope = ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")
                .unwrap(),
        };
        let scheme = if counter.is_some() {
            EncryptedPayloadScheme::MlsExporterAeadV1
        } else {
            EncryptedPayloadScheme::MlsRfc9420
        };
        let header = decoded
            .reconstruct_pre_encryption_header(
                scheme,
                scope,
                "ak.strand.update",
                "sender.example",
                None,
            )
            .unwrap();
        assert_eq!(header.counter, counter);
    }
}

#[test]
fn encrypted_envelope_invalid_counter_cannot_fall_back_to_standard_mls() {
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!("0"),
        serde_json::json!(-1),
        serde_json::json!(0.5),
        // encoding.md section 1 bounds canonical JSON integers; a counter
        // past that bound is not a wider counter, it is an invalid envelope.
        serde_json::json!(MAX_EVENT_CONTENT_INTEGER + 1),
    ] {
        let mut wire = encrypted_envelope_wire();
        wire["encryption_context"]["counter"] = invalid;
        assert!(serde_json::from_value::<EncryptedEnvelope>(wire).is_err());
    }
    for counter in [None, Some(0)] {
        let mut wire = encrypted_envelope_wire();
        if let Some(counter) = counter {
            wire["encryption_context"]["counter"] = counter.into();
        }
        wire["encryption_context"]["unknown"] = true.into();
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
