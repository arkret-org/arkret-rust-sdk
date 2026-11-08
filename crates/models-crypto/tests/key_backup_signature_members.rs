use arkret_models_crypto::KeyBackup;
use arkret_schema_conformance::{schema_registry_from_spec_artifacts, spec_json_artifact};
use serde_json::{Value, json};

fn envelope() -> Value {
    spec_json_artifact("fixtures/content-history-fixture.json").unwrap()["root_backup"]["envelope"]
        .clone()
}

fn schema_accepts(value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema = spec_json_artifact("schemas/key-backup.schema.json").unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment("test:backup-signature-members", schema, "#")
        .unwrap();
    registry
        .validate_value("test:backup-signature-members", value)
        .is_ok()
}

#[test]
fn every_present_false_or_null_member_remains_in_the_exact_signed_envelope() {
    let mut wire = envelope();
    wire["mixed_secret_storage"] = json!(false);
    wire["expires_at"] = Value::Null;
    wire["updated_at"] = wire["created_at"].clone();
    wire["retention"] = json!({"deletion_eligible_at":null,"legal_hold":false});
    assert!(schema_accepts(&wire));
    let decoded: KeyBackup = serde_json::from_value(wire.clone()).unwrap();
    decoded.validate().unwrap();
    assert!(
        serde_json::to_value(&decoded).unwrap() == wire,
        "present signed members were lost"
    );
    wire["signature_proof"]
        .as_object_mut()
        .unwrap()
        .remove("signature");
    assert!(
        decoded.signing_payload_bytes().unwrap()
            == arkret_canonical::canonical_json_bytes(&wire).unwrap(),
        "signature transcript changed its member set"
    );
}

#[test]
fn absence_and_present_false_or_null_have_different_signature_transcripts() {
    let original = envelope();
    let base: KeyBackup = serde_json::from_value(original.clone()).unwrap();
    let base = base.signing_payload_bytes().unwrap();
    for (member, value) in [
        ("mixed_secret_storage", json!(false)),
        ("expires_at", Value::Null),
        ("expires_at", json!("2027-11-08T00:00:00.000Z")),
        ("retention", json!({"deletion_eligible_at":null})),
        (
            "retention",
            json!({"deletion_eligible_at":"2027-11-08T00:00:00.000Z"}),
        ),
    ] {
        let mut changed = original.clone();
        changed[member] = value;
        assert!(schema_accepts(&changed));
        let decoded: KeyBackup = serde_json::from_value(changed).unwrap();
        assert!(base != decoded.signing_payload_bytes().unwrap(), "{member}");
    }
}

#[test]
fn nonnullable_optional_members_reject_explicit_null_before_signature_verification() {
    for pointer in [
        "/device_id",
        "/mixed_secret_storage",
        "/updated_at",
        "/plaintext_commitment",
        "/retention",
        "/retention/legal_hold",
        "/source_commit_ref",
        "/recovery_policy_ref",
        "/encryption/hpke_suite",
        "/encryption/recipient_key_ref",
        "/encryption/kdf",
        "/encryption/key_commitment",
        "/encryption/aead/aead_profile",
        "/encryption/aead/nonce",
        "/encryption/aead/nonce_salt",
        "/signature_proof/agent_authorization_event_ref",
    ] {
        let mut wire = envelope();
        wire["retention"] = json!({"legal_hold":false});
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        wire.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), Value::Null);
        assert!(!schema_accepts(&wire), "{pointer}");
        assert!(
            serde_json::from_value::<KeyBackup>(wire).is_err(),
            "{pointer}"
        );
    }
}
