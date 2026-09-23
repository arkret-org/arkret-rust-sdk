use arkret_models_crypto::{KeyBackupUnlockProof, KeysBackupsDeleteChallenge};
use serde_json::{Value, json};

fn recovery_fixture() -> Value {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/key-backup-fixture.json").unwrap();
    fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "key_backup_unlock_proof_valid")
        .unwrap()["instance"]
        .clone()
}

#[test]
fn unlock_proof_roundtrips_both_closed_authority_branches() {
    let recovery = recovery_fixture();
    let mut current = recovery.clone();
    let object = current.as_object_mut().unwrap();
    object.remove("recovery_session_id");
    object.insert("kind".into(), "current_device".into());
    object.insert("challenge_id".into(), "AAAAAAAAAAAAAAAAAAAAAA".into());
    object.insert("nonce".into(), "BBBBBBBBBBBBBBBBBBBBBB".into());

    for input in [recovery, current] {
        let proof: KeyBackupUnlockProof = serde_json::from_value(input.clone()).unwrap();
        let encoded = serde_json::to_vec(&proof).unwrap();
        let restored: KeyBackupUnlockProof = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), input);
    }
}

#[test]
fn unlock_proof_rejects_unknown_and_cross_branch_fields() {
    let mut recovery = recovery_fixture();
    recovery["unexpected"] = Value::Bool(true);
    assert!(serde_json::from_value::<KeyBackupUnlockProof>(recovery).is_err());

    let mut recovery = recovery_fixture();
    recovery["nonce"] = Value::String("BBBBBBBBBBBBBBBBBBBBBB".into());
    assert!(serde_json::from_value::<KeyBackupUnlockProof>(recovery).is_err());

    let mut current = recovery_fixture();
    current["kind"] = Value::String("current_device".into());
    current["challenge_id"] = Value::String("AAAAAAAAAAAAAAAAAAAAAA".into());
    current["nonce"] = Value::String("BBBBBBBBBBBBBBBBBBBBBB".into());
    assert!(serde_json::from_value::<KeyBackupUnlockProof>(current).is_err());
}

#[test]
fn delete_intent_transcript_includes_exact_challenge_and_null_reason() {
    let challenge: KeysBackupsDeleteChallenge = serde_json::from_value(json!({
        "challenge_id": "AAAAAAAAAAAAAAAAAAAAAA",
        "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nonce": "BBBBBBBBBBBBBBBBBBBBBB",
        "operation": "ak.self.keys.backups.resource.delete.v1",
        "account_id": {
            "principal_id": "ak:did_core:web:alice.example",
            "station_id": "ak:did_core:web:station.example"
        },
        "backup_id": "ak:backup:01964137-1000-7000-8000-000000000001",
        "audience": "https://station.example",
        "service_id": "ak:did_core:web:station.example",
        "request_id": "CCCCCCCCCCCCCCCCCCCCCC",
        "issued_at": "2026-04-27T00:00:00.000Z",
        "expires_at": "2026-04-27T00:05:00.000Z"
    }))
    .unwrap();
    let transcript = challenge.delete_intent_transcript(None);
    assert_eq!(transcript["reason"], Value::Null);
    assert_eq!(transcript["context"], "ak.key_backup_delete_proof.v1");
    assert_eq!(transcript["issued_at"], "2026-04-27T00:00:00.000Z");
    let expected = arkret_canonical::canonical_sha256(&transcript).unwrap();
    assert_eq!(
        challenge.delete_intent_digest(None).unwrap().as_str(),
        expected
    );
    assert_ne!(
        challenge
            .delete_intent_digest(Some("user_requested"))
            .unwrap(),
        challenge.delete_intent_digest(None).unwrap()
    );
}
