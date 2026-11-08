use arkret_models_crypto::{
    KeysBackupsIssueUnlockChallengeRequestBody, KeysBackupsUnlockChallenge,
};
use arkret_schema_conformance::spec_json_artifact;
use serde_json::json;

#[test]
fn root_keybag_preserves_registered_extensions_and_rejects_other_unknown_members() {
    use arkret_models_crypto::KeyBackupPlaintext;
    let fixture = spec_json_artifact("fixtures/content-history-fixture.json").unwrap();
    let original = fixture["root_backup"]["plaintext"].clone();
    let mut extended = original.clone();
    extended["x_vendor"] = json!({"nested": [1, true, "opaque"]});
    let decoded: KeyBackupPlaintext = serde_json::from_value(extended.clone()).unwrap();
    let contents = decoded
        .items
        .iter()
        .map(|item| item.content_index())
        .collect::<Vec<_>>();
    decoded.validate_against(&contents).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), extended);
    for name in ["unknown", "x_Vendor", "x_", "x_vendor-extra"] {
        let mut invalid = original.clone();
        invalid[name] = json!(true);
        assert!(
            serde_json::from_value::<KeyBackupPlaintext>(invalid).is_err(),
            "{name}"
        );
    }
}

#[test]
fn current_device_challenge_binds_history_selection_and_freshness_exactly() {
    let fixture = spec_json_artifact("fixtures/content-history-fixture.json").unwrap();
    let backup = &fixture["root_backup"]["envelope"];
    let actor = &fixture["kat"]["content_context"]["producer"]["actor_id"];
    let history = json!({"source":fixture["hpke_grant"]["grant"]["history_cut"],
        "root_refs":[fixture["kat"]["content_context"]["root_ref"]]});
    let request: KeysBackupsIssueUnlockChallengeRequestBody = serde_json::from_value(json!({
        "request_id":"AAAAAAAAAAAAAAAAAAAAAA", "content_history":history,
    }))
    .unwrap();
    let challenge: KeysBackupsUnlockChallenge = serde_json::from_value(json!({
        "challenge_id":"AAAAAAAAAAAAAAAAAAAAAA", "challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nonce":"AAAAAAAAAAAAAAAAAAAAAA",
        "operation":arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1,
        "account_id":actor["account_id"],
        "requesting_device_id":"ak:device:019a0000-0000-7000-8000-000000000099",
        "backup_id":backup["backup_id"], "series_id":backup["series_id"], "ciphertext_digest":backup["ciphertext_digest"],
        "audience":"https://station.example", "service_id":actor["account_id"]["station_id"],
        "request_id":request.request_id, "issued_at":"2026-11-08T00:00:00.000Z", "expires_at":"2026-11-08T00:05:00.000Z",
        "content_history":history,
    })).unwrap();
    challenge
        .validate_for_request(&request, &challenge.backup_id)
        .unwrap();
    let mut changed = request.clone();
    changed.content_history = None;
    assert!(
        challenge
            .validate_for_request(&changed, &challenge.backup_id)
            .is_err()
    );
    changed = request.clone();
    changed.content_history.as_mut().unwrap().root_refs[0] =
        arkret_wire::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap();
    assert!(
        challenge
            .validate_for_request(&changed, &challenge.backup_id)
            .is_err()
    );
    let mut expired = challenge.clone();
    expired.expires_at += chrono::Duration::seconds(1);
    assert!(
        expired
            .validate_for_request(&request, &challenge.backup_id)
            .is_err()
    );
    changed.subject_actor_id = Some(serde_json::from_value(actor.clone()).unwrap());
    assert!(changed.validate().is_err());
}
