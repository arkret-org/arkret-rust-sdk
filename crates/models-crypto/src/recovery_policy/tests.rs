use serde_json::json;

use super::{fixtures, *};

#[test]
fn recovery_policy_round_trips_and_keeps_null_supersedes() {
    let value = fixtures::policy();
    let parsed: RecoveryPolicy = serde_json::from_value(value.clone()).expect("closed policy");
    parsed.validate_shape().expect("valid policy");
    assert!(parsed.supersedes_id.is_none());
    assert!(!parsed.revokes_recovery());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
}

#[test]
fn recovery_policy_rejects_missing_required_members() {
    for member in [
        "schema",
        "policy_id",
        "account_id",
        "signature_proof",
        "methods",
    ] {
        let mut missing = fixtures::policy();
        missing.as_object_mut().unwrap().remove(member);
        assert!(
            serde_json::from_value::<RecoveryPolicy>(missing).is_err(),
            "{member} is a required policy member"
        );
    }
}

#[test]
fn genesis_policy_serializes_its_null_predecessor() {
    let parsed: RecoveryPolicy = serde_json::from_value(fixtures::policy()).expect("closed policy");
    let encoded = serde_json::to_value(&parsed).unwrap();
    assert_eq!(encoded["supersedes_id"], serde_json::Value::Null);
    assert!(encoded.as_object().unwrap().contains_key("supersedes_id"));
}

#[test]
fn recovery_policy_extension_members_stay_in_the_x_map() {
    let mut value = fixtures::policy();
    value
        .as_object_mut()
        .unwrap()
        .insert("x_deployment_note".to_owned(), json!("staged"));
    let parsed: RecoveryPolicy = serde_json::from_value(value.clone()).expect("x_ extension");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
}

#[test]
fn recovery_policy_signature_transcript_matches_the_formal_known_answer() {
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

    let mut value = fixtures::policy();
    value["methods"] = json!([]);
    value
        .as_object_mut()
        .unwrap()
        .insert("cooldown_seconds".to_owned(), json!(0));
    value
        .as_object_mut()
        .unwrap()
        .insert("x_deployment_note".to_owned(), json!("covered"));
    let policy: RecoveryPolicy = serde_json::from_value(value).unwrap();
    let transcript = recovery_policy_signature_transcript_bytes(&policy).unwrap();
    assert_eq!(
        String::from_utf8(transcript.clone()).unwrap(),
        concat!(
            "ak.identity.recovery_policy.signature.v1\n",
            "{\"account_id\":{\"principal_id\":\"ak:did_core:webvh:z6mkfixture:alice.example\",",
            "\"station_id\":\"ak:did_core:web:station.example\"},\"cooldown_seconds\":0,",
            "\"issued_at\":\"2026-08-01T00:00:00.000Z\",\"methods\":[],",
            "\"policy_id\":\"ak:policy:0198ff00-0000-7000-8000-000000000001\",",
            "\"schema\":\"ak.schema.recovery_policy.v1\",\"supersedes_id\":null,",
            "\"trust_domain\":\"ak:trust_domain:example.net\",\"version\":1,",
            "\"x_deployment_note\":\"covered\"}"
        )
    );

    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let signature = signing_key.sign(&transcript);
    assert_eq!(
        arkret_canonical::base64url_encode(signature.to_bytes()),
        "wx6-ox_ks4tQQj3sXRRMwQYZmbFIXne2C-UhfGEf3sOQW7Ex8jBfzbzNoxtwjSDgJdhsrOuY2fN1QbQDF8R_Bw"
    );
    signing_key
        .verifying_key()
        .verify(&transcript, &signature)
        .unwrap();

    let mut changed_auth = policy.clone();
    changed_auth.signature_proof.verification_method =
        DidUrl::new("did:web:ignored.example#other".to_owned()).unwrap();
    changed_auth.signature_proof.signature = Base64UrlString::new("aGVsbG8").unwrap();
    assert_eq!(
        recovery_policy_signature_transcript_bytes(&changed_auth).unwrap(),
        transcript,
        "the whole top-level signature_proof member is excluded"
    );

    let mut tampered = policy;
    tampered
        .extra
        .insert("x_deployment_note".to_owned(), json!("tampered"))
        .unwrap();
    let tampered_transcript = recovery_policy_signature_transcript_bytes(&tampered).unwrap();
    assert!(
        signing_key
            .verifying_key()
            .verify(&tampered_transcript, &signature)
            .is_err()
    );
}

#[test]
fn recovery_key_entry_is_closed() {
    let mut keys = fixtures::recovery_unlock_method();
    keys["keys"][0]
        .as_object_mut()
        .unwrap()
        .insert("or_set".to_owned(), json!(true));
    assert!(serde_json::from_value::<RecoveryMethod>(keys).is_err());

    let mut without_backup = fixtures::recovery_unlock_method();
    without_backup["keys"][0]
        .as_object_mut()
        .unwrap()
        .remove("backup_hpke");
    assert!(serde_json::from_value::<RecoveryMethod>(without_backup).is_err());
}

#[test]
fn device_quorum_min_device_count_cannot_exceed_its_member_count() {
    let method: RecoveryMethod = serde_json::from_value(json!({
        "kind": "device_quorum",
        "min_device_count": 3,
        "member_ids": [
            "ak:device:0198ff00-0000-7000-8000-00000000000a",
            "ak:device:0198ff00-0000-7000-8000-00000000000b"
        ]
    }))
    .expect("quorum shape");
    assert!(method.validate_shape().is_err());
}

#[test]
fn policy_rejects_repeated_method_kinds() {
    let mut value = fixtures::policy();
    value["methods"] = json!([
        fixtures::recovery_unlock_method(),
        fixtures::recovery_unlock_method()
    ]);
    let parsed: RecoveryPolicy = serde_json::from_value(value).expect("shape parses");
    assert!(parsed.validate_shape().is_err());
}

#[test]
fn set_payload_binds_its_policy_id() {
    let value = json!({"policy_id": fixtures::POLICY_ID, "value": fixtures::policy()});
    let parsed: RecoveryPolicySetPayload =
        serde_json::from_value(value.clone()).expect("closed payload");
    parsed.validate_shape().expect("bound payload");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("state".to_owned(), json!("active"));
    assert!(serde_json::from_value::<RecoveryPolicySetPayload>(unknown).is_err());

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("value");
    assert!(serde_json::from_value::<RecoveryPolicySetPayload>(missing).is_err());
}

fn summary_value() -> serde_json::Value {
    json!({
        "policy_id": fixtures::POLICY_ID,
        "account_id": fixtures::account_id(),
        "version": 1,
        "acceptance_basis_ref": RealmCommitId::from_digest([3; 32]),
        "trust_domain": fixtures::TRUST_DOMAIN,
        "issued_at": "2026-08-01T00:00:00.000Z",
        "methods": [fixtures::recovery_unlock_method()]
    })
}

#[test]
fn policy_summary_round_trips_and_is_closed() {
    let value = summary_value();
    let parsed: RecoveryPolicySummary =
        serde_json::from_value(value.clone()).expect("closed summary");
    parsed.validate_shape().expect("valid summary");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("cas_revision".to_owned(), json!(4));
    assert!(serde_json::from_value::<RecoveryPolicySummary>(unknown).is_err());

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("methods");
    assert!(serde_json::from_value::<RecoveryPolicySummary>(missing).is_err());
}

#[test]
fn active_outcome_absent_policy_forbids_a_policy_ref() {
    let value = json!({"active_policy": null});
    let parsed: RecoveryPolicyStatusView =
        serde_json::from_value(value.clone()).expect("closed outcome");
    parsed.validate_shape().expect("null read is a success");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let with_ref: RecoveryPolicyStatusView = serde_json::from_value(json!({
        "active_policy": null,
        "recovery_policy_ref": {"policy_id": fixtures::POLICY_ID, "policy_version": 1}
    }))
    .expect("shape parses");
    assert!(with_ref.validate_shape().is_err());

    let mut unknown = json!({"active_policy": null});
    unknown
        .as_object_mut()
        .unwrap()
        .insert("observed_frontier".to_owned(), json!([]));
    assert!(serde_json::from_value::<RecoveryPolicyStatusView>(unknown).is_err());
}

#[test]
fn authority_stream_head_is_closed_and_fully_optional() {
    let value = json!({});
    let parsed: RecoveryAuthorityStreamHead =
        serde_json::from_value(value.clone()).expect("closed head");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    assert!(
        serde_json::from_value::<RecoveryAuthorityStreamHead>(json!({"security_frontier": []}))
            .is_err()
    );
}

#[test]
fn publish_outcome_round_trips_and_is_closed() {
    let value = json!({
        "policy_id": fixtures::POLICY_ID,
        "account_id": fixtures::account_id(),
        "version": 2,
        "acceptance_basis_ref": RealmCommitId::from_digest([5; 32]),
        "accepted_at": "2026-08-02T00:00:00.000Z"
    });
    let parsed: RecoveryPolicyPublishResponseBody =
        serde_json::from_value(value.clone()).expect("closed outcome");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("accepted_frontier".to_owned(), json!([]));
    assert!(serde_json::from_value::<RecoveryPolicyPublishResponseBody>(unknown).is_err());

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("version");
    assert!(serde_json::from_value::<RecoveryPolicyPublishResponseBody>(missing).is_err());
}
