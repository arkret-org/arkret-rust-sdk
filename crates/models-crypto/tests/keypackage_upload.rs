use arkret_models_crypto::{
    KeyPackagesUploadRequestBody, KeyPackagesUploadUnsignedRequest,
    keypackages_upload_signing_input,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};
use serde_json::{Value, json};

fn fixture() -> Value {
    arkret_schema_conformance::spec_json_artifact(
        "fixtures/keypackage-write-transcript-fixture.json",
    )
    .unwrap()
}

fn signed_device() -> Value {
    let fixture = fixture();
    let mut body = fixture["cases"][0]["unsigned_request"].clone();
    body["endpoint_signature"] = json!({
        "kid": fixture["test_key"]["kid"],
        "signature_algorithm": "Ed25519",
        "sig": fixture["cases"][0]["signature"],
    });
    body
}

#[test]
fn upload_matches_spec_jcs_bytes_and_signature_kat() {
    let fixture = fixture();
    let unsigned: KeyPackagesUploadUnsignedRequest =
        serde_json::from_value(fixture["cases"][0]["unsigned_request"].clone()).unwrap();
    let input = keypackages_upload_signing_input(&unsigned).unwrap();
    assert_eq!(
        arkret_canonical::base64url_encode(&input),
        fixture["cases"][0]["signing_input_base64url"]
    );
    let seed: [u8; 32] = arkret_canonical::base64url_decode(
        fixture["test_key"]["private_key_seed"].as_str().unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    assert_eq!(
        arkret_canonical::base64url_encode(SigningKey::from_bytes(&seed).sign(&input).to_bytes()),
        fixture["cases"][0]["signature"]
    );
    let signed: KeyPackagesUploadRequestBody = serde_json::from_value(signed_device()).unwrap();
    assert_eq!(
        serde_json::to_value(signed.unsigned()).unwrap(),
        fixture["cases"][0]["unsigned_request"]
    );
}

#[test]
fn upload_accepts_only_closed_human_and_agent_branches() {
    let human = signed_device();
    let mut agent = human.clone();
    agent.as_object_mut().unwrap().remove("device_id");
    agent["agent_verification_method"] = agent["endpoint_signature"]["kid"].clone();
    agent["agent_key_authorize_event_id"] =
        json!("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM");
    for valid in [human.clone(), agent.clone()] {
        let parsed: KeyPackagesUploadRequestBody = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), valid);
        for field in [
            "pairwise_verification_method",
            "intended_realm_id",
            "unknown",
        ] {
            for value in [Value::Null, json!("non-null")] {
                let mut invalid = valid.clone();
                invalid[field] = value;
                assert!(
                    serde_json::from_value::<KeyPackagesUploadRequestBody>(invalid.clone())
                        .is_err(),
                    "{field}"
                );
                invalid
                    .as_object_mut()
                    .unwrap()
                    .remove("endpoint_signature");
                assert!(
                    serde_json::from_value::<KeyPackagesUploadUnsignedRequest>(invalid).is_err(),
                    "{field}"
                );
            }
        }
    }
    let mut mixed = agent.clone();
    mixed["device_id"] = human["device_id"].clone();
    assert!(serde_json::from_value::<KeyPackagesUploadRequestBody>(mixed).is_err());
    for missing in ["agent_verification_method", "agent_key_authorize_event_id"] {
        let mut incomplete = agent.clone();
        incomplete.as_object_mut().unwrap().remove(missing);
        assert!(serde_json::from_value::<KeyPackagesUploadRequestBody>(incomplete).is_err());
    }
    let mut missing = human.clone();
    missing.as_object_mut().unwrap().remove("device_id");
    assert!(serde_json::from_value::<KeyPackagesUploadRequestBody>(missing).is_err());
    let mut wrong_kid = agent;
    wrong_kid["endpoint_signature"]["kid"] = json!("did:web:another.example#key");
    assert!(serde_json::from_value::<KeyPackagesUploadRequestBody>(wrong_kid).is_err());
    let mut empty = human.clone();
    empty["keypackages"] = json!([]);
    assert!(serde_json::from_value::<KeyPackagesUploadRequestBody>(empty).is_err());
    for field in [
        "device_id",
        "agent_verification_method",
        "agent_key_authorize_event_id",
        "expires_at",
        "strand_id",
        "mls_group_id",
        "endpoint_signature",
    ] {
        let mut null = human.clone();
        null[field] = Value::Null;
        assert!(
            serde_json::from_value::<KeyPackagesUploadRequestBody>(null).is_err(),
            "{field}"
        );
    }
    let mut null = human;
    null["keypackages"][0]["last_resort"] = Value::Null;
    assert!(serde_json::from_value::<KeyPackagesUploadRequestBody>(null).is_err());
}

#[test]
fn every_present_optional_and_entry_order_is_covered_by_the_batch_signature() {
    let mut full = fixture()["cases"][0]["unsigned_request"].clone();
    full["expires_at"] = json!("2026-07-29T00:00:00.000Z");
    full["strand_id"] = json!("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7");
    full["mls_group_id"] = json!("_eWozxgdBxDHaOyjY_q0ZstYlzkfbmcnpTqLf9g2aDQ");
    let mut second = full["keypackages"][0].clone();
    second["keypackage_id"] = json!("ak:mls:kp:01964137-0000-7000-8000-00000000000e");
    second["last_resort"] = json!(true);
    full["keypackages"].as_array_mut().unwrap().push(second);
    let original: KeyPackagesUploadUnsignedRequest = serde_json::from_value(full.clone()).unwrap();
    let input = keypackages_upload_signing_input(&original).unwrap();
    let key = SigningKey::from_bytes(&[93; 32]);
    let signature: Signature = key.sign(&input);
    key.verifying_key().verify(&input, &signature).unwrap();
    let mut mutations = Vec::new();
    for field in ["expires_at", "strand_id", "mls_group_id"] {
        let mut omitted = full.clone();
        omitted.as_object_mut().unwrap().remove(field);
        mutations.push(omitted);
    }
    let mut omitted = full.clone();
    omitted["keypackages"][1]
        .as_object_mut()
        .unwrap()
        .remove("last_resort");
    mutations.push(omitted);
    let mut reversed = full.clone();
    reversed["keypackages"].as_array_mut().unwrap().reverse();
    mutations.push(reversed);
    let mut truncated = full.clone();
    truncated["keypackages"].as_array_mut().unwrap().pop();
    mutations.push(truncated);
    let mut station = full.clone();
    station["actor_id"]["account_id"]["station_id"] = json!("ak:did_core:web:another.example");
    mutations.push(station);
    for mutation in mutations {
        let parsed: KeyPackagesUploadUnsignedRequest = serde_json::from_value(mutation).unwrap();
        assert!(
            key.verifying_key()
                .verify(
                    &keypackages_upload_signing_input(&parsed).unwrap(),
                    &signature
                )
                .is_err()
        );
    }
    let body = original.into_signed(
        serde_json::from_value(signed_device()["endpoint_signature"].clone()).unwrap(),
    );
    let mut raw = serde_json::to_value(body).unwrap();
    raw.as_object_mut().unwrap().remove("endpoint_signature");
    assert_eq!(raw, full);
}

#[test]
fn invalid_constructed_unsigned_request_cannot_be_signed() {
    let mut unsigned: KeyPackagesUploadUnsignedRequest =
        serde_json::from_value(fixture()["cases"][0]["unsigned_request"].clone()).unwrap();
    unsigned.device_id = None;
    assert!(keypackages_upload_signing_input(&unsigned).is_err());
}
