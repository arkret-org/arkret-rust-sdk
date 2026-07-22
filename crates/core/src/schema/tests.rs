#![allow(unused_qualifications)]

use std::fs;

use serde_json::Value;

use crate::schema::*;

fn fixture_artifact(name: &str) -> Value {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        let path = artifacts_dir.join("fixtures").join(name);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
    } else {
        embedded_json_artifact(&format!("fixtures/{name}")).unwrap()
    }
}

#[test]
fn applet_registration_epoch_fixture_executes_against_sdk() {
    use crate::applet::AppletRegistrationEpochTranscript;

    let fixture = fixture_artifact("applet-registration-epoch-fixture.json");
    let positive = &fixture["positive"];
    let transcript: AppletRegistrationEpochTranscript =
        serde_json::from_value(positive["transcript"].clone()).unwrap();

    assert_eq!(
        transcript.canonical_json_bytes().unwrap(),
        positive["canonical_bytes_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        transcript.registration_epoch().unwrap().as_str(),
        positive["expected_registration_epoch"].as_str().unwrap()
    );

    let mut unsorted = transcript.clone();
    unsorted.accepted_signing_keys.reverse();
    assert!(unsorted.registration_epoch().is_err());

    let mut duplicate = transcript.clone();
    duplicate
        .accepted_signing_keys
        .push(duplicate.accepted_signing_keys[1].clone());
    assert!(duplicate.registration_epoch().is_err());

    let mut invalid_version_branch = transcript.clone();
    invalid_version_branch
        .service_did_document
        .method_version
        .unversioned_refetch = true;
    assert!(invalid_version_branch.registration_epoch().is_err());

    let mut changed_security_field = transcript;
    changed_security_field.derived_registration.base_url = "https://other.example/cx".to_owned();
    assert_ne!(
        changed_security_field
            .registration_epoch()
            .unwrap()
            .as_str(),
        positive["expected_registration_epoch"].as_str().unwrap()
    );
}

#[test]
fn federation_fixture_expected_digest_matches_sdk_canonicalizer() {
    let fixture = fixture_artifact("federation-fixture.json");
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .expect("federation fixture missing cases");
    let case = cases
        .iter()
        .find(|case| {
            case.get("name").and_then(Value::as_str)
                == Some("reducer_profile_digest_federation_minimal")
        })
        .expect("federation fixture missing reducer_profile_digest_federation_minimal");
    let source = case
        .get("resolved_digest_input_source")
        .expect("federation reducer profile fixture missing resolved_digest_input_source");
    let profile_id = source
        .get("profile_id")
        .and_then(Value::as_str)
        .expect("federation reducer profile fixture missing profile_id");
    let registry = embedded_json_artifact("registry/reducer-profile-registry.json")
        .expect("embedded reducer profile registry");
    let profile = registry
        .get("profiles")
        .and_then(Value::as_array)
        .and_then(|profiles| {
            profiles.iter().find(|profile| {
                profile.get("profile_id").and_then(Value::as_str) == Some(profile_id)
            })
        })
        .expect("federation reducer profile missing from registry");
    let canonical_input = profile
        .get("resolved_digest_input")
        .expect("federation reducer profile missing resolved_digest_input");
    let expected_digest = case
        .get("expected_digest")
        .and_then(Value::as_str)
        .expect("federation reducer profile fixture missing expected_digest");

    assert_eq!(
        crate::canonical::canonical_sha256(canonical_input).unwrap(),
        expected_digest
    );
}

#[test]
fn auth_session_fixture_enforces_device_identity_key_separation() {
    let fixture = fixture_artifact("auth-session-proof-fixture.json");
    let vector = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "session_and_device_identity_key_separation")
        .expect("session/device key-separation vector missing");
    for case in vector["cases"].as_array().unwrap() {
        let result = crate::validate_session_device_key_separation(
            case["session_public_key_fingerprint"].as_str().unwrap(),
            case["device_public_key_fingerprint"].as_str().unwrap(),
        );
        match case["expected"].as_str().unwrap() {
            "accepted" => result.unwrap(),
            "unauthenticated" => assert!(result.is_err()),
            unexpected => panic!("unknown key-separation outcome {unexpected}"),
        }
    }
}
