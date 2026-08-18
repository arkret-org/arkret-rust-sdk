use std::collections::BTreeMap;

use arkret_models_integration::applet::AppletRegistrationEpochTranscript;
use arkret_models_integration::{AppletIdentifier, AppletRegistrationPayload};
use arkret_schema::embedded_json_artifact;
use arkret_wire::{DidCoreId, Hash};
use serde_json::{Value, json};

#[test]
fn applet_registration_epoch_fixture_executes_against_owner() {
    let fixture =
        embedded_json_artifact("fixtures/applet-registration-epoch-fixture.json").unwrap();
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
fn applet_registration_builder_validates_against_catalog() {
    // applet-package.schema.json#/$defs/webhook_auth is closed: kind, key_ref
    // and accepted_signature_algorithms are all required.
    let webhook_auth: BTreeMap<String, Value> = [
        ("kind".to_owned(), json!("http_message_signature")),
        (
            "key_ref".to_owned(),
            json!("did:webvh:z6mkfixture:applet.example#svc"),
        ),
        (
            "accepted_signature_algorithms".to_owned(),
            json!(["ed25519"]),
        ),
    ]
    .into_iter()
    .collect();
    let proof: BTreeMap<String, Value> = [("signature".to_owned(), json!("c2ln"))]
        .into_iter()
        .collect();
    let payload = AppletRegistrationPayload::new(
        AppletIdentifier::Service(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        "https://applet.example",
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        webhook_auth,
        proof,
        "2026-07-08T10:05:00.000Z".parse().unwrap(),
    )
    .with_protocols(vec!["a2a".to_owned()])
    .with_requested_scopes(vec!["ak.message.create".to_owned()])
    .with_receive_events(true);
    let value = payload.to_value().unwrap();
    assert_eq!(value["service_id"], json!("ak:did_core:webvh:z6mkfixture"));
    assert_eq!(
        value["claimed_profiles"],
        json!(["ak.profile.applet_service.v1"])
    );
    arkret_schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ak.applet.registration", &value)
        .unwrap();
}
