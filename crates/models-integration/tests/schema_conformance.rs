use arkret_models_integration::Widget;
use arkret_models_integration::applet::AppletRegistrationEpochTranscript;
use arkret_schema::embedded_json_artifact;
use serde_json::json;

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
fn widget_origin_is_a_canonical_https_web_origin() {
    let widget = json!({
        "schema": "ak.schema.applet_widget_declaration.v1",
        "widget_origin": "https://widget.example:8443",
        "csp": "default-src 'none'",
        "token_scope": {
            "actions": ["ak.message.create"],
            "resources": [{"kind": "*"}],
            "expires_at": "2026-08-29T00:00:00.000Z"
        },
        "consent_required": true
    });
    let parsed: Widget = serde_json::from_value(widget.clone()).unwrap();
    parsed.validate().unwrap();

    for invalid in [
        "http://widget.example",
        "https://widget.example/",
        "https://widget.example:443",
        "https://widget.example/path",
    ] {
        let mut invalid_widget = widget.clone();
        invalid_widget["widget_origin"] = json!(invalid);
        assert!(serde_json::from_value::<Widget>(invalid_widget).is_err());
    }
}
