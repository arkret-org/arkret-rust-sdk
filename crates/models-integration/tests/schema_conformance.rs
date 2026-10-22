use arkret_models_integration::Widget;
use arkret_models_integration::applet::AppletRegistrationEpochTranscript;
use arkret_schema_conformance::spec_json_artifact;
use serde_json::json;

#[test]
fn applet_registration_epoch_fixture_executes_against_owner() {
    let fixture = spec_json_artifact("fixtures/applet-registration-epoch-fixture.json").unwrap();
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

#[test]
fn realm_device_original_expiry_round_trips_through_generated_current() {
    use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
    use arkret_models_integration::RealmActorDeviceAuthorizationValue;
    use arkret_wire::{ActorId, EventKind, RealmActorId, ScopeRef};
    let fixture = spec_json_artifact("fixtures/applet-device-scope-fixture.json").unwrap();
    let realm = serde_json::from_value(fixture["cases"][0]["scope"]["realm_id"].clone()).unwrap();
    let actor = ActorId::realm(RealmActorId::new(
        realm,
        "ak:did_core:webvh:z6mkcontroller".parse().unwrap(),
    ));
    let applet = "ak:applet:01964137-0000-7000-8000-000000000002";
    for expiry in ["2026-10-17T00:00:00.000Z", "2026-10-17T00:00:00.123Z"] {
        let wire = json!({
            "device_id":"ak:device:01964137-0000-7000-8000-000000000001",
            "device_public_key_did":"did:key:z6Mkdevice", "hpke_key":"z6LShpke",
            "algorithms":["Ed25519"], "device_key_algorithm":"Ed25519",
            "authorized_by":actor.signing_principal_id(), "authorization_binding_kind":"realm_managed_delegation",
            "authorized_generation_ref":1, "not_before":"2026-10-16T00:00:00.000Z", "expires_at":expiry,
            "scopes":fixture["cases"][0]["scopes"], "applet_id":applet, "device_signature":"AA",
            "expected_control_revision":{"commit_id":arkret_wire::RealmCommitId::from_digest([42;32]),"stream_position":0},
            "expected_device_revision":null
        });
        let payload: DeviceAuthorizePayload = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), wire);
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::DeviceAuthorize.as_str(),
            ScopeRef::RealmControl {
                realm_id: actor.as_realm_actor_id().unwrap().realm_id.clone(),
            },
            actor.clone(),
            wire.clone(),
            "2026-10-16T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap();
        event.applet_id = Some(applet.parse().unwrap());
        event.producer_proof = None;
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let current = RealmActorDeviceAuthorizationValue::from_event(&event).unwrap();
        let current_wire = serde_json::to_value(&current).unwrap();
        assert_eq!(current_wire["expires_at"], wire["expires_at"]);
        assert_eq!(current_wire["not_before"], wire["not_before"]);
        assert_eq!(
            current_wire["device_authorize_event_id"],
            json!(event.event_id)
        );
        assert_eq!(
            serde_json::from_value::<RealmActorDeviceAuthorizationValue>(current_wire).unwrap(),
            current
        );
        for invalid in [
            "2026-10-17T00:00:00Z",
            "2026-10-17T00:00:00.123456789Z",
            "2026-10-17T00:00:00.123+00:00",
        ] {
            let mut poisoned = event.clone();
            poisoned.payload.insert("expires_at".into(), json!(invalid));
            poisoned
                .refresh_content_bound_identity_with_digest_suite(
                    arkret_canonical::DigestSuite::Sha256,
                )
                .unwrap();
            assert!(
                RealmActorDeviceAuthorizationValue::from_event(&poisoned).is_err(),
                "raw expiry must fail before becoming current: {invalid}"
            );
        }
    }
}
