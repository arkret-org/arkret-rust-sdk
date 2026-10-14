use arkret_test_kit::service_identity::ServiceIdentityFixture;

#[test]
fn media_ice_binds_the_exact_request_and_rejects_tampering() {
    use arkret_models_collaboration::objects::media::MediaIceConfigRequestBody;
    let at = "2026-10-14T00:00:00.000Z".parse().unwrap();
    let authority = ServiceIdentityFixture::webvh(
        &"https://media-fixture.example/".parse().unwrap(),
        51,
        [51; 32],
        "ice",
        at,
        at,
    )
    .unwrap();
    let request: MediaIceConfigRequestBody = serde_json::from_value(serde_json::json!({
        "realm_id":"ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        "call_id":"ak:call:AVxshP1cCAeTx94DZvt3ODhEjNR9Da4hbdzLBzwPU-T1",
        "actor_id":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":authority.service_id}},
        "device_id":"ak:device:01904100-0000-7000-8000-000000000005","mode":"p2p"
    })).unwrap();
    let outcome = arkret_test_kit::media_ice::signed_config(&request, &authority, at).unwrap();
    let anchors = arkret_signatures::media::MediaServiceAnchors::new([(
        authority.service_id.clone(),
        authority.history.did.clone(),
    )])
    .unwrap()
    .with_keys([(
        authority.verification_method.to_string(),
        authority.signing_key.verifying_key(),
    )])
    .unwrap();
    let verify = |value: &arkret_models_collaboration::objects::media::MediaIceConfigOutcome| {
        arkret_signatures::media::verify_ice_config_outcome(value, &anchors)
    };
    verify(&outcome).unwrap();
    assert_eq!(outcome.actor_id, request.actor_id);
    assert_eq!(outcome.realm_id, request.realm_id);
    assert_eq!(outcome.call_id, request.call_id);
    assert_eq!(outcome.device_id, request.device_id);
    for field in [
        "realm",
        "call",
        "actor",
        "device",
        "timestamp",
        "credential",
        "signature",
    ] {
        let mut changed = outcome.clone();
        match field {
            "realm" => {
                changed.realm_id = "ak:realm:ATJ_DJ_0dc3yFbBW3UWM7qysprZ6zJPZzhxGzqahfHEA"
                    .parse()
                    .unwrap()
            }
            "call" => {
                changed.call_id = "ak:call:ATJ_DJ_0dc3yFbBW3UWM7qysprZ6zJPZzhxGzqahfHEA".into()
            }
            "actor" => {
                changed.actor_id = arkret_wire::ActorId::service(authority.service_id.clone())
            }
            "device" => {
                changed.device_id = "ak:device:01904100-0000-7000-8000-000000000006"
                    .parse()
                    .unwrap()
            }
            "timestamp" => changed.issued_at += chrono::Duration::seconds(1),
            "credential" => changed.ice_servers[1].credential = Some("changed".into()),
            "signature" => changed.signature.sig = arkret_canonical::base64url_encode([0; 64]),
            _ => unreachable!(),
        }
        assert!(verify(&changed).is_err(), "{field} mutation was accepted");
    }
}

#[test]
fn native_service_route_is_exact_and_rejects_changed_identity_document_and_history() {
    let at = "2026-10-14T00:00:00.000Z".parse().unwrap();
    let fixture = ServiceIdentityFixture::webvh(
        &"https://fixture-station.example/".parse().unwrap(),
        31,
        [31; 32],
        "signing-1",
        "2026-06-01T00:00:00.000Z".parse().unwrap(),
        at,
    )
    .unwrap();
    let verify = |resolution: &arkret_models_identity::AuthenticatedServiceResolution,
                  id: &arkret_wire::DidCoreId| {
        arkret_identity::verify_authenticated_service_resolution_history(resolution, id, at)
    };
    verify(&fixture.resolution, &fixture.service_id).unwrap();
    let other = ServiceIdentityFixture::webvh(
        &"https://other-station.example/".parse().unwrap(),
        32,
        [32; 32],
        "signing-1",
        "2026-06-01T00:00:00.000Z".parse().unwrap(),
        at,
    )
    .unwrap();
    assert!(verify(&fixture.resolution, &other.service_id).is_err());
    let mut document = fixture.resolution.clone();
    document
        .normalized_did_document
        .raw_properties
        .get_mut("service")
        .unwrap()[0]["serviceEndpoint"] = "https://forged.example/".into();
    assert!(verify(&document, &fixture.service_id).is_err());
    let mut history = fixture.resolution.clone();
    if let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
        log_entries, ..
    } = &mut history.method_history_evidence
    {
        log_entries[0]["state"]["alsoKnownAs"] = serde_json::json!(["https://forged.example/"]);
    } else {
        panic!("fixture must carry native history")
    }
    assert!(verify(&history, &fixture.service_id).is_err());
}
