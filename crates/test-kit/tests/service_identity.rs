use arkret_test_kit::service_identity::ServiceIdentityFixture;

#[test]
fn media_ice_binds_the_exact_request_and_rejects_tampering() {
    use arkret_models_collaboration::objects::media::MediaIceConfigurationRequestBody;
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
    let request: MediaIceConfigurationRequestBody = serde_json::from_value(serde_json::json!({
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
    let verify =
        |value: &arkret_models_collaboration::objects::media::MediaIceConfigurationResponseBody| {
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
            "signature" => {
                changed.signature.signature = arkret_canonical::base64url_encode([0; 64])
            }
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

#[test]
fn station_fixture_retains_the_original_service_inception_bytes() {
    use rand_core::SeedableRng as _;

    let endpoint = "https://fixture-station.example/".parse().unwrap();
    let at = "2026-10-14T00:00:00.000Z".parse().unwrap();
    let fixture =
        ServiceIdentityFixture::webvh(&endpoint, 33, [33; 32], "signing-1", at, at).unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(33);
    let expected = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_created_at: at,
            did_key_fragment: Some("signing-1"),
        },
        &[33; 32],
    )
    .unwrap();
    assert_eq!(fixture.history.entries, vec![expected.log_entry.clone()]);
    assert_eq!(fixture.history.did.as_str(), expected.did);
    assert_eq!(fixture.verification_method.as_str(), expected.did_key_id);
    assert_eq!(fixture.resolution.service_kind, "station");
}

#[test]
fn applet_service_fixture_verifies_native_history_and_rejects_role_relabeling() {
    let endpoint = "https://fixture-applet.example/".parse().unwrap();
    let at = "2026-10-14T00:00:00.000Z".parse().unwrap();
    let fixture = ServiceIdentityFixture::webvh_applet_service(
        &endpoint,
        34,
        [34; 32],
        "applet-signing",
        at,
        at,
    )
    .unwrap();
    let verify = |resolution: &arkret_models_identity::AuthenticatedServiceResolution| -> anyhow::Result<()> {
        arkret_identity::verify_authenticated_service_resolution_history(
            resolution,
            &fixture.service_id,
            at,
        )?;
        resolution.projection()?;
        Ok(())
    };
    verify(&fixture.resolution).unwrap();
    assert_eq!(fixture.resolution.service_kind, "applet_service");
    assert_eq!(
        fixture.history.entries[0]["state"]["service"][0]["service_kind"],
        "applet_service"
    );
    assert_eq!(
        fixture.resolution.normalized_did_document.raw_properties["service"][0]["service_kind"],
        "applet_service"
    );
    assert!(
        fixture.history.entries[0]["state"]["service"][0]
            .get("serviceKind")
            .is_none()
    );
    let station =
        ServiceIdentityFixture::webvh(&endpoint, 34, [34; 32], "applet-signing", at, at).unwrap();
    assert_ne!(fixture.history.did, station.history.did);
    assert_ne!(fixture.history.entries, station.history.entries);
    let mut relabeled_applet = fixture.resolution.clone();
    relabeled_applet.service_kind = "station".into();
    assert!(verify(&relabeled_applet).is_err());
    let mut relabeled_station = station.resolution.clone();
    relabeled_station.service_kind = "applet_service".into();
    arkret_identity::verify_authenticated_service_resolution_history(
        &relabeled_station,
        &station.service_id,
        at,
    )
    .unwrap();
    assert!(relabeled_station.projection().is_err());
    let mut changed_history = fixture.resolution.clone();
    if let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
        log_entries, ..
    } = &mut changed_history.method_history_evidence
    {
        // No SCID, entry hash or update-key proof is regenerated for this mutation.
        log_entries[0]["state"]["service"][0]["service_kind"] = "station".into();
    } else {
        panic!("fixture must carry native history")
    }
    assert!(verify(&changed_history).is_err());
}

#[test]
fn push_gateway_fixture_binds_role_before_scid_and_preserves_registration_limits() {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    use rand_core::SeedableRng as _;

    let endpoint = "https://fixture-push.example/".parse().unwrap();
    let at = "2026-10-14T00:00:00.000Z".parse().unwrap();
    let fixture =
        ServiceIdentityFixture::webvh_push_gateway(&endpoint, 35, [35; 32], "push-receipt", at, at)
            .unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(35);
    let expected = arkret_signatures::webvh::prepare_push_gateway_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_created_at: at,
            did_key_fragment: Some("push-receipt"),
        },
        &[35; 32],
    )
    .unwrap();
    assert_eq!(fixture.history.entries, vec![expected.log_entry]);
    assert_eq!(fixture.history.did.as_str(), expected.did);
    assert_eq!(fixture.verification_method.as_str(), expected.did_key_id);
    assert_eq!(fixture.resolution.service_kind, "push_gateway");
    assert_eq!(
        fixture.history.entries[0]["state"]["service"][0]["service_kind"],
        "push_gateway"
    );
    assert_eq!(
        fixture.signing_key.verifying_key().to_bytes(),
        ed25519_dalek::SigningKey::from_bytes(&[35; 32])
            .verifying_key()
            .to_bytes()
    );
    let verify =
        |value: &arkret_models_identity::AuthenticatedServiceResolution| -> anyhow::Result<()> {
            arkret_identity::verify_authenticated_service_resolution_history(
                value,
                &fixture.service_id,
                at,
            )?;
            value.projection()?;
            Ok(())
        };
    verify(&fixture.resolution).unwrap();
    let station =
        ServiceIdentityFixture::webvh(&endpoint, 35, [35; 32], "push-receipt", at, at).unwrap();
    assert_ne!(fixture.history.did, station.history.did);
    assert_ne!(fixture.history.entries, station.history.entries);
    let mut relabeled = fixture.resolution.clone();
    relabeled.service_kind = "station".into();
    assert!(verify(&relabeled).is_err());
    let mut changed = fixture.resolution.clone();
    if let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
        log_entries, ..
    } = &mut changed.method_history_evidence
    {
        log_entries[0]["state"]["service"][0]["service_kind"] = "station".into();
    } else {
        panic!("gateway must carry native signed history");
    }
    assert!(verify(&changed).is_err());
    assert!(
        ServiceRegistrationKey::new(
            arkret_wire::ServiceKind::PushGateway,
            CanonicalServiceUrl::new(endpoint.as_str()).unwrap()
        )
        .is_err()
    );
}
