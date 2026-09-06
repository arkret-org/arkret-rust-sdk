use arkret_models_discovery::{
    DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
    DirectoryRealmSearchOutcome, DirectorySearchRealmsRequestBody, InteropSurfaceEntry,
    InteropSurfaceKind, InviteConsentHandoffStub, PrivateContactDiscovery,
    PrivateContactDiscoveryHandoffStubsMode, PrivateContactDiscoveryProfile, PsiResponsePadding,
    RealmMemberCountBucket, RealmMemberCountBucketLabel, ServiceDescribe,
};
use arkret_wire::{Did, RealmId, ServiceKind, TrustDomainId};

#[test]
fn announce_origin_is_carried_only_by_the_signed_event_actor() {
    let realm_id = "ak:realm:ATH75ame6bMfYpXtcoLOVb7FKmgpWVniZZqVBz1dUdQa";
    let mut value = serde_json::json!({
        "discovery_event": {
            "event_id": "ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2",
            "kind": "ak.realm.discovery", "realm_id": realm_id,
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:web:author.example",
                "station_id": "ak:did_core:web:station.example"}},
            "actor_seq": 1, "created_at": "2026-08-31T00:00:00.000Z",
            "prev_refs": [], "payload": {"value": {}}, "proofs": []
        },
        "source_ref_access": {
            "kind": "directory_announce",
            "source_id": "ak:did_core:web:station.example",
            "directory_id": "ak:did_core:web:directory.example",
            "realm_id": realm_id,
            "discovery_event_id": "ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2",
            "source_refs": ["ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2"],
            "as_of": "2026-08-31T00:00:00.000Z",
            "expires_at": "2026-08-31T00:05:00.000Z",
            "proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:station.example#notary-key",
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": "2026-08-31T00:00:00.000Z",
                "domain": "ak:trust_domain:example.com",
                "audience": "ak:did_core:web:directory.example",
                "jws": "e30..c2ln"
            }
        },
        "as_of": "2026-08-31T00:00:00.000Z"
    });
    let body: arkret_models_discovery::DirectoryAnnounceRequestBody =
        serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        body.discovery_event.actor_id.route_service_id().as_str(),
        "ak:did_core:web:station.example"
    );
    assert!(
        serde_json::to_value(&body)
            .unwrap()
            .get("station_id")
            .is_none()
    );
    value["station_id"] = serde_json::json!("ak:did_core:web:other.example");
    assert!(
        serde_json::from_value::<arkret_models_discovery::DirectoryAnnounceRequestBody>(value)
            .is_err()
    );
    let mut missing_access = serde_json::to_value(&body).unwrap();
    missing_access
        .as_object_mut()
        .unwrap()
        .remove("source_ref_access");
    assert!(
        serde_json::from_value::<arkret_models_discovery::DirectoryAnnounceRequestBody>(
            missing_access
        )
        .is_err()
    );
}

#[test]
fn interop_surface_entry_is_closed_and_supports_delegated_resolver() {
    let surface = InteropSurfaceEntry::delegated_resolver("station_did_resolver")
        .with_notes("delegated DID document surface");
    let encoded = serde_json::to_value(&surface).unwrap();
    assert_eq!(encoded["kind"], "delegated_resolver");
    assert_eq!(surface.kind, InteropSurfaceKind::DelegatedResolver);

    let open = serde_json::json!({
        "name": "private_routes",
        "kind": "external_interop",
        "base_path": "/_product"
    });
    assert!(serde_json::from_value::<InteropSurfaceEntry>(open).is_err());
}

#[test]
fn service_describe_round_trips_interop_surfaces_on_the_canonical_key() {
    let mut description = ServiceDescribe::development(
        Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        ServiceKind::Station,
        vec!["ak.operation_bundle.station.describe.v1".to_owned()],
        vec![arkret_models_discovery::TransportBinding::HttpJson {
            base_url: "https://service.example".to_owned(),
            extension_profile_required: (),
        }],
    );
    description.interop_surfaces = vec![
        InteropSurfaceEntry::delegated_resolver("station_did_resolver"),
        InteropSurfaceEntry::matrix_passthrough("matrix_bridge"),
    ];

    let encoded = serde_json::to_value(&description).unwrap();
    assert_eq!(encoded["interop_surfaces"][0]["kind"], "delegated_resolver");
    assert_eq!(encoded["interop_surfaces"][1]["kind"], "matrix_passthrough");

    let decoded: ServiceDescribe = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded.interop_surfaces, description.interop_surfaces);

    // The field is required, not defaulted: a payload carrying the surfaces
    // under any other key leaves `interop_surfaces` missing and MUST fail.
    let mut without_surfaces = encoded;
    without_surfaces
        .as_object_mut()
        .unwrap()
        .remove("interop_surfaces")
        .unwrap();
    assert!(serde_json::from_value::<ServiceDescribe>(without_surfaces).is_err());
}

#[test]
fn directory_realm_search_outcome_decodes_typed_preview_fields() {
    let value = serde_json::json!({
        "realms": [
            {
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "title": "Public Realm",
                "member_count_bucket": "51-100",
                "as_of": "2026-06-13T00:00:00.000Z",
                "source_refs": ["ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"],
                "policy_revision": "rev-1"
            },
            {
                "realm_id": "ak:realm:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
                "member_count_bucket": 342,
                "as_of": "2026-06-13T00:00:00.000Z",
                "source_refs": ["ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"],
                "policy_revision": "rev-2"
            }
        ],
        "next_cursor": null,
        "has_more": false
    });

    let outcome: DirectoryRealmSearchOutcome = serde_json::from_value(value).unwrap();

    assert!(!outcome.has_more);
    assert!(matches!(
        outcome.realms[0].member_count_bucket,
        Some(RealmMemberCountBucket::Bucket(
            RealmMemberCountBucketLabel::FiftyOneToOneHundred
        ))
    ));
    assert!(matches!(
        outcome.realms[1].member_count_bucket,
        Some(RealmMemberCountBucket::Exact(342))
    ));
}

#[test]
fn directory_search_realms_request_uses_source_realm_id() {
    let source_realm_id =
        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let request = DirectorySearchRealmsRequestBody {
        query: Some("release".to_owned()),
        organization_id: None,
        source_realm_id: Some(source_realm_id.clone()),
        requester_id: None,
        proof_challenge: Some("challenge-1".to_owned()),
        claim_presentations: Vec::new(),
        cursor: None,
        limit: Some(20),
    };
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["source_realm_id"], source_realm_id.as_str());
    assert_eq!(value["proof_challenge"], "challenge-1");
    assert!(value.get("proofs").is_none());
    assert!(value.get("parent_space_id").is_none());

    let parsed: DirectorySearchRealmsRequestBody = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.source_realm_id, Some(source_realm_id));
    assert_eq!(parsed.proof_challenge.as_deref(), Some("challenge-1"));
    assert!(parsed.claim_presentations.is_empty());
}

#[test]
fn private_contact_discovery_privacy_fixture_closes_current_v1_wire() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/privacy-security-fixture.json")
            .expect("embedded privacy fixture");
    let vector = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["vector_id"].as_str() == Some("ak.vector.psi.padding_and_cardinality.v1"))
        .expect("PSI padding/cardinality vector");

    let configuration: PrivateContactDiscovery =
        serde_json::from_value(vector["input"]["private_contact_discovery_config"].clone())
            .expect("closed PCD configuration");
    configuration.validate().unwrap();
    let blind: DirectoryPrivateContactDiscoveryRequestBody =
        serde_json::from_value(vector["input"]["blind_request"].clone())
            .expect("closed blind request");
    let match_request: DirectoryPrivateContactDiscoveryRequestBody =
        serde_json::from_value(vector["input"]["match_request"].clone())
            .expect("closed match request");
    blind.validate_against(&configuration).unwrap();
    match_request.validate_against(&configuration).unwrap();
    let expected = &vector["expected"];
    let expected_count = expected["wire_batch_cardinality_equals_advertised_batch_item_count"]
        .as_u64()
        .unwrap() as usize;
    let expected_content_length = expected["success_content_length_bytes"].as_u64().unwrap();
    assert_eq!(blind.item_count(), expected_count);
    assert_eq!(match_request.item_count(), expected_count);
    assert_eq!(configuration.batch_item_count as usize, expected_count);
    assert_eq!(
        configuration.match_response_bucket_bytes as u64,
        expected_content_length
    );
    for expected_flag in [
        "wire_batch_cardinality_does_not_equal_real_identifier_count",
        "evaluated_elements_same_length_and_order_as_blinded_elements",
        "derived_prefixes_and_hit_bitmap_same_length_and_order",
        "single_batched_dleq_proof_verified_with_described_public_key",
        "result_count_does_not_reveal_match_count",
        "no_raw_connection_identifier",
        "handoff_stubs_if_present_same_cardinality_dummy_padded",
        "per_target_policy_denied_and_no_match_byte_indistinguishable_in_hit_bitmap",
    ] {
        assert_eq!(
            expected[expected_flag], true,
            "fixture expectation {expected_flag}"
        );
    }

    let handoff_stubs = vec![InviteConsentHandoffStub::dummy(); expected_count];
    let match_outcome = DirectoryPrivateContactDiscoveryOutcome::Match {
        profile: PrivateContactDiscoveryProfile::V1,
        batch_id: match_request.batch_id().clone(),
        key_epoch: 14,
        hit_bitmap: vec![false, true, false, false],
        handoff_stubs: Some(handoff_stubs),
        padding: PsiResponsePadding::default(),
    }
    .pad_to_advertised_bucket(&configuration)
    .unwrap();
    match_outcome
        .validate_against_request(&match_request, &configuration)
        .unwrap();

    let encoded = arkret_canonical::canonical_json_bytes(&match_outcome).unwrap();
    assert_eq!(encoded.len() as u64, expected_content_length);
    let value = serde_json::to_value(&match_outcome).unwrap();
    assert!(value.get("padding").is_some());
    assert!(value.get("padding_count").is_none());
    assert_eq!(expected["cache_control"], "no-store, no-transform");
    assert_eq!(expected["content_encoding_header_absent"], true);
}

fn rfc9497_hex(value: &str) -> String {
    arkret_canonical::base64url_encode(hex::decode(value).expect("RFC 9497 hex vector"))
}

#[test]
fn private_contact_discovery_verifies_rfc9497_batch_dleq_vector() {
    // RFC 9497 Appendix A.1.2.3: modeVOPRF, ristretto255-SHA512,
    // batch size 2. These are fixed external KAT values, not generated by the
    // implementation under test.
    const PUBLIC_KEY: &str = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e";
    const BLINDED: [&str; 2] = [
        "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
        "90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654",
    ];
    const EVALUATED: [&str; 2] = [
        "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
        "cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a",
    ];
    const PROOF: &str = concat!(
        "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a",
        "5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08"
    );

    let mut configuration = PrivateContactDiscovery::new(
        rfc9497_hex(PUBLIC_KEY),
        14,
        2,
        PrivateContactDiscoveryHandoffStubsMode::Never,
        4096,
        4096,
        3600,
        1,
        86_400,
        arkret_models_discovery::AntiEnumerationDelay {
            minimum_ms: 100,
            jitter_ms: 50,
        },
    );
    let request: DirectoryPrivateContactDiscoveryRequestBody =
        serde_json::from_value(serde_json::json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "blind",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "ciphersuite": "ristretto255-SHA512",
            "key_epoch": 14,
            "blinded_elements": BLINDED.map(rfc9497_hex)
        }))
        .unwrap();
    let outcome: DirectoryPrivateContactDiscoveryOutcome =
        serde_json::from_value(serde_json::json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "blind",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "ciphersuite": "ristretto255-SHA512",
            "key_epoch": 14,
            "evaluated_elements": EVALUATED.map(rfc9497_hex),
            "evaluation_proofs": [rfc9497_hex(PROOF)],
            "derived_prefix_bytes": 16,
            "padding": ""
        }))
        .unwrap();
    let outcome = outcome.pad_to_advertised_bucket(&configuration).unwrap();
    outcome
        .validate_against_request(&request, &configuration)
        .unwrap();

    let mut swapped = serde_json::to_value(&outcome).unwrap();
    swapped["evaluated_elements"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let swapped: DirectoryPrivateContactDiscoveryOutcome = serde_json::from_value(swapped).unwrap();
    assert!(
        swapped
            .validate_against_request(&request, &configuration)
            .is_err()
    );

    let mut changed_proof = serde_json::to_value(&outcome).unwrap();
    let mut proof_bytes =
        arkret_canonical::base64url_decode(changed_proof["evaluation_proofs"][0].as_str().unwrap())
            .unwrap();
    proof_bytes[0] ^= 1;
    changed_proof["evaluation_proofs"][0] =
        serde_json::Value::String(arkret_canonical::base64url_encode(proof_bytes));
    let changed_proof: DirectoryPrivateContactDiscoveryOutcome =
        serde_json::from_value(changed_proof).unwrap();
    assert!(
        changed_proof
            .validate_against_request(&request, &configuration)
            .is_err()
    );

    configuration.public_key = rfc9497_hex(BLINDED[0]);
    configuration.validate().unwrap();
    assert!(
        outcome
            .validate_against_request(&request, &configuration)
            .is_err()
    );
}
