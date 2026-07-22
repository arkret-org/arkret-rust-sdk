use arkret_models_discovery::{
    CompatSurfaceEntry, DirectoryRealmSearchOutcome, DirectorySearchRealmsRequestBody,
    RealmMemberCountBucket, RealmMemberCountBucketLabel,
};
use arkret_wire::RealmId;

#[test]
fn compat_surface_entry_serializes_schema_shape() {
    let surface = CompatSurfaceEntry::external_interop("soland_private_local_routes")
        .with_notes("local compatibility surface")
        .with_extra_string("base_path", "/_soland")
        .with_extra_string("status", "soland_private_local");

    let value = serde_json::to_value(surface).unwrap();

    assert_eq!(value["name"], "soland_private_local_routes");
    assert_eq!(value["kind"], "external_interop");
    assert_eq!(value["notes"], "local compatibility surface");
    assert_eq!(value["base_path"], "/_soland");
    assert_eq!(value["status"], "soland_private_local");
}

#[test]
fn directory_realm_search_outcome_decodes_typed_preview_fields() {
    let value = serde_json::json!({
        "realms": [
            {
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
                "title": "Public Realm",
                "member_count_bucket": "51-100",
                "as_of": "2026-06-13T00:00:00.000Z",
                "source_refs": ["ak:event:01904100-0000-7000-8000-000000000002"],
                "policy_revision": "rev-1"
            },
            {
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000003",
                "member_count_bucket": 342,
                "as_of": "2026-06-13T00:00:00.000Z",
                "source_refs": ["ak:event:01904100-0000-7000-8000-000000000004"],
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
    let source_realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let request = DirectorySearchRealmsRequestBody {
        query: Some("release".to_owned()),
        organization_did: None,
        source_realm_id: Some(source_realm_id.clone()),
        requester: None,
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
