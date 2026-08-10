use arkret_models_discovery::{
    CompatSurfaceEntry, CompatSurfaceKind, DirectoryRealmSearchOutcome,
    DirectorySearchRealmsRequestBody, RealmMemberCountBucket, RealmMemberCountBucketLabel,
};
use arkret_wire::RealmId;

#[test]
fn compat_surface_entry_is_closed_and_supports_delegated_resolver() {
    let surface = CompatSurfaceEntry::delegated_resolver("auth_server_did_resolver")
        .with_since("1")
        .with_notes("delegated DID document surface");
    let encoded = serde_json::to_value(&surface).unwrap();
    assert_eq!(encoded["kind"], "delegated_resolver");
    assert_eq!(surface.kind, CompatSurfaceKind::DelegatedResolver);

    let open = serde_json::json!({
        "name": "private_routes",
        "kind": "external_interop",
        "base_path": "/_product"
    });
    assert!(serde_json::from_value::<CompatSurfaceEntry>(open).is_err());
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
        organization_principal_id: None,
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
