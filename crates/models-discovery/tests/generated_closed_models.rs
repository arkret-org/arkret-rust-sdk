use arkret_canonical::canonical::canonical_json_bytes;
use arkret_models_discovery::PublicRealmMetadata;
use arkret_models_discovery::directory::{
    DirectoryRealmSearchResponseBody, DirectorySearchRealmsRequestBody,
};
use arkret_models_discovery::presence::{
    ManualPresenceState, PresencePreference, PresenceVisibilityPreference,
};
use serde_json::{Value, json};

#[test]
fn legal_values_keep_frozen_canonical_bytes_and_public_paths() {
    let vectors = [
        (json!({}), "{}"),
        (
            json!({"limit": 20, "query": "工程", "cursor": "next"}),
            "{\"cursor\":\"next\",\"limit\":20,\"query\":\"工程\"}",
        ),
    ];
    for (wire, expected) in vectors {
        let request: DirectorySearchRealmsRequestBody =
            serde_json::from_value(wire.clone()).unwrap();
        request.validate().unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), wire);
        assert_eq!(canonical_json_bytes(&request).unwrap(), expected.as_bytes());
    }
    let absent: DirectorySearchRealmsRequestBody = serde_json::from_value(json!({})).unwrap();
    assert_eq!(absent.limit, None);
    assert_eq!(
        serde_json::to_string(&DirectorySearchRealmsRequestBody {
            query: Some("q".into()),
            limit: Some(20),
            cursor: Some("c".into()),
        })
        .unwrap(),
        r#"{"query":"q","limit":20,"cursor":"c"}"#
    );
    let preference: PresencePreference = serde_json::from_value(json!({
        "manual_state": "dnd", "status_message": "busy", "clears_at": "2026-10-13T00:00:00.000Z",
    }))
    .unwrap();
    assert_eq!(preference.manual_state, Some(ManualPresenceState::Dnd));
    assert_eq!(
        canonical_json_bytes(&preference).unwrap(),
        br#"{"clears_at":"2026-10-13T00:00:00.000Z","manual_state":"dnd","status_message":"busy"}"#
    );
}

#[test]
fn closed_required_and_optional_non_null_members_follow_spec() {
    for field in ["summary", "public_locator", "avatar_blob_ref"] {
        let mut wire = json!({"display_name": "Engineering"});
        wire[field] = Value::Null;
        assert!(
            serde_json::from_value::<PublicRealmMetadata>(wire).is_err(),
            "{field}"
        );
    }
    for field in ["query", "limit", "cursor"] {
        let mut wire = json!({});
        wire[field] = Value::Null;
        assert!(
            serde_json::from_value::<DirectorySearchRealmsRequestBody>(wire).is_err(),
            "{field}"
        );
    }
    for field in ["manual_state", "status_message", "clears_at"] {
        let mut wire = json!({});
        wire[field] = Value::Null;
        assert!(
            serde_json::from_value::<PresencePreference>(wire).is_err(),
            "{field}"
        );
    }
    for wire in [
        json!({}),
        json!({"realms": []}),
        json!({"has_more": false}),
        json!({"realms": null, "has_more": false}),
        json!({"realms": [], "has_more": false, "next_cursor": null}),
        json!({"realms": [], "has_more": false, "extra": true}),
    ] {
        assert!(serde_json::from_value::<DirectoryRealmSearchResponseBody>(wire).is_err());
    }
    for wire in [
        json!({}),
        json!({"presence_visibility": null}),
        json!({"presence_visibility": "invisible"}),
        json!({"presence_visibility": "public", "extra": 1}),
    ] {
        assert!(serde_json::from_value::<PresenceVisibilityPreference>(wire).is_err());
    }
    for state in ["offline", "invisible", "busy"] {
        assert!(
            serde_json::from_value::<PresencePreference>(json!({"manual_state": state})).is_err()
        );
    }
    assert!(
        serde_json::from_value::<PresencePreference>(json!({"clears_at": "2026-10-13T00:00:00Z"}))
            .is_err()
    );
    assert!(serde_json::from_value::<PresencePreference>(json!({"unknown": true})).is_err());
}

#[test]
fn directory_acceptance_matches_live_spec_with_existing_domain_validation() {
    use arkret_schema_conformance::{
        default_spec_artifacts_dir, schema_registry_from_spec_artifacts,
    };
    let artifacts = default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("schemas/directory-operations.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            "test:directory_request".to_owned(),
            schema,
            "#/$defs/directory_search_realms_request_body",
        )
        .unwrap();
    for (wire, expected) in [
        (json!({}), true),
        (json!({"query": "engineering", "limit": 20}), true),
        (json!({"query": null}), false),
        (json!({"limit": null}), false),
        (json!({"cursor": null}), false),
        (json!({"query": ""}), false),
        (json!({"limit": 0}), false),
        (json!({"limit": 101}), false),
        (json!({"cursor": ""}), false),
        (json!({"extra": true}), false),
    ] {
        assert_eq!(
            registry
                .validate_value("test:directory_request", &wire)
                .is_ok(),
            expected,
            "schema {wire}"
        );
        let accepts = serde_json::from_value::<DirectorySearchRealmsRequestBody>(wire.clone())
            .is_ok_and(|value| value.validate().is_ok());
        assert_eq!(accepts, expected, "model {wire}");
    }
}
