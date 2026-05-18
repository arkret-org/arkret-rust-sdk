use super::artifacts::registry_entry;
use super::*;

#[test]
fn schema_catalog_reports_all_registered_schemas() {
    let catalog = schema_catalog();
    catalog.validate().unwrap();
    assert!(catalog.entries.iter().any(|entry| entry.schema_id == EVENT_SCHEMA));
}

#[test]
fn schema_vectors_include_negative_security_extension_case() {
    validate_schema_vectors(&built_in_schema_vectors()).unwrap();
}

#[test]
fn event_payload_catalog_validates_known_payload_fields() {
    let catalog = event_payload_validator_catalog();
    catalog
        .validate_payload(
            "cx.flow.move",
            &json!({
                "board_place_id": "cx:place:01904100-0000-7000-8000-111111111111",
                "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
                "target_place_id": "cx:place:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(matches!(
        catalog.validate_payload(
            "cx.flow.move",
            &json!({
                "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
                "target_place_id": "cx:place:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            })
        ),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn artifact_payload_catalog_covers_active_durable_event_kinds() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(&artifacts_dir).unwrap();
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts_dir).unwrap();
    let durable_event_kinds = bundle.event_kind_registry["event_kinds"]
        .as_array()
        .expect("event_kinds array")
        .iter()
        .filter(|entry| entry["status"].as_str() == Some("active"))
        .filter(|entry| entry["wire_scope"].as_str() == Some("durable_event"))
        .filter_map(|entry| entry["event_kind"].as_str())
        .filter(|event_kind| crate::events::is_standard_event_kind(event_kind))
        .collect::<Vec<_>>();
    let missing = catalog.missing_payload_validators_for(durable_event_kinds.iter().copied());
    assert!(missing.is_empty(), "missing payload validators: {missing:?}");
    assert!(
        catalog.rules.len() > 7,
        "artifact-derived payload catalog should not collapse to old hand-written rules"
    );
}

#[test]
fn artifact_payload_catalog_enforces_deep_schema_rules() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    catalog
        .validate_payload(
            crate::events::FLOW_MOVE,
            &json!({
                "board_place_id": "cx:place:01904100-0000-7000-8000-111111111111",
                "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
                "target_place_id": "cx:place:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::FLOW_MOVE,
                &json!({
                    "board_place_id": "not-a-place-id",
                    "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
                    "target_place_id": "cx:place:01904100-0000-7000-8000-222222222222",
                    "rank": "U"
                }),
            )
            .is_err()
    );
    assert!(
        catalog
            .validate_payload(
                crate::events::FLOW_MOVE,
                &json!({
                    "board_place_id": "cx:place:01904100-0000-7000-8000-111111111111",
                    "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
                    "target_place_id": "cx:place:01904100-0000-7000-8000-222222222222",
                    "rank": "U",
                    "unexpected": true
                }),
            )
            .is_err()
    );
}

#[test]
fn artifact_payload_catalog_enforces_external_schema_refs_and_enums() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let key = json!({
        "kid": "did:web:alice.example#psk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExample",
        "key_format": "multibase"
    });
    let subordinate_key = json!({
        "kid": "did:web:alice.example#ssk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExampleSub",
        "key_format": "multibase",
        "binding": {
            "signed_by": "did:web:alice.example#psk-1",
            "alg": "EdDSA",
            "signature": "sig"
        }
    });
    catalog
        .validate_payload(
            crate::events::CROSS_SIGNING_PUBLISH,
            &json!({
                "principal_id": "did:web:alice.example",
                "principal_signing_key": key,
                "self_signing_key": subordinate_key,
                "user_signing_key": subordinate_key,
                "generation": 1,
                "issued_at": "2026-05-02T00:00:00Z"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::CROSS_SIGNING_PUBLISH,
                &json!({
                    "principal_id": "did:web:alice.example",
                    "principal_signing_key": key,
                    "self_signing_key": subordinate_key,
                    "user_signing_key": subordinate_key,
                    "generation": 0,
                    "issued_at": "2026-05-02T00:00:00Z"
                }),
            )
            .is_err()
    );
}

fn registry_with_keys(array_field: &str, key_field: &str, values: &[&str]) -> Value {
    let entries = values
        .iter()
        .map(|value| json!({ key_field: *value, "status": "active" }))
        .collect::<Vec<_>>();
    json!({ array_field: entries })
}

#[test]
fn profile_requirement_drift_reports_missing_sdk_constants() {
    let mut profile_requirements = serde_json::Map::new();
    profile_requirements.insert(
        crate::PROFILE_DIRECTORY_SERVICE.to_owned(),
        json!({
            "required_endpoints": ["cx.directory.search_spaces", "cx.missing.operation"],
            "required_event_kinds": ["cx.space.discovery"],
            "required_schemas": ["cx.schema.actor_profile.v1"]
        }),
    );
    let bundle = SpecArtifactBundle {
        schema_registry: registry_with_keys("schemas", "schema_id", ARTIFACT_BACKED_SCHEMA_IDS),
        event_kind_registry: registry_with_keys(
            "event_kinds",
            "event_kind",
            ARTIFACT_BACKED_EVENT_KINDS,
        ),
        operation_registry: registry_with_keys(
            "operations",
            "operation_id",
            ARTIFACT_BACKED_SERVICE_OPERATIONS,
        ),
        id_kind_registry: registry_with_keys("id_kinds", "kind", ARTIFACT_BACKED_ID_KINDS),
        conformance_profiles: json!({ "profile_requirements": profile_requirements }),
        artifacts_dir: None,
    };

    let report = bundle.drift_report();
    assert!(
        report
            .profile_requirement_issues
            .iter()
            .any(|issue| issue.contains("cx.missing.operation")),
        "{:?}",
        report.profile_requirement_issues
    );
    assert!(report.validate().is_err());
}

#[test]
fn generated_validators_cover_core_schema_ids() {
    let validators = generated_validators().unwrap();
    for schema_id in CORE_SCHEMA_IDS {
        assert!(validators.contains_key(*schema_id), "{schema_id}");
    }
}

#[test]
fn generated_validators_cover_all_artifact_schema_ids() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
    let validators = generated_validators().unwrap();
    let schema_ids = bundle.schema_registry["schemas"]
        .as_array()
        .expect("schemas array")
        .iter()
        .filter_map(|schema| schema["schema_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(validators.len(), schema_ids.len());
    for schema_id in schema_ids {
        assert!(validators.contains_key(schema_id), "{schema_id}");
    }
}

#[test]
fn generated_profile_constants_match_artifact_profile_ids() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
    let artifact_ids = bundle.profile_ids();
    let generated_ids =
        crate::generated::profiles::PROFILE_IDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        generated_ids.len(),
        crate::generated::profiles::PROFILE_IDS.len(),
        "generated profile constants contain duplicates"
    );
    assert_eq!(
        artifact_ids.len(),
        generated_ids.len(),
        "generated profile constants drifted from conformance profile artifacts"
    );
    for profile_id in artifact_ids {
        assert!(
            crate::generated::profiles::is_profile_id(&profile_id),
            "generated profile constants missing {profile_id}"
        );
    }
}

#[test]
fn schema_registry_enforces_json_schema_composition_and_value_rules() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry.register(
        "cx.schema.deep_test.v1",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "cx.schema.deep_test.v1",
            "type": "object",
            "required": ["kind", "items", "target"],
            "properties": {
                "kind": {"const": "demo"},
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "pattern": "^[a-z]+$"}
                },
                "target": {
                    "oneOf": [
                        {"type": "string", "enum": ["user", "space"]},
                        {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
                    ]
                }
            },
            "allOf": [{"properties": {"kind": {"type": "string"}}}],
            "additionalProperties": false
        }),
    );
    registry
        .validate_value(
            "cx.schema.deep_test.v1",
            &json!({"kind": "demo", "items": ["alpha"], "target": "user"}),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(
                "cx.schema.deep_test.v1",
                &json!({"kind": "demo", "items": [], "target": "user"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "cx.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "other"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "cx.schema.deep_test.v1",
                &json!({"kind": "other", "items": ["alpha"], "target": "user"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "cx.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "user", "extra": true}),
            )
            .is_err()
    );
}

#[test]
fn spec_artifact_registry_covers_key_local_schema_and_event_contracts() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
    bundle.drift_report().validate().unwrap();

    let spec_active_event_kinds = bundle.event_kind_registry["event_kinds"]
        .as_array()
        .expect("event_kinds array")
        .iter()
        .filter(|entry| entry["status"].as_str() == Some("active"))
        .filter_map(|entry| entry["event_kind"].as_str())
        .collect::<BTreeSet<_>>();
    let sdk_event_kinds = ARTIFACT_BACKED_EVENT_KINDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        sdk_event_kinds.len(),
        ARTIFACT_BACKED_EVENT_KINDS.len(),
        "SDK event constants contain duplicates"
    );
    let missing_event_kinds =
        spec_active_event_kinds.difference(&sdk_event_kinds).copied().collect::<Vec<_>>();
    let extra_event_kinds =
        sdk_event_kinds.difference(&spec_active_event_kinds).copied().collect::<Vec<_>>();
    assert!(
        missing_event_kinds.is_empty(),
        "SDK event constants missing active spec event kinds {missing_event_kinds:?}"
    );
    assert!(
        extra_event_kinds.is_empty(),
        "SDK event constants include non-active spec event kinds {extra_event_kinds:?}"
    );

    let spec_operation_ids = bundle.operation_registry["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .filter_map(|entry| entry["operation_id"].as_str())
        .collect::<BTreeSet<_>>();
    let sdk_operation_ids =
        ARTIFACT_BACKED_SERVICE_OPERATIONS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        sdk_operation_ids.len(),
        ARTIFACT_BACKED_SERVICE_OPERATIONS.len(),
        "SDK built-in operation constants contain duplicates"
    );
    let missing_operation_ids =
        spec_operation_ids.difference(&sdk_operation_ids).copied().collect::<Vec<_>>();
    let extra_operation_ids =
        sdk_operation_ids.difference(&spec_operation_ids).copied().collect::<Vec<_>>();
    assert!(
        missing_operation_ids.is_empty(),
        "SDK built-in operations missing spec operations {missing_operation_ids:?}"
    );
    assert!(
        extra_operation_ids.is_empty(),
        "SDK built-in operations include operations outside spec {extra_operation_ids:?}"
    );

    let schemas = bundle.schema_registry["schemas"].as_array().expect("schemas array");
    let schema_ids =
        schemas.iter().filter_map(|schema| schema["schema_id"].as_str()).collect::<BTreeSet<_>>();
    assert_eq!(
        ARTIFACT_BACKED_SCHEMA_IDS.len(),
        schema_ids.len(),
        "SDK artifact-backed schema coverage should cover the full schema registry"
    );
    for schema_id in ARTIFACT_BACKED_SCHEMA_IDS {
        assert!(schema_ids.contains(*schema_id), "missing schema artifact for {schema_id}");
    }
    let event_schema = schemas
        .iter()
        .find(|schema| schema["schema_id"] == EVENT_SCHEMA)
        .expect("event envelope schema registry entry");
    assert_eq!(event_schema["file"].as_str(), Some("schemas/event-envelope.schema.json"));

    for event_kind in ARTIFACT_BACKED_EVENT_KINDS {
        let entry =
            registry_entry(&bundle.event_kind_registry, "event_kinds", "event_kind", event_kind)
                .unwrap_or_else(|| panic!("missing event kind {event_kind}"));
        assert_eq!(entry["status"].as_str(), Some("active"), "{event_kind}");
        assert!(entry["wire_scope"].as_str().is_some(), "{event_kind}");
    }

    for operation_id in ARTIFACT_BACKED_SERVICE_OPERATIONS {
        assert!(
            registry_entry(&bundle.operation_registry, "operations", "operation_id", operation_id)
                .is_some(),
            "missing service operation {operation_id}"
        );
    }

    let profile_ids = bundle.profile_ids();
    for profile_id in ARTIFACT_BACKED_PROFILE_IDS {
        assert!(profile_ids.contains(*profile_id), "missing profile artifact for {profile_id}");
        let requirement = bundle
            .profile_requirement(profile_id)
            .unwrap_or_else(|error| panic!("invalid profile requirement {profile_id}: {error}"))
            .unwrap_or_else(|| panic!("missing profile requirement {profile_id}"));
        assert!(
            !requirement.required_endpoints.is_empty()
                || !requirement.required_event_kinds.is_empty()
                || !requirement.required_schemas.is_empty(),
            "profile requirement should not be empty: {profile_id}"
        );
    }

    for (kind, wire_form) in
        [("event", "cx:event:<uuid>"), ("space", "cx:space:<uuid>"), ("flow", "cx:flow:<uuid>")]
    {
        let entry = registry_entry(&bundle.id_kind_registry, "id_kinds", "kind", kind)
            .unwrap_or_else(|| panic!("missing id kind {kind}"));
        assert_eq!(entry["wire_form"].as_str(), Some(wire_form), "{kind}");
    }
}

#[test]
fn component_descriptor_resolves_canonical_and_alias_kinds() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();

    // Canonical kind owns its slot — no alias_of.
    let canonical = bundle
        .component("cx.capability.grant")
        .unwrap()
        .expect("cx.capability.grant should be registered");
    assert_eq!(canonical.criticality, Criticality::Required);
    assert!(canonical.component_type.starts_with("cx.component."));
    assert!(canonical.component_version >= 1);
    assert!(canonical.component_slot_alias_of.is_none());

    // Alias kind shares the canonical kind's slot.
    let alias = bundle
        .component("cx.capability.revoke")
        .unwrap()
        .expect("cx.capability.revoke should be registered");
    assert_eq!(
        alias.component_slot_alias_of.as_deref(),
        Some("cx.capability.grant"),
        "cx.capability.revoke should slot-alias cx.capability.grant"
    );
    assert_eq!(alias.component_type, canonical.component_type);
    assert_eq!(alias.component_version, canonical.component_version);

    // Unknown kind is a clean None, not an error.
    assert!(bundle.component("cx.bogus.kind").unwrap().is_none());
}

#[test]
fn evolution_plan_rejects_breaking_release_candidate() {
    let mut breaking_changes = BTreeSet::new();
    breaking_changes.insert(SchemaBreakingChange::NewRequiredField);
    let plan = SchemaEvolutionPlan {
        from_version: "0.1.0".to_owned(),
        to_version: "0.2.0".to_owned(),
        affected_schemas: vec![EVENT_SCHEMA.to_owned()],
        breaking_changes,
    };
    assert!(matches!(plan.validate_release_candidate(), Err(Error::Protocol(_))));
}
