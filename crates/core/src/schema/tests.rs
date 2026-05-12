use super::artifacts::registry_entry;
use super::*;

#[test]
fn schema_catalog_has_compatibility_for_all_registered_schemas() {
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
fn generated_validators_cover_core_schema_ids() {
    let validators = generated_validators().unwrap();
    for schema_id in CORE_SCHEMA_IDS {
        assert!(validators.contains_key(*schema_id), "{schema_id}");
    }
}

#[test]
fn spec_artifact_registry_covers_key_local_schema_and_event_contracts() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();
    bundle.drift_report().validate().unwrap();

    let schemas = bundle.schema_registry["schemas"].as_array().expect("schemas array");
    let schema_ids =
        schemas.iter().filter_map(|schema| schema["schema_id"].as_str()).collect::<BTreeSet<_>>();
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
