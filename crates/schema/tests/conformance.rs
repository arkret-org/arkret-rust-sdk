use arkret_canonical::DigestSuite;
use arkret_schema::*;
use arkret_schema_conformance::{
    schema_registry_from_configured_spec_artifacts, spec_json_artifact,
};
use arkret_wire::generated::profile_requirements::non_event_grant_authority_rule;
use arkret_wire::{
    AuthoredEvent, BUILT_IN_CONFORMANCE_FIXTURES_VERSION, DidCoreId, DidUrl, Hash,
    ProducerEventProof, RealmId, SchemaId, ScopeRef,
};
use serde_json::json;

fn required_profiles() -> [ConformanceProfile; 11] {
    [
        ConformanceProfile::Encoding,
        ConformanceProfile::Hlc,
        ConformanceProfile::Cursor,
        ConformanceProfile::StateResolution,
        ConformanceProfile::Redaction,
        ConformanceProfile::Capability,
        ConformanceProfile::Sync,
        ConformanceProfile::RealmStateSnapshot,
        ConformanceProfile::FederationSignatures,
        ConformanceProfile::Privacy,
        ConformanceProfile::Security,
    ]
}

#[test]
fn protocol_schema_registry_publishes_core_json_schemas() {
    let registry = ProtocolSchemaRegistry::default();
    for schema_id in [
        SchemaId::CURSOR_V1,
        SchemaId::STRAND_V1,
        SchemaId::SPACE_V1,
        SchemaId::VIEW_V1,
        SchemaId::EVENT_V1,
        SchemaId::CAPABILITY_V1,
        SchemaId::ENCRYPTED_ENVELOPE_V1,
        SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1,
    ] {
        assert!(registry.schema(schema_id).is_some(), "{schema_id}");
    }

    registry
        .validate_value(
            SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1,
            &json!({
                "kind": "delta",
                "cursor": "ak:cursor:s1",
                "realms": {},
                "unknown_future_field": true
            }),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1, &json!({"realms": {}}))
            .is_err()
    );

    let event_shape = registry.generated_object_shape(SchemaId::EVENT_V1).unwrap();
    for field in [
        "event_id",
        "kind",
        "scope_ref",
        "actor_id",
        "created_at",
        "payload",
        "proofs",
    ] {
        assert!(
            event_shape
                .fields
                .iter()
                .any(|candidate| candidate.name == field && candidate.required),
            "{field}"
        );
    }
}

fn event_value() -> serde_json::Value {
    let realm_id = RealmId::new("ak:realm:AS_LTHQu5UtXbAIUOgUFzEY5nFJzI1cgPvxODB_NnHSR").unwrap();
    let created_at = "2026-05-02T00:00:00.000Z".parse().unwrap();
    let event = arkret_wire::test_support::raw_event_at(
        "ak.message.create",
        ScopeRef::Realm { realm_id },
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
        json!({
            "strand_id": "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "extension fixture"},
        }),
        created_at,
    )
    .unwrap();
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap();
    let event_digest = Hash::new(
        authored
            .event()
            .event_digest_with_digest_suite(DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    authored.attach_proof(ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture#key-1").unwrap(),
        event_digest: event_digest.clone(),
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&event_digest),
    });
    serde_json::to_value(authored.into_event()).unwrap()
}

#[test]
fn schema_registry_exposes_object_shape_metadata_and_uses_full_runtime_for_admission() {
    let mut registry = ProtocolSchemaRegistry::default();
    let shape = registry.generated_object_shape(SchemaId::EVENT_V1).unwrap();
    assert!(shape.fields.iter().any(|field| {
        field.name == "event_id"
            && field.required
            && field.value_type == SchemaValueTypeSummary::String
    }));

    registry.register(
        "ak.schema.strict.v1",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "ak.schema.strict.v1",
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
            "additionalProperties": false
        }),
    );
    registry
        .validate_value("ak.schema.strict.v1", &json!({"id": "1"}))
        .unwrap();
    assert!(
        registry
            .validate_value("ak.schema.strict.v1", &json!({"id": 1}))
            .is_err()
    );
    assert!(
        registry
            .validate_value("ak.schema.strict.v1", &json!({"id": "1", "extra": true}),)
            .is_err()
    );
}

#[test]
fn schema_registry_fails_closed_for_unknown_security_extensions() {
    let mut registry = schema_registry_from_configured_spec_artifacts().unwrap();
    let base_event = event_value();
    registry
        .validate_value(SchemaId::EVENT_V1, &base_event)
        .unwrap();

    let mut event = base_event.clone();
    event["x-security-critical"] = json!({"unknown": true});

    assert!(registry.validate_value(SchemaId::EVENT_V1, &event).is_err());
    registry.trust_extension_prefix("x-security-critical");
    assert!(
        registry.validate_value(SchemaId::EVENT_V1, &event).is_err(),
        "a trusted prefix does not override the formal Event schema's closed envelope"
    );

    let mut ordinary = base_event;
    ordinary["x-ui-hint"] = json!({"preserved": true});
    assert!(
        schema_registry_from_configured_spec_artifacts()
            .unwrap()
            .validate_value(SchemaId::EVENT_V1, &ordinary)
            .is_err(),
        "the formal Event envelope rejects every undeclared top-level extension"
    );
}

#[test]
fn profile_conformance_suites_cover_required_domains() {
    let suites = profile_conformance_suites();
    for profile in required_profiles() {
        assert!(
            suites
                .iter()
                .any(|suite| suite.profile == profile && !suite.cases.is_empty())
        );
    }
}

#[test]
fn applet_bridge_exposes_exact_non_event_grant_authority_rule() {
    let rule =
        non_event_grant_authority_rule("ak.profile.applet_bridge.v1", "ak.applet.ghost.provision")
            .expect("applet bridge rule must be generated");
    assert_eq!(rule.issuer_action, "ak.realm.admin");
    assert_eq!(
        rule.required_registration_event_kind,
        "ak.applet.registration"
    );
    assert_eq!(rule.required_constraint_subkind, "applet_authority");
    assert_eq!(rule.subject_binding, "registration.service_id");
    assert!(
        non_event_grant_authority_rule("ak.profile.applet_bridge.v1", "ak.message.create")
            .is_none()
    );
}

#[test]
fn builtin_conformance_report_is_machine_readable_and_covers_profiles() {
    let report = run_builtin_conformance_report();
    assert_eq!(
        report.fixture_version,
        BUILT_IN_CONFORMANCE_FIXTURES_VERSION
    );
    assert!(report.passed);
    for profile in required_profiles() {
        let coverage = report
            .coverage
            .iter()
            .find(|coverage| coverage.profile == profile)
            .unwrap();
        assert!(coverage.cases_total > 0);
        assert_eq!(coverage.cases_total, coverage.cases_passed);
    }

    let encoded = serde_json::to_value(report).unwrap();
    assert!(encoded["fixture_version"].is_string());
    assert!(encoded["results"].is_array());
}

#[test]
fn conformance_fixture_set_loads_and_reports_external_json() {
    let encoded = serde_json::to_value(ConformanceFixtureSet::builtin()).unwrap();
    let fixtures = ConformanceFixtureSet::from_json(encoded).unwrap();
    let report = fixtures.run();
    assert!(report.passed);
    assert_eq!(
        report.fixture_version,
        BUILT_IN_CONFORMANCE_FIXTURES_VERSION
    );

    let empty = serde_json::from_value::<ConformanceFixtureSet>(json!({
        "fixture_version": "",
        "suites": []
    }))
    .unwrap();
    assert!(empty.validate().is_err());
}

#[test]
fn generated_relation_kind_metadata_matches_configured_registry() {
    use arkret_wire::{RELATION_KIND_DESCRIPTORS, RelationKind, RelationTruthSourceClass};

    let registry = spec_json_artifact("registry/relation-kind-registry.json")
        .expect("configured relation registry");
    let relation_kinds = registry["relation_kinds"]
        .as_array()
        .expect("relation_kinds array");
    let mut registry_ids: Vec<&str> = relation_kinds
        .iter()
        .map(|row| row["canonical_id"].as_str().expect("canonical_id"))
        .collect();
    let mut sdk_ids: Vec<&str> = RELATION_KIND_DESCRIPTORS
        .iter()
        .map(|metadata| metadata.canonical_id)
        .collect();
    registry_ids.sort_unstable();
    sdk_ids.sort_unstable();
    assert_eq!(sdk_ids, registry_ids);

    for row in relation_kinds {
        let id = row["canonical_id"].as_str().expect("canonical_id");
        let metadata = RelationKind::from_wire(id)
            .descriptor()
            .expect("SDK descriptor row");
        assert_eq!(
            metadata.default_cardinality,
            row["default_cardinality"]
                .as_str()
                .expect("default_cardinality")
        );
        assert_eq!(
            metadata.truth_source_class,
            match row["truth_source_class"]
                .as_str()
                .expect("truth_source_class")
            {
                "canonical" => RelationTruthSourceClass::Canonical,
                "derived_projection" => RelationTruthSourceClass::DerivedProjection,
                "shape_dependent" => RelationTruthSourceClass::ShapeDependent,
                other => panic!("unexpected truth_source_class: {other}"),
            }
        );
        assert_eq!(
            metadata.weak_semantic,
            row["weak_semantic"].as_bool().expect("weak_semantic")
        );
    }
}
