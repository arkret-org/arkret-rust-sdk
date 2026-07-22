use arkret_canonical::canonical;
use arkret_schema::*;
use arkret_wire::{BUILT_IN_CONFORMANCE_FIXTURES_VERSION, Did, Hash, Proof};
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
        ConformanceProfile::Snapshot,
        ConformanceProfile::FederationSignatures,
        ConformanceProfile::Privacy,
        ConformanceProfile::Security,
    ]
}

#[test]
fn protocol_schema_registry_publishes_core_json_schemas() {
    let registry = ProtocolSchemaRegistry::default();
    for schema_id in [
        CURSOR_SCHEMA,
        STRAND_SCHEMA,
        SPACE_SCHEMA,
        VIEW_SCHEMA,
        EVENT_SCHEMA,
        CAPABILITY_SCHEMA,
        ENCRYPTED_ENVELOPE_SCHEMA,
        ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
    ] {
        assert!(registry.schema(schema_id).is_some(), "{schema_id}");
    }

    registry
        .validate_value(
            ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
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
            .validate_value(ACCOUNT_SUBSCRIBE_FRAME_SCHEMA, &json!({"realms": {}}))
            .is_err()
    );

    let event_validator = registry.generated_validator(EVENT_SCHEMA).unwrap();
    for field in [
        "event_id",
        "space_id",
        "actor_id",
        "actor_seq",
        "kind",
        "created_at",
        "hlc",
        "prev_refs",
        "refs",
        "payload",
        "proofs",
    ] {
        assert!(
            event_validator
                .fields
                .iter()
                .any(|candidate| candidate.name == field && candidate.required),
            "{field}"
        );
    }
}

fn event_value() -> serde_json::Value {
    json!({
        "event_id": "ak:event:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "ak:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:webvh:z6mkfixture:alice.example",
        "kind": "ak.message.create",
        "actor_seq": 1,
        "created_at": "2026-05-02T00:00:00.000Z",
        "hlc": "01970e589d21-0000-a13f9c2e",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": [],
        "unknown_future_field": true
    })
}

#[test]
fn schema_registry_generates_runtime_validators_from_supported_schema_subset() {
    let mut registry = ProtocolSchemaRegistry::default();
    let validator = registry.generated_validator(EVENT_SCHEMA).unwrap();
    assert!(validator.fields.iter().any(|field| {
        field.name == "event_id"
            && field.required
            && field.value_type == GeneratedSchemaValueType::String
    }));
    validator.validate(&event_value()).unwrap();

    let mut wrong_type = event_value();
    wrong_type["prev_refs"] = json!({});
    assert!(validator.validate(&wrong_type).is_err());

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
    let warnings = registry
        .generated_validator("ak.schema.strict.v1")
        .unwrap()
        .validate_with_warnings(&json!({"id": "1", "extra": true}))
        .unwrap();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("additional field") && warning.contains("extra"))
    );
}

#[test]
fn schema_registry_fails_closed_for_unknown_security_extensions() {
    let mut registry = ProtocolSchemaRegistry::default();
    let mut event = event_value();
    event["x-security-critical"] = json!({"unknown": true});

    assert!(registry.validate_value(EVENT_SCHEMA, &event).is_err());
    registry.trust_extension_prefix("x-security-critical");
    registry.validate_value(EVENT_SCHEMA, &event).unwrap();

    let mut ordinary = event_value();
    ordinary["x-ui-hint"] = json!({"preserved": true});
    ProtocolSchemaRegistry::default()
        .validate_value(EVENT_SCHEMA, &ordinary)
        .unwrap();
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

#[cfg(feature = "embedded-artifacts")]
#[test]
fn signature_binding_payload_matches_spec_encoding_vector() {
    let fixture = embedded_json_artifact("fixtures/encoding-fixture.json").unwrap();
    let vector = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["vector_id"] == "ak.vector.encoding.signature_binding_payload.v1")
        .unwrap();
    let input = &vector["input"];
    let actor = Did::new(input["actor_id"].as_str().unwrap()).unwrap();
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: input["verification_method"].as_str().unwrap().to_owned(),
        event_digest: Hash::new(input["event_digest"].as_str().unwrap()).unwrap(),
        created_at: input["created_at"].as_str().unwrap().parse().unwrap(),
        domain: None,
        audience: None,
        jws: String::new(),
    };

    let binding_bytes = proof.canonical_binding_bytes(&actor).unwrap();
    assert_eq!(
        std::str::from_utf8(&binding_bytes).unwrap(),
        vector["expected_canonical_bytes_utf8"].as_str().unwrap()
    );
    assert_eq!(
        canonical::sha256_digest(&binding_bytes),
        vector["expected_digest"].as_str().unwrap()
    );
}
