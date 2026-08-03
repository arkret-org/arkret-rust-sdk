use arkret_schema::{
    ProtocolSchemaRegistry, SchemaError, SchemaValidationReason, embedded_json_artifact,
    schema_registry_from_spec_artifacts,
};
use serde_json::{Value, json};

const STRING_PROFILE_FIXTURE: &str = "fixtures/string-profile-fixture.json";
const STRING_PROFILE_SCHEMA: &str = "schemas/string-profiles.schema.json";
const PROPERTY_PRESENCE_MANIFEST: &str = "reports/property-presence-manifest.json";

/// Load one spec artifact from the live checkout, falling back to the embedded snapshot.
fn spec_artifact(relative_path: &str) -> Option<Value> {
    if let Ok(artifacts_dir) = std::env::var("ARKRET_SPEC_ARTIFACTS") {
        let path = std::path::Path::new(&artifacts_dir).join(relative_path);
        let raw = std::fs::read_to_string(path).expect("live spec artifact must be readable");
        return Some(serde_json::from_str(&raw).expect("live spec artifact must be JSON"));
    }
    embedded_json_artifact(relative_path).ok()
}

#[test]
fn presence_manifest_summary_matches_targets_and_has_one_explicit_distinct_sdk_target() {
    let Some(manifest) = spec_artifact(PROPERTY_PRESENCE_MANIFEST) else {
        return;
    };
    let targets = manifest["tristate_audit_targets"]
        .as_array()
        .expect("tristate_audit_targets must be an array");
    let summary = manifest["summary"]["tristate_sdk_dispositions"]
        .as_object()
        .expect("tristate_sdk_dispositions must be an object");
    let dispositions = ["absent_null_equivalent", "condition_guarded", "distinct"];
    assert_eq!(summary.len(), dispositions.len());
    assert!(targets.iter().all(|target| {
        dispositions.contains(&target["sdk_disposition"].as_str().unwrap_or_default())
    }));
    for disposition in dispositions {
        let actual = targets
            .iter()
            .filter(|target| target["sdk_disposition"] == disposition)
            .count() as u64;
        assert_eq!(summary[disposition].as_u64(), Some(actual));
    }
    let distinct = targets
        .iter()
        .filter(|target| target["sdk_disposition"] == "distinct")
        .collect::<Vec<_>>();
    assert_eq!(distinct.len(), 1);
    assert_eq!(distinct[0]["schema_file"], "event-payload.schema.json");
    assert_eq!(distinct[0]["shape"], "/$defs/circle_member_state_payload");
    assert_eq!(distinct[0]["instance_path"], "/expected_membership");
}

#[test]
fn runtime_enforces_draft_2020_12_keywords_and_standard_formats() {
    let cases = [
        (
            "prefix-items",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "array",
                "prefixItems": [{"const": "v1"}, {"type": "integer"}],
                "items": false
            }),
            json!(["v1", 1]),
            json!(["v2", 1]),
        ),
        (
            "dependent-required",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "dependentRequired": {"credit_card": ["billing_address"]}
            }),
            json!({"credit_card": 1, "billing_address": "somewhere"}),
            json!({"credit_card": 1}),
        ),
        (
            "unevaluated-properties",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "allOf": [
                    {"properties": {"left": {"type": "string"}}},
                    {"properties": {"right": {"type": "integer"}}}
                ],
                "unevaluatedProperties": false
            }),
            json!({"left": "ok", "right": 1}),
            json!({"left": "ok", "right": 1, "extra": true}),
        ),
        (
            "one-of-exactly-one",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "oneOf": [{"type": "integer"}, {"type": "number"}]
            }),
            json!(1.5),
            json!(1),
        ),
        (
            "uri-format",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "string",
                "format": "uri"
            }),
            json!("https://arkret.org/v1"),
            json!("not a uri"),
        ),
    ];

    for (schema_id, schema, valid, invalid) in cases {
        let mut registry = ProtocolSchemaRegistry::new();
        registry.register(schema_id, schema);
        registry.validate_value(schema_id, &valid).unwrap();
        assert!(
            registry.validate_value(schema_id, &invalid).is_err(),
            "{schema_id} must reject {invalid}"
        );
    }
}

/// The eight Arkret string formats are driven by the normative spec fixture.
///
/// `string-profile-fixture.json` is the single positive/negative vector set
/// shared with the spec lint, so this test never restates values locally. Each
/// `profile_validator` negative is additionally replayed against the same
/// definition with `format` stripped: it must pass there, which proves the
/// coarse JSON Schema shape alone cannot reject it and the custom format
/// assertion carries the normative semantics.
#[test]
fn runtime_enforces_arkret_custom_string_formats_from_spec_vectors() {
    let (Some(fixture), Some(profiles)) = (
        spec_artifact(STRING_PROFILE_FIXTURE),
        spec_artifact(STRING_PROFILE_SCHEMA),
    ) else {
        return;
    };

    let vectors = fixture["vectors"]
        .as_array()
        .expect("fixture must declare vectors");
    assert_eq!(
        vectors.len(),
        profiles["$defs"]
            .as_object()
            .expect("string profiles schema must declare $defs")
            .values()
            .filter(|node| node.get("format").is_some())
            .count(),
        "every declared custom format needs a vector"
    );

    for vector in vectors {
        let format = vector["format"].as_str().expect("vector needs a format");
        let pointer = vector["schema_ref"]
            .as_str()
            .and_then(|schema_ref| schema_ref.split_once('#'))
            .map(|(_, fragment)| format!("#{fragment}"))
            .expect("vector needs a schema_ref fragment");
        let definition = profiles
            .pointer(pointer.trim_start_matches('#'))
            .unwrap_or_else(|| panic!("{pointer} must exist in the string profiles schema"))
            .clone();

        let mut registry = ProtocolSchemaRegistry::new();
        registry
            .register_fragment(format, profiles.clone(), &pointer)
            .expect("string profile fragment must register");

        let mut shape_only = definition;
        shape_only
            .as_object_mut()
            .expect("string profile definition must be an object")
            .remove("format");
        let shape_only_id = format!("{format}-shape-only");
        registry.register(&shape_only_id, shape_only);

        for accepted in vector["accepted"]
            .as_array()
            .expect("vector needs accepted values")
        {
            registry
                .validate_value(format, accepted)
                .unwrap_or_else(|error| panic!("{format} must accept {accepted}: {error}"));
        }

        for rejected in vector["rejected"]
            .as_array()
            .expect("vector needs rejected values")
        {
            let value = &rejected["value"];
            assert!(
                registry.validate_value(format, value).is_err(),
                "{format} must reject {value}"
            );
            if rejected["rejected_by"] == "profile_validator" {
                registry
                    .validate_value(&shape_only_id, value)
                    .unwrap_or_else(|error| {
                        panic!(
                            "{format} declares {value} as profile-only, but the coarse shape \
                             already rejects it: {error}"
                        )
                    });
            }
        }
    }
}

#[test]
fn validation_errors_are_structured_and_cache_metrics_are_observable() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry.register(
        "structured-error",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"name": {"type": "string", "minLength": 2}},
            "required": ["name"]
        }),
    );

    registry
        .validate_value("structured-error", &json!({"name": "ok"}))
        .unwrap();
    registry
        .validate_value("structured-error", &json!({"name": "yes"}))
        .unwrap();
    let error = registry
        .validate_value("structured-error", &json!({"name": "x"}))
        .unwrap_err();
    let SchemaError::Validation(issue) = error else {
        panic!("expected a structured validation issue");
    };
    assert_eq!(issue.schema_id, "structured-error");
    assert_eq!(issue.instance_pointer, "/name");
    assert_eq!(issue.keyword, "minLength");
    assert_eq!(issue.reason, SchemaValidationReason::InstanceInvalid);
    assert!(issue.schema_pointer.ends_with("/minLength"));
    assert!(!issue.message.contains("\"x\""));

    let stats = registry.validator_stats();
    assert_eq!(stats.cache_misses, 1);
    assert_eq!(stats.cache_hits, 2);
    assert_eq!(stats.compiled_validators, 1);
    assert_eq!(stats.cache_hit_ratio(), Some(2.0 / 3.0));
}

#[test]
fn runtime_resolves_external_refs_and_enforces_ref_siblings() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry.register(
        "base",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.test/base.schema.json",
            "type": "string"
        }),
    );
    registry.register(
        "root",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.test/root.schema.json",
            "$ref": "base.schema.json",
            "maxLength": 3
        }),
    );

    registry.validate_value("root", &json!("ok")).unwrap();
    assert!(registry.validate_value("root", &json!("four")).is_err());
    assert!(registry.validate_value("root", &json!(4)).is_err());

    registry.register(
        "base",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.test/base.schema.json",
            "type": "integer"
        }),
    );
    registry.validate_value("root", &json!(4)).unwrap();
    assert!(registry.validate_value("root", &json!("ok")).is_err());
}

#[test]
fn logical_schema_ids_can_target_registered_document_fragments() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry
        .register_fragment(
            "logical-operation",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://example.test/operations.schema.json",
                "$defs": {
                    "operation": {
                        "type": "object",
                        "required": ["kind"],
                        "properties": {"kind": {"const": "create"}},
                        "additionalProperties": false
                    }
                }
            }),
            "#/$defs/operation",
        )
        .unwrap();

    assert_eq!(
        registry
            .schema("logical-operation")
            .and_then(|schema| schema.get("type"))
            .and_then(Value::as_str),
        Some("object")
    );
    registry
        .validate_value("logical-operation", &json!({"kind": "create"}))
        .unwrap();
    assert!(
        registry
            .validate_value("logical-operation", &json!({"kind": "delete"}))
            .is_err()
    );
}

#[test]
fn live_spec_catalog_compiles_when_explicitly_available() {
    let Ok(artifacts_dir) = std::env::var("ARKRET_SPEC_ARTIFACTS") else {
        return;
    };
    let registry = schema_registry_from_spec_artifacts(artifacts_dir).unwrap();
    registry.ensure_all_schemas_compile().unwrap();
}
