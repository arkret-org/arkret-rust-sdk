//! Relation authoring carriers stay isomorphic to the closed formal schemas.

use std::fs;
use std::path::PathBuf;

use arkret_models_collaboration::events_payloads::RelationCreatePayload;
use arkret_models_collaboration::objects::relation::RelationDefinition;
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn schema_value(file: &str) -> Value {
    let path = artifacts_dir().join("schemas").join(file);
    serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .expect("schema artifact must be valid JSON")
}

fn fragment_registry(file: &str, fragment: &str) -> (ProtocolSchemaRegistry, String) {
    let mut registry = schema_registry_from_spec_artifacts(artifacts_dir()).unwrap();
    let schema = schema_value(file);
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let schema_id = format!("test:{file}{}", fragment.replace('#', "@"));
    registry
        .register_fragment(schema_id.clone(), schema, fragment)
        .unwrap();
    (registry, schema_id)
}

fn assert_schema_and_serde<T>(file: &str, fragment: &str, value: Value)
where
    T: DeserializeOwned + serde::Serialize,
{
    let (registry, schema_id) = fragment_registry(file, fragment);
    registry.validate_value(&schema_id, &value).unwrap();
    let parsed: T = serde_json::from_value(value.clone()).expect("SDK must accept schema value");
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

fn definition() -> Value {
    json!({
        "scope_circle_id": "ak:circle:AUD2WOhX-Xh47vBHtRJPMRfXRQXGiOWQqOrJGJnE8CaI",
        "relation_kind": "references",
        "from_ref": "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
        "to_ref": "ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
        "rank": "U",
        "fields": {"note": "author supplied"}
    })
}

fn create_payload() -> Value {
    json!({
        "primary_conflict_domain": {
            "domain_kind": "tuple",
            "relation_kind": "references",
            "from_ref": "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
            "to_ref": "ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
        },
        "expected_revision": null,
        "relation": definition()
    })
}

#[test]
fn closed_definition_and_create_payload_round_trip_against_formal_fragments() {
    assert_schema_and_serde::<RelationDefinition>(
        "relation.schema.json",
        "#/$defs/relation_definition",
        definition(),
    );
    assert_schema_and_serde::<RelationCreatePayload>(
        "event-payload.schema.json",
        "#/$defs/relation_create_payload",
        create_payload(),
    );
}

#[test]
fn old_top_level_rank_and_materialized_members_fail_both_gates() {
    let (registry, schema_id) = fragment_registry(
        "event-payload.schema.json",
        "#/$defs/relation_create_payload",
    );

    let mut top_level_rank = create_payload();
    top_level_rank["rank"] = json!("V");
    assert!(
        registry
            .validate_value(&schema_id, &top_level_rank)
            .is_err()
    );
    assert!(serde_json::from_value::<RelationCreatePayload>(top_level_rank).is_err());

    for field in [
        "schema",
        "realm_id",
        "id",
        "effective_scope",
        "state",
        "state_changed_at",
        "created_by",
        "created_at",
        "updated_by",
        "updated_at",
    ] {
        let mut materialized = create_payload();
        materialized["relation"][field] = json!("forbidden");
        assert!(
            registry.validate_value(&schema_id, &materialized).is_err(),
            "formal schema must reject materialized member {field}"
        );
        assert!(
            serde_json::from_value::<RelationCreatePayload>(materialized).is_err(),
            "SDK must reject materialized member {field}"
        );
    }

    for rank in [String::new(), "rank-with-dash".to_owned(), "A".repeat(129)] {
        let mut invalid_rank = create_payload();
        invalid_rank["relation"]["rank"] = json!(&rank);
        assert!(registry.validate_value(&schema_id, &invalid_rank).is_err());
        assert!(serde_json::from_value::<RelationCreatePayload>(invalid_rank).is_err());
    }

    let mut nested_rank = create_payload();
    nested_rank["relation"]["fields"]["rank"] = json!("V");
    assert!(registry.validate_value(&schema_id, &nested_rank).is_err());
    assert!(serde_json::from_value::<RelationCreatePayload>(nested_rank).is_err());
}
