//! Machine gate: a hand-written request/response DTO's field set MUST equal the
//! property set its spec `$defs` entry declares.
//!
//! Why this exists: `EventsQueryPostRequestBody` once shipped without
//! `include_completeness` while both the schema and the GET query binding
//! declared it, so the typed POST body could not express a request the GET
//! client could. The schema release gate stayed green throughout, because
//! nothing compared the two field sets — the spec's claim that the GET and POST
//! forms are `binding_variant_of` each other lived only in prose.
//!
//! The comparison is exact in both directions:
//!
//! - a schema property the DTO cannot carry is a missing capability;
//! - a DTO field the schema does not declare is a field no peer will accept.
//!
//! Adding a DTO to the gate means one `assert_dto_matches_schema` call with a
//! fully-populated instance. The instance MUST set every optional field, since
//! `skip_serializing_if` hides `None` from the serialized form; deserializing
//! the fixture (rather than constructing it field by field) also proves the DTO
//! accepts every declared property on the wire.

use std::collections::BTreeSet;

use arkret_models_collaboration::event_query::EventsQueryPostRequestBody;
use serde::Serialize;
use serde_json::{Value, json};

/// Spec artifact holding the service operation request/response DTOs.
const SERVICE_OPERATION_DTOS: &str = "schemas/service-operation-dtos.schema.json";

/// Field names declared by `<artifact>#/$defs/<definition>/properties`.
fn schema_property_names(artifact: &str, definition: &str) -> BTreeSet<String> {
    let schema = arkret_schema::embedded_json_artifact(artifact)
        .unwrap_or_else(|error| panic!("embedded artifact {artifact} failed to load: {error}"));
    let properties = schema
        .get("$defs")
        .and_then(|defs| defs.get(definition))
        .and_then(|definition| definition.get("properties"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| panic!("{artifact}#/$defs/{definition}/properties is missing"));
    properties.keys().cloned().collect()
}

/// Field names a fully-populated instance actually serializes.
fn serialized_field_names<T: Serialize>(fully_populated: &T) -> BTreeSet<String> {
    serde_json::to_value(fully_populated)
        .expect("DTO serializes")
        .as_object()
        .expect("DTO serializes to a JSON object")
        .keys()
        .cloned()
        .collect()
}

/// Assert the DTO carries exactly the fields its schema definition declares.
fn assert_dto_matches_schema<T: Serialize>(artifact: &str, definition: &str, fully_populated: &T) {
    let declared = schema_property_names(artifact, definition);
    let carried = serialized_field_names(fully_populated);

    let missing: Vec<&String> = declared.difference(&carried).collect();
    assert!(
        missing.is_empty(),
        "{definition} cannot carry schema-declared field(s) {missing:?}; \
         either the DTO is behind the schema or the fixture forgot to populate them"
    );
    let undeclared: Vec<&String> = carried.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "{definition} serializes field(s) {undeclared:?} that {artifact} does not declare; \
         no conforming peer will accept them"
    );
}

/// `$defs/Cursor` is `^ak:cursor:[A-Za-z0-9_-]+$` — an opaque token the client
/// carries verbatim. Any syntactically valid value serves here.
fn sample_cursor() -> Value {
    json!("ak:cursor:c2FtcGxlLWhhbmRsZQ")
}

#[test]
fn events_query_post_request_body_matches_its_schema_definition() {
    let fully_populated: EventsQueryPostRequestBody = serde_json::from_value(json!({
        "realms": ["ak:realm:01904100-0000-7000-8000-000000000001"],
        "actors": ["did:web:alice.example"],
        "before": sample_cursor(),
        "after": sample_cursor(),
        "order": "descending",
        "limit": 50,
        "filters": { "kind": "ak.message.create" },
        "include_completeness": true
    }))
    .expect("every schema-declared field is accepted by the typed POST body");

    assert_dto_matches_schema(
        SERVICE_OPERATION_DTOS,
        "EventsQueryPostRequestBody",
        &fully_populated,
    );
}

/// Guard the guard: a DTO behind its schema must fail the comparison rather
/// than pass silently. Without this, a bug in `schema_property_names` (an
/// artifact rename, a `$defs` restructure) would turn the gate into a no-op
/// that reports success for every DTO.
#[test]
fn the_gate_detects_a_dto_missing_a_declared_field() {
    #[derive(Serialize)]
    struct BehindTheSchema {
        realms: Vec<String>,
    }

    let declared = schema_property_names(SERVICE_OPERATION_DTOS, "EventsQueryPostRequestBody");
    let carried = serialized_field_names(&BehindTheSchema {
        realms: vec!["ak:realm:01904100-0000-7000-8000-000000000001".to_owned()],
    });
    let missing: Vec<&String> = declared.difference(&carried).collect();
    assert!(
        missing.contains(&&"include_completeness".to_owned()),
        "the coverage comparison must notice a dropped field, got {missing:?}"
    );
}
