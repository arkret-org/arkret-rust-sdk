use arkret_schema::ProtocolSchemaRegistry;
use serde_json::json;

#[test]
fn conflicting_reference_documents_report_both_sources_and_escaped_pointer() {
    let mut registry = ProtocolSchemaRegistry::new();
    let schema =
        json!({"$id": "https://example.test/schema", "properties": {"a/b~c": {"type": "string"}}});
    registry
        .register_reference_document_from(schema.clone(), "schemas/first.json")
        .unwrap();
    registry
        .register_reference_document_from(schema.clone(), "schemas/same.json")
        .unwrap();
    let mut changed = schema;
    changed["properties"]["a/b~c"]["type"] = json!("integer");
    let error = registry
        .register_reference_document_from(changed, "schemas/conflict.json")
        .unwrap_err()
        .to_string();
    assert!(error.contains("schemas/first.json"), "{error}");
    assert!(error.contains("schemas/conflict.json"), "{error}");
    assert!(error.contains("/properties/a~1b~0c/type"), "{error}");
}

#[test]
fn logical_schema_conflicts_do_not_replace_reference_documents() {
    let mut registry = ProtocolSchemaRegistry::new();
    let schema = json!({"$id": "https://example.test/schema", "type": "string"});
    registry
        .register_reference_document_from(schema.clone(), "schemas/source.json")
        .unwrap();
    let mut changed = schema;
    changed["type"] = json!("integer");
    registry.register("ak.schema.example.v1", changed);
    let error = registry
        .validate_value("ak.schema.example.v1", &json!(1))
        .unwrap_err()
        .to_string();
    assert!(error.contains("schemas/source.json"), "{error}");
    assert!(error.contains("ak.schema.example.v1"), "{error}");
    assert!(error.contains("/type"), "{error}");
}

#[test]
fn diagnostic_sources_do_not_change_registry_equality_or_serialization() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry
        .register_reference_document_from(
            json!({"$id": "https://example.test/schema", "type": "string"}),
            "private/source.json",
        )
        .unwrap();
    let encoded = serde_json::to_string(&registry).unwrap();
    assert!(!encoded.contains("private/source.json"));
    let decoded: ProtocolSchemaRegistry = serde_json::from_str(&encoded).unwrap();
    assert_eq!(registry, decoded);
}
