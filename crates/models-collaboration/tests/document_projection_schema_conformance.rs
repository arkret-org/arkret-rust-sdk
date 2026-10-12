//! Projection carriers must match the actual normative View schema.

use std::fs;

use arkret_models_collaboration::objects::query_projection::{
    DocumentMorphProjectionOutcome, StateRevision,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value =
        serde_json::from_slice(&fs::read(artifacts.join("schemas/view.schema.json")).unwrap())
            .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    let id = format!("test:view-{fragment}");
    registry
        .register_fragment(&id, schema, format!("#/$defs/{fragment}"))
        .unwrap();
    registry.validate_value(&id, value).is_ok()
}

fn projection() -> Value {
    json!({
        "document": {
            "morph_id": "ak:morph:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0",
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "morph_kind": "document", "state": "active", "body": null
        },
        "versions": [], "relations": [], "comments": [],
        "checkpoint": {"state_digest": format!("sha256:{}", "a".repeat(64))}
    })
}

#[test]
fn document_projection_serializes_the_normative_required_wire_fields() {
    let value = projection();
    assert!(schema_accepts("document_morph_projection_outcome", &value));
    let parsed: DocumentMorphProjectionOutcome = serde_json::from_value(value.clone()).unwrap();
    let serialized = serde_json::to_value(parsed).unwrap();
    assert_eq!(serialized, value);
    assert!(schema_accepts(
        "document_morph_projection_outcome",
        &serialized
    ));

    let mut without_checkpoint = value;
    without_checkpoint
        .as_object_mut()
        .unwrap()
        .remove("checkpoint");
    assert!(schema_accepts(
        "document_morph_projection_outcome",
        &without_checkpoint
    ));
    let parsed: DocumentMorphProjectionOutcome =
        serde_json::from_value(without_checkpoint.clone()).unwrap();
    assert!(parsed.checkpoint.is_none());
    assert_eq!(serde_json::to_value(parsed).unwrap(), without_checkpoint);
}

#[test]
fn required_projection_arrays_are_not_invented_when_missing() {
    for field in ["document", "versions", "relations", "comments"] {
        let mut missing = projection();
        missing.as_object_mut().unwrap().remove(field);
        assert!(!schema_accepts(
            "document_morph_projection_outcome",
            &missing
        ));
        assert!(serde_json::from_value::<DocumentMorphProjectionOutcome>(missing).is_err());
    }
}

#[test]
fn server_projection_rejects_unregistered_cursor_presence_fields() {
    for field in ["cursor_presence", "cursor_presence_entries"] {
        let mut unknown = projection();
        unknown[field] = json!([]);
        assert!(!schema_accepts(
            "document_morph_projection_outcome",
            &unknown
        ));
        assert!(serde_json::from_value::<DocumentMorphProjectionOutcome>(unknown).is_err());
    }
}

#[test]
fn checkpoint_requires_the_normative_digest_and_preserves_optional_heads() {
    let value = json!({"state_digest": format!("sha256:{}", "a".repeat(64))});
    assert!(schema_accepts("state_revision", &value));
    let parsed: StateRevision = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);

    let absent_digest = json!({"stream_heads": []});
    assert!(!schema_accepts("state_revision", &absent_digest));
    assert!(serde_json::from_value::<StateRevision>(absent_digest).is_err());
    let malformed_digest = json!({"state_digest": "a".repeat(64)});
    assert!(!schema_accepts("state_revision", &malformed_digest));
    assert!(serde_json::from_value::<StateRevision>(malformed_digest).is_err());

    let other_suite = json!({"state_digest": format!("blake3:{}", "a".repeat(64))});
    assert!(!schema_accepts("state_revision", &other_suite));
    assert!(serde_json::from_value::<StateRevision>(other_suite).is_err());
    let locally_constructed = StateRevision {
        state_digest: arkret_wire::Hash::new(format!("blake3:{}", "a".repeat(64))).unwrap(),
        stream_heads: Vec::new(),
    };
    assert!(serde_json::to_value(locally_constructed).is_err());

    let mut unknown = value;
    unknown["generation"] = json!(1);
    assert!(!schema_accepts("state_revision", &unknown));
    assert!(serde_json::from_value::<StateRevision>(unknown).is_err());
}
