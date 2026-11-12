use super::*;

#[test]
fn keyword_transport_is_lossless_including_boolean_and_ref_siblings() {
    let source = serde_json::json!({
        "conditional": {"$ref":"#/components/schemas/never", "if":{"const":null},
            "then":false, "else":{"unevaluatedProperties":false},
            "x-literal":{"$ref":"this is instance data"}, "default":null},
        "never":false, "unconstrained":true, "text":{"type":"string"},
    });
    let mut components = Components::default();
    register_components(&mut components, &decode_components(&source.to_string()));
    register_components(&mut components, &decode_components(&source.to_string()));
    assert_eq!(serde_json::to_value(components.schemas).unwrap(), source);
}

#[test]
fn collision_rejection_is_atomic_for_existing_and_duplicate_batch_names() {
    let mut components = Components::default();
    register_components(&mut components, &decode_components(r#"{"z":false}"#));
    let before = components.clone();
    for batch in [
        decode_components(r#"{"a":true,"z":true}"#),
        vec![
            ("a".into(), Schema::Boolean(true)),
            ("a".into(), Schema::Boolean(false)),
        ],
    ] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                register_components(&mut components, &batch);
            }))
            .is_err()
        );
        assert_eq!(components, before);
    }
}
