use std::fs;

use arkret_models_collaboration::governance::circle::{CircleList, CircleReadView};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

const CIRCLE: &str = "ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const REALM: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/circle-operations.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            format!("test:circle-{fragment}"),
            schema,
            format!("#/$defs/{fragment}"),
        )
        .unwrap();
    registry
        .validate_value(&format!("test:circle-{fragment}"), value)
        .is_ok()
}

#[test]
fn preview_and_list_have_one_closed_wire_shape() {
    let preview = json!({
        "circle_id": CIRCLE,
        "realm_id": REALM,
        "visibility": "realm_members",
        "display": {"color_token": "blue", "symbol": {"glyph": "lock"}},
        "member_count_bucket": "2-3",
        "join_rule": "public",
        "opaque_commitment": "a".repeat(64)
    });
    assert!(schema_accepts("circle_preview", &preview));
    assert!(schema_accepts("circle_read_view", &preview));
    assert!(!schema_accepts("circle_view", &preview));
    let read: CircleReadView = serde_json::from_value(preview.clone()).unwrap();
    assert_eq!(serde_json::to_value(read).unwrap(), preview);

    let list = json!({"realm_id": REALM, "circles": [preview.clone()]});
    assert!(schema_accepts("circle_list", &list));
    let parsed: CircleList = serde_json::from_value(list.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), list);

    let mut leaked = preview.clone();
    leaked["title"] = json!("private");
    assert!(!schema_accepts("circle_read_view", &leaked));
    assert!(serde_json::from_value::<CircleReadView>(leaked).is_err());
    let mut bad_digest = preview.clone();
    bad_digest["opaque_commitment"] = json!("A".repeat(64));
    assert!(!schema_accepts("circle_read_view", &bad_digest));
    assert!(serde_json::from_value::<CircleReadView>(bad_digest).is_err());
    let mut bad_visibility = preview.clone();
    bad_visibility["visibility"] = json!("members");
    assert!(!schema_accepts("circle_read_view", &bad_visibility));
    assert!(serde_json::from_value::<CircleReadView>(bad_visibility).is_err());
    let old_wire = json!({"realm_id": REALM, "circle_views": [preview]});
    assert!(!schema_accepts("circle_list", &old_wire));
    assert!(serde_json::from_value::<CircleList>(old_wire).is_err());
}
