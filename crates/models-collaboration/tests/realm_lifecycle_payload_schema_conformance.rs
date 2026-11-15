use std::fs;

use arkret_models_collaboration::governance::realm_lifecycle::{
    RealmDiscoverability, RealmDiscoveryPayload, RealmJoinRulePayload, RealmJoinRuleValue,
};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde_json::{Value, json};

fn schema_accepts(fragment: &str, value: &Value) -> bool {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/event-payload.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(
            format!("test:{fragment}"),
            schema,
            format!("#/$defs/{fragment}"),
        )
        .unwrap();
    registry
        .validate_value(&format!("test:{fragment}"), value)
        .is_ok()
}

#[test]
fn realm_join_rule_and_discovery_have_only_formal_author_fields() {
    let join = serde_json::to_value(RealmJoinRulePayload::new(RealmJoinRuleValue::Invite)).unwrap();
    let discovery =
        serde_json::to_value(RealmDiscoveryPayload::new(RealmDiscoverability::Secret)).unwrap();
    assert_eq!(join, json!({"value": "invite"}));
    assert_eq!(discovery, json!({"value": {"discoverability": "secret"}}));

    for (fragment, valid) in [
        ("realm_join_rule_payload", join),
        ("realm_discovery_payload", discovery),
    ] {
        assert!(schema_accepts(fragment, &valid));
        for retired_field in ["state", "reason"] {
            let mut invalid = valid.clone();
            invalid[retired_field] = json!("author supplied");
            assert!(!schema_accepts(fragment, &invalid));
            match fragment {
                "realm_join_rule_payload" => {
                    assert!(serde_json::from_value::<RealmJoinRulePayload>(invalid).is_err());
                }
                _ => {
                    assert!(serde_json::from_value::<RealmDiscoveryPayload>(invalid).is_err());
                }
            }
        }
    }
}

#[test]
fn member_count_hysteresis_counts_match_the_exact_formal_boundaries() {
    use arkret_models_collaboration::governance::realm_lifecycle::MemberCountHysteresis;
    for value in [
        json!({"absolute_count":2}),
        json!({"ratio_basis_points":1000}),
        json!({"ratio_basis_points":10000}),
    ] {
        let count: MemberCountHysteresis = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(count).unwrap(), value);
    }
    for value in [
        json!({}),
        json!({"absolute_count":null}),
        json!({"absolute_count":0}),
        json!({"absolute_count":1}),
        json!({"ratio_basis_points":null}),
        json!({"ratio_basis_points":999}),
        json!({"ratio_basis_points":10001}),
        json!({"absolute":2}),
    ] {
        assert!(serde_json::from_value::<MemberCountHysteresis>(value).is_err());
    }
    let invalid = MemberCountHysteresis {
        absolute_count: Some(1),
        ratio_basis_points: None,
    };
    assert!(serde_json::to_value(invalid).is_err());
}
