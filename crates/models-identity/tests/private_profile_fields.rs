use arkret_models_identity::{ActorProfile, ActorProfileDefinition, PrivateProfileFields};
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

#[test]
fn private_profile_preserves_its_typed_original_and_rejects_null_or_realm_owner() {
    let artifacts = default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("fixtures/content-history-fixture.json")).unwrap(),
    )
    .unwrap();
    let value = json!({
        "principal_id":"ak:did_core:webvh:z6mkfixture", "actor_kind":"user",
        "display_name":"Public name", "encrypted_private_fields":fixture["kat"]["envelope"]
    });
    let definition: ActorProfileDefinition = serde_json::from_value(value.clone()).unwrap();
    definition.validate().unwrap();
    assert_eq!(serde_json::to_value(&definition).unwrap(), value);
    let realm = serde_json::from_value(fixture["kat"]["outer_event"]["realm_id"].clone()).unwrap();
    let id = arkret_wire::ActorProfileId::from_event_id(
        &serde_json::from_value(fixture["kat"]["root_context"]["genesis_event_ref"].clone())
            .unwrap(),
    );
    let profile =
        ActorProfile::materialize_create(definition.clone(), id, realm, chrono::Utc::now())
            .unwrap();
    assert_eq!(
        profile.encrypted_private_fields,
        definition.encrypted_private_fields
    );
    let mut null_slot = value;
    null_slot["encrypted_private_fields"] = Value::Null;
    assert!(serde_json::from_value::<ActorProfileDefinition>(null_slot).is_err());
    let mut realm_definition = definition;
    realm_definition.principal_id = None;
    realm_definition.actor_kind = arkret_wire::ActorKind::Bot;
    realm_definition.actor_id = Some(
        serde_json::from_value(json!({
            "kind":"realm", "realm_actor_id":{
                "realm_id":fixture["kat"]["outer_event"]["realm_id"],
                "principal_id":"ak:did_core:webvh:z6mkfixture"
            }
        }))
        .unwrap(),
    );
    assert!(realm_definition.validate().is_err());
}

#[test]
fn private_plaintext_requires_the_closed_wrapper_and_profile_text_bounds() {
    let artifacts = default_spec_artifacts_dir().unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("schemas/actor-profile.schema.json")).unwrap(),
    )
    .unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    registry
        .register_fragment(
            "test:private_profile".to_owned(),
            schema,
            "#/$defs/private_profile_fields",
        )
        .unwrap();
    for value in [
        json!({"profile_fields":{}}),
        json!({"profile_fields":{"biography":"private"}}),
    ] {
        registry
            .validate_value("test:private_profile", &value)
            .unwrap();
        let decoded: PrivateProfileFields = serde_json::from_value(value.clone()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    }
    for value in [
        json!({}),
        json!({"profile_fields":{},"device_authorization":{}}),
    ] {
        assert!(
            registry
                .validate_value("test:private_profile", &value)
                .is_err()
        );
        assert!(serde_json::from_value::<PrivateProfileFields>(value).is_err());
    }
    let oversized = json!({"profile_fields":{"biography":"x".repeat(257)}});
    assert!(
        registry
            .validate_value("test:private_profile", &oversized)
            .is_err()
    );
    assert!(
        serde_json::from_value::<PrivateProfileFields>(oversized)
            .unwrap()
            .validate()
            .is_err()
    );
}
