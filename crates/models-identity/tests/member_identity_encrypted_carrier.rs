use arkret_models_identity::member_identity::IdentityPayloadCarrier;
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

#[test]
fn encrypted_member_identity_preserves_the_registered_closed_carrier() {
    let artifacts = default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("fixtures/content-history-fixture.json")).unwrap(),
    )
    .unwrap();
    let value = json!({"encrypted_payload": fixture["kat"]["envelope"]});
    let schema: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("schemas/event-payload.schema.json")).unwrap(),
    )
    .unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    registry
        .register_fragment(
            "test:identity_carrier".to_owned(),
            schema,
            "#/$defs/member_identity_update_payload/properties/identity_payload",
        )
        .unwrap();
    assert!(
        registry
            .validate_value("test:identity_carrier", &value)
            .is_ok()
    );
    let typed: IdentityPayloadCarrier = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&typed).unwrap(), value);
    assert_eq!(
        typed.carrier_sha256().unwrap(),
        arkret_canonical::canonical_sha256(&value).unwrap()
    );
    for malformed in [
        json!({"encrypted_content": fixture["kat"]["envelope"]}),
        json!({"encrypted_payload": null}),
        json!({"encrypted_payload": fixture["kat"]["envelope"], "member_identity": {}}),
        json!({"encrypted_payload": {"ciphertext":"AA"}}),
    ] {
        assert!(
            registry
                .validate_value("test:identity_carrier", &malformed)
                .is_err()
        );
        assert!(serde_json::from_value::<IdentityPayloadCarrier>(malformed).is_err());
    }
}
