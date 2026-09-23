use std::fs;

use arkret_models_identity::account::AccountDeviceSummary;
use arkret_models_identity::artifacts_account::DeviceSummary;
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

fn validates_schema(value: &Value) -> bool {
    let artifacts = default_spec_artifacts_dir().expect("spec artifacts checkout");
    let mut registry: ProtocolSchemaRegistry =
        schema_registry_from_spec_artifacts(&artifacts).expect("schema registry");
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/account-operations.schema.json")).expect("schema file"),
    )
    .expect("schema JSON");
    registry
        .register_reference_document(schema.clone())
        .expect("schema id");
    registry
        .register_fragment(
            "test:device_summary".to_owned(),
            schema,
            "#/$defs/device_summary",
        )
        .expect("device summary fragment");
    registry
        .validate_value("test:device_summary", value)
        .is_ok()
}

#[test]
fn verified_device_summary_uses_exact_published_fields() {
    let value = json!({
        "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
        "status": "active",
        "verification_state": "verified",
        "verification_source": "pairing_code",
        "authorized_event_ref": "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        "signer_resolution_evidence_ref": format!("ak:signer_evidence:sha256:{}", "a".repeat(64))
    });
    assert!(validates_schema(&value));
    let identity: DeviceSummary = serde_json::from_value(value.clone()).unwrap();
    identity.validate().unwrap();
    assert_eq!(serde_json::to_value(identity).unwrap(), value);
    let account: AccountDeviceSummary = serde_json::from_value(value.clone()).unwrap();
    account.validate().unwrap();
    assert_eq!(serde_json::to_value(account).unwrap(), value);

    let mut missing_evidence = value.clone();
    missing_evidence
        .as_object_mut()
        .unwrap()
        .remove("signer_resolution_evidence_ref");
    assert!(!validates_schema(&missing_evidence));
    let parsed: AccountDeviceSummary = serde_json::from_value(missing_evidence).unwrap();
    assert!(parsed.validate().is_err());

    let mut retired = value;
    retired["authorization_ref"] = json!("retired");
    assert!(!validates_schema(&retired));
    assert!(serde_json::from_value::<DeviceSummary>(retired.clone()).is_err());
    assert!(serde_json::from_value::<AccountDeviceSummary>(retired).is_err());
}
