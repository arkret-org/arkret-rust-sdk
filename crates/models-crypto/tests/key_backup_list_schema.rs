//! `KeysBackupsList.active_series` carries exactly one backup class.
//!
//! Every case is decided twice: by the live Spec schema
//! `keys-operations.schema.json#/$defs/keys_backups_list` and by the SDK DTO.
//! The two must agree, so an `mls_history` or private class member, or an
//! open pointer branch, cannot be accepted by the Rust type while the closed
//! schema rejects it (key-management §7.5.0 / §7.6.1, decision 0097).

use std::fs;

use arkret_models_crypto::{BackupActiveSeriesPointer, KeysBackupsList};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

const LIST_SCHEMA: &str = "test:keys_backups_list";
const SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-000000000000";

fn registry() -> ProtocolSchemaRegistry {
    let artifacts = default_spec_artifacts_dir().expect("spec artifacts checkout");
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(artifacts.join("schemas/keys-operations.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_reference_document(schema.clone())
        .unwrap();
    registry
        .register_fragment(LIST_SCHEMA, schema, "#/$defs/keys_backups_list")
        .unwrap();
    registry
}

fn list(pointer: Value) -> Value {
    json!({
        "backups": [],
        "active_series": {
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "control_realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "authority_commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "secret_storage": pointer
        },
        "has_more": false
    })
}

fn absent() -> Value {
    json!({"state": "absent"})
}

fn active(version: Value) -> Value {
    json!({"state": "active", "active_series_id": SERIES, "series_pointer_version": version})
}

fn decide(registry: &ProtocolSchemaRegistry, value: &Value) -> (bool, bool) {
    let schema = registry.validate_value(LIST_SCHEMA, value).is_ok();
    let sdk = serde_json::from_value::<KeysBackupsList>(value.clone()).is_ok();
    (schema, sdk)
}

#[test]
fn schema_and_dto_accept_only_the_secret_storage_pointer_branches() {
    let registry = registry();
    for accepted in [
        list(absent()),
        list(active(json!(1))),
        list(active(json!(7))),
    ] {
        assert_eq!(decide(&registry, &accepted), (true, true), "{accepted}");
        let parsed: KeysBackupsList = serde_json::from_value(accepted.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);
    }

    let parsed: KeysBackupsList = serde_json::from_value(list(active(json!(3)))).unwrap();
    assert_eq!(
        parsed.active_series.secret_storage,
        BackupActiveSeriesPointer::Active {
            active_series_id: arkret_wire::BackupSeriesId::new(SERIES).unwrap(),
            series_pointer_version: 3,
        }
    );
}

#[test]
fn schema_and_dto_reject_every_other_backup_class_and_open_pointer() {
    let registry = registry();
    let mut rejected = Vec::new();

    for class in ["mls_history", "org_example_private", "x-private"] {
        for pointer in [absent(), active(json!(1))] {
            let mut extra = list(absent());
            extra["active_series"][class] = pointer;
            rejected.push((format!("extra class {class}"), extra));
        }
        let mut renamed = list(absent());
        let object = renamed["active_series"].as_object_mut().unwrap();
        let moved = object.remove("secret_storage").unwrap();
        object.insert(class.to_owned(), moved);
        rejected.push((format!("secret_storage renamed to {class}"), renamed));
    }

    let mut missing = list(absent());
    missing["active_series"]
        .as_object_mut()
        .unwrap()
        .remove("secret_storage");
    rejected.push(("secret_storage omitted".to_owned(), missing));

    let mut per_class_map = list(absent());
    per_class_map["active_series"]
        .as_object_mut()
        .unwrap()
        .remove("secret_storage");
    per_class_map["active_series"]["classes"] = json!({"secret_storage": absent()});
    rejected.push(("class map".to_owned(), per_class_map));

    for (name, pointer) in [
        ("null pointer", json!(null)),
        ("unknown state", json!({"state": "unknown"})),
        ("empty pointer", json!({})),
        (
            "absent carries a series",
            json!({"state": "absent", "active_series_id": SERIES}),
        ),
        (
            "active without version",
            json!({"state": "active", "active_series_id": SERIES}),
        ),
        ("active version zero", active(json!(0))),
        ("active version negative", active(json!(-1))),
        ("active version string", active(json!("1"))),
        (
            "pointer names its class",
            json!({
                "state": "active", "active_series_id": SERIES, "series_pointer_version": 1,
                "backup_kind": "mls_history"
            }),
        ),
    ] {
        rejected.push((name.to_owned(), list(pointer)));
    }

    for (name, value) in rejected {
        assert_eq!(decide(&registry, &value), (false, false), "{name}: {value}");
    }
}
