//! `KeysBackupsList.active_series` carries exactly one backup class, and
//! every `backups[]` row is the closed `backup_metadata` summary.
//!
//! Every case is decided twice: by the live Spec schema
//! `keys-operations.schema.json#/$defs/keys_backups_list` (or its
//! `backup_metadata` item) and by the SDK DTO. The two must agree, so an
//! `mls_history` or private class member, an open pointer branch, or an
//! envelope-only member such as `auth_data` cannot be accepted by the Rust
//! type while the closed schema rejects it, and no schema-valid summary is
//! refused by the Rust type (key-management §7.5.0 / §7.6.1, decision 0097).

use std::fs;

use arkret_models_crypto::{BackupActiveSeriesPointer, KeyBackupSummary, KeysBackupsList};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

const LIST_SCHEMA: &str = "test:keys_backups_list";
const METADATA_SCHEMA: &str = "test:backup_metadata";
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
        .register_fragment(LIST_SCHEMA, schema.clone(), "#/$defs/keys_backups_list")
        .unwrap();
    registry
        .register_fragment(METADATA_SCHEMA, schema, "#/$defs/backup_metadata")
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

const DIGEST: &str = "sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c";

/// The required members only.
fn minimal_metadata() -> Value {
    json!({
        "backup_id": "ak:backup:01964137-2000-7000-8000-000000000001",
        "actor_id": {"kind": "account", "account_id": {
            "principal_id": "ak:did_core:web:alice.example",
            "station_id": "ak:did_core:web:station.example"
        }},
        "backup_kind": "secret_storage",
        "backup_version": "kb_1",
        "series_id": SERIES,
        "series_seq": 0,
        "created_at": "2026-09-09T00:00:00.000Z",
        "ciphertext_digest": DIGEST,
        "encryption": {"recipient_method": "secret_storage_key"}
    })
}

/// Every member the schema allows, in schema `properties` order.
fn full_metadata() -> Value {
    json!({
        "backup_id": "ak:backup:01964137-2000-7000-8000-000000000002",
        "actor_id": minimal_metadata()["actor_id"],
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "backup_kind": "secret_storage",
        "backup_version": "kb_1",
        "series_id": SERIES,
        "series_seq": 1,
        "supersedes_id": "ak:backup:01964137-2000-7000-8000-000000000001",
        "supersedes_digest": DIGEST,
        "expires_at": "2027-09-09T00:00:00.000Z",
        "created_at": "2026-09-09T00:00:00.000Z",
        "updated_at": "2026-09-10T00:00:00.000Z",
        "ciphertext_digest": DIGEST,
        "encryption": {"recipient_method": "recovery_public_key", "recipient_key_ref": "hpke-1"},
        "retention": {"delete_after": null, "legal_hold": false}
    })
}

fn decide_metadata(registry: &ProtocolSchemaRegistry, value: &Value) -> (bool, bool, bool) {
    let schema = registry.validate_value(METADATA_SCHEMA, value).is_ok();
    let sdk = serde_json::from_value::<KeyBackupSummary>(value.clone()).is_ok();
    let mut page = list(absent());
    page["backups"] = json!([value]);
    let listed = registry.validate_value(LIST_SCHEMA, &page).is_ok()
        == serde_json::from_value::<KeysBackupsList>(page).is_ok();
    (schema, sdk, listed)
}

#[test]
fn schema_and_dto_accept_every_backup_metadata_shape_and_round_trip_it() {
    let registry = registry();
    let mut accepted = vec![minimal_metadata(), full_metadata()];

    // Tristate members: explicit null is a distinct, schema-valid value.
    let mut nulls = minimal_metadata();
    nulls["supersedes_id"] = json!(null);
    nulls["expires_at"] = json!(null);
    accepted.push(nulls);

    // Retention is the only open summary object and carries members verbatim.
    let mut open = full_metadata();
    open["retention"] = json!({"legal_hold": true, "x_note": {"k": [1, 2]}});
    accepted.push(open);

    for method in [
        "passphrase_kdf",
        "recovery_public_key",
        "secret_storage_key",
    ] {
        let mut value = minimal_metadata();
        value["encryption"] = json!({"recipient_method": method});
        accepted.push(value);
    }

    for value in accepted {
        assert_eq!(
            decide_metadata(&registry, &value),
            (true, true, true),
            "{value}"
        );
        let parsed: KeyBackupSummary = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    }

    let null_tristate: KeyBackupSummary = serde_json::from_value({
        let mut value = minimal_metadata();
        value["supersedes_id"] = json!(null);
        value["expires_at"] = json!(null);
        value
    })
    .unwrap();
    assert_eq!(null_tristate.supersedes_id, Some(None));
    assert_eq!(null_tristate.expires_at, Some(None));
    let absent_tristate: KeyBackupSummary = serde_json::from_value(minimal_metadata()).unwrap();
    assert_eq!(absent_tristate.supersedes_id, None);
    assert_eq!(absent_tristate.expires_at, None);
    let full: KeyBackupSummary = serde_json::from_value(full_metadata()).unwrap();
    assert_eq!(
        full.supersedes_id.flatten().unwrap().as_str(),
        "ak:backup:01964137-2000-7000-8000-000000000001"
    );
}

#[test]
fn schema_and_dto_reject_envelope_members_nulls_and_malformed_metadata() {
    let registry = registry();
    let mut rejected = Vec::new();

    // The whole envelope minus its ciphertext is not a summary.
    for (member, member_value) in [
        ("ciphertext", json!("AAAA")),
        ("domain_separation", json!({"subdomain": "secret_storage"})),
        (
            "contents",
            json!([{"item_kind": "recovery_key_share", "secret_id": "share"}]),
        ),
        (
            "auth_data",
            json!({
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "verification_method": "did:web:backup.example#device-signer",
                "signature_algorithm": "Ed25519", "signature": "AAAA",
                "device_authorize_event_id": "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
            }),
        ),
        ("plaintext_commitment", json!(DIGEST)),
        ("mixed_secret_storage", json!(false)),
        ("schema", json!("ak.schema.key_backup.v1")),
        ("x_extension", json!(true)),
    ] {
        let mut value = full_metadata();
        value[member] = member_value;
        rejected.push((format!("envelope member {member}"), value));
    }
    for (member, member_value) in [
        (
            "aead",
            json!({"name": "xchacha20_poly1305", "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        ),
        ("kdf", json!({"name": "argon2id"})),
        ("hpke_suite", json!("x25519_chacha20poly1305_v1")),
    ] {
        let mut value = full_metadata();
        value["encryption"][member] = member_value;
        rejected.push((format!("encryption.{member}"), value));
    }

    for member in [
        "backup_id",
        "actor_id",
        "backup_kind",
        "backup_version",
        "series_id",
        "series_seq",
        "created_at",
        "ciphertext_digest",
        "encryption",
    ] {
        let mut value = full_metadata();
        value.as_object_mut().unwrap().remove(member);
        rejected.push((format!("missing {member}"), value));
    }
    let mut no_method = full_metadata();
    no_method["encryption"]
        .as_object_mut()
        .unwrap()
        .remove("recipient_method");
    rejected.push(("missing recipient_method".to_owned(), no_method));

    // Only the tristate members admit null.
    for member in ["device_id", "supersedes_digest", "updated_at", "retention"] {
        let mut value = full_metadata();
        value[member] = json!(null);
        rejected.push((format!("null {member}"), value));
    }
    let mut null_key_ref = full_metadata();
    null_key_ref["encryption"]["recipient_key_ref"] = json!(null);
    rejected.push(("null recipient_key_ref".to_owned(), null_key_ref));

    for (name, member, member_value) in [
        ("empty backup_version", "backup_version", json!("")),
        ("negative series_seq", "series_seq", json!(-1)),
        ("string series_seq", "series_seq", json!("0")),
        ("mls_history class", "backup_kind", json!("mls_history")),
        (
            "retired source_commit_ref",
            "source_commit_ref",
            json!({"realm_commit_id": "ak:realm_commit:x"}),
        ),
        (
            "retired recovery_policy_ref",
            "recovery_policy_ref",
            json!({"policy_id": "ak:policy:01964137-3000-7000-8000-000000000001"}),
        ),
        ("array retention", "retention", json!([])),
        (
            "malformed supersedes_id",
            "supersedes_id",
            json!("backup-1"),
        ),
        ("malformed digest", "ciphertext_digest", json!("sha256:zz")),
        (
            "unknown recipient method",
            "encryption",
            json!({"recipient_method": "password"}),
        ),
    ] {
        let mut value = full_metadata();
        value[member] = member_value;
        rejected.push((name.to_owned(), value));
    }

    for (name, value) in rejected {
        let (schema, sdk, listed) = decide_metadata(&registry, &value);
        assert_eq!((schema, sdk), (false, false), "{name}: {value}");
        assert!(listed, "list page disagrees for {name}");
    }
}
