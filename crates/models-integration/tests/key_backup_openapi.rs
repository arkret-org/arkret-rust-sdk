#![cfg(feature = "openapi")]

use arkret_models_integration::{KeysBackupsListResponseBody, KeysBackupsUnlockResponseBody};
use arkret_schema_conformance::spec_json_artifact;
use salvo_oapi::{Components, ComposeSchema, EndpointOutRegister, Operation, ToSchema};
use serde_json::{Value, json};

fn registered<T: ToSchema + ComposeSchema>() -> (Value, Value) {
    let mut components = Components::default();
    let root = serde_json::to_value(T::to_schema(&mut components)).unwrap();
    assert_eq!(
        serde_json::to_value(T::compose(&mut components, vec![])).unwrap(),
        root
    );
    let document = json!({"$ref": root["$ref"], "components": components});
    (root, document)
}

#[test]
fn actual_json_endpoint_output_registers_both_complete_response_schemas() {
    fn endpoint<T: EndpointOutRegister>() -> (Components, Operation) {
        let mut components = Components::default();
        let mut operation = Operation::default();
        T::register(&mut components, &mut operation);
        (components, operation)
    }
    for (components, operation) in [
        endpoint::<salvo_core::writing::Json<KeysBackupsListResponseBody>>(),
        endpoint::<salvo_core::writing::Json<KeysBackupsUnlockResponseBody>>(),
    ] {
        let components = serde_json::to_value(components).unwrap();
        let operation = serde_json::to_value(operation).unwrap();
        let reference =
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
                .as_str()
                .unwrap();
        assert!(
            components
                .pointer(reference.strip_prefix("#/components").unwrap())
                .is_some()
        );
        assert!(components["schemas"].as_object().unwrap().len() > 100);
    }
}

#[test]
fn emitted_schemas_validate_all_roles_and_reject_native_disclosure_and_aliases() {
    let fixture = spec_json_artifact("fixtures/realm-actor-content-backup-fixture.json").unwrap();
    let (_, list) = registered::<KeysBackupsListResponseBody>();
    let (_, unlock) = registered::<KeysBackupsUnlockResponseBody>();
    let list = jsonschema::validator_for(&list).unwrap();
    let unlock = jsonschema::validator_for(&unlock).unwrap();
    let legacy = spec_json_artifact("fixtures/key-backup-fixture.json").unwrap();
    let legacy_packet = &legacy["schema_validation_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["name"] == "key_backup_envelope_canonical_source_commit_ref_successor_valid"
        })
        .unwrap()["instance"];
    assert!(unlock.is_valid(legacy_packet));
    let legacy_page = json!({"backups":[], "has_more":false, "active_series":{
        "account_id":legacy_packet["actor_id"]["account_id"],
        "control_realm_id":fixture["archive_inventory"]["realm_actor_id"]["realm_id"],
        "authority_commit_id":fixture["device_head_response"]["active_series"]["authority_commit_id"],
        "secret_storage":{"state":"absent"}
    }});
    assert!(list.is_valid(&legacy_page));
    let manager_page = json!({
        "purpose":"archive_inventory", "realm_actor_id":fixture["archive_inventory"]["realm_actor_id"],
        "manager_ref":fixture["archive_inventory"]["manager_ref"],
        "archive_revision":fixture["archive_inventory"]["archive_revision"],
        "inventory_digest":fixture["inventory_cut"]["inventory_digest"],
        "entries":fixture["archive_inventory"]["entries"], "has_more":false
    });
    for valid in [&fixture["device_head_response"], &manager_page] {
        assert!(
            list.is_valid(valid),
            "{:?}",
            list.iter_errors(valid).collect::<Vec<_>>()
        );
    }
    for valid in [
        &fixture["device_unlock_response"],
        &fixture["manager_unlock_response"],
    ] {
        assert!(
            unlock.is_valid(valid),
            "{:?}",
            unlock.iter_errors(valid).collect::<Vec<_>>()
        );
    }
    assert!(!unlock.is_valid(&fixture["native_packet"]));
    let mut leaked_head = fixture["device_head_response"].clone();
    leaked_head["items"][0]["native_source"] = fixture["native_source"].clone();
    assert!(!list.is_valid(&leaked_head));
    let mut null_expiry = fixture["device_unlock_response"].clone();
    null_expiry["backup"]["expires_at"] = Value::Null;
    assert!(!unlock.is_valid(&null_expiry));
    for both in [false, true] {
        let mut old_name = fixture["manager_unlock_response"].clone();
        let history = old_name["native_source"]["governance_history"]
            .as_object_mut()
            .unwrap();
        let original = history["genesis_resolution"].clone();
        if !both {
            history.remove("genesis_resolution");
        }
        history.insert("genesis_service_resolution".into(), original);
        assert!(!unlock.is_valid(&old_name));
    }
    let mut wrong_event_layout = fixture["manager_unlock_response"].clone();
    // RealmCreate uses the canonical special envelope, never the Rust Event memory layout.
    let event = &mut wrong_event_layout["native_source"]["governance_history"]["genesis"]["event"];
    assert!(event.is_object());
    event["realm_id"] = json!("ak:realm:00000000-0000-0000-0000-000000000001");
    assert!(!unlock.is_valid(&wrong_event_layout));
}
