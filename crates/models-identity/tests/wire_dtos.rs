use arkret_models_identity::ActorProfile;
use arkret_models_identity::service_identity::ServiceRegistrationReceipt;
use arkret_wire::{ActorKind, SchemaId};
use serde_json::json;

#[test]
fn actor_profile_rejects_unknown_fields_and_the_retired_status_member() {
    let value = json!({
        "id": "ak:actor_profile:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu",
        "schema": SchemaId::ACTOR_PROFILE_V1,
        "principal_id": "ak:did_core:webvh:z6mkfixtureghost",
        "actor_kind": "integration",
        "display_name": "Ghost",
        "accountable_principal_ids": ["ak:did_core:webvh:z6mkfixtureowner"],
        "profile_fields": {
            "managed_by_applet": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        },
        "created_at": "2026-04-30T00:00:00.000Z",
        "updated_by": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixtureowner",
                "station_id": "ak:did_core:webvh:z6mkfixturestation"
            }
        },
        "updated_at": "2026-04-30T00:01:00.000Z"
    });
    let profile: ActorProfile = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(profile.actor_kind, ActorKind::Integration);
    // `status` is no durable profile member (profiles-presence.md section 2.2);
    // the verified account status is a resolve-row projection instead.
    let mut with_status = value;
    with_status["status"] = json!("locked");
    assert!(serde_json::from_value::<ActorProfile>(with_status).is_err());

    let bad = json!({
        "id": "ak:actor_profile:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu",
        "schema": SchemaId::ACTOR_PROFILE_V1,
        "principal_id": "ak:did_core:webvh:z6mkfixtureghost",
        "actor_kind": "integration",
        "display_name": "Ghost",
        "created_at": "2026-04-30T00:00:00.000Z",
        "managed_by_applet": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
    });
    assert!(serde_json::from_value::<ActorProfile>(bad).is_err());
}

#[test]
fn service_registration_receipt_uses_the_spec_field_and_typed_id() {
    let receipt = json!({
        "registration_receipt_id": format!(
            "ak:service_registration_receipt:{}",
            "a".repeat(64)
        ),
        "registration_key": {
            "service_kind": "station",
            "public_base_url": "https://station.example/"
        },
        "service_id": "ak:did_core:webvh:z6mkfixtureauth",
        "did": "did:webvh:z6mkfixtureauth:auth.example",
        "version_id": "1-zVersion",
        "log_head_digest": format!("sha256:{}", "b".repeat(64)),
        "control_key_digest": format!("sha256:{}", "c".repeat(64)),
        "issued_at": "2026-08-01T00:00:00.000Z",
        "provider_id": "ak:did_core:webvh:z6mkfixtureprovider",
        "proof": {
            "kind": "detached_jws",
            "verification_method": "did:webvh:z6mkfixtureprovider:provider.example#key-1",
            "payload_digest": format!("sha256:{}", "d".repeat(64)),
            "created_at": "2026-08-01T00:00:00.000Z",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..fixture"
        }
    });

    let parsed = serde_json::from_value::<ServiceRegistrationReceipt>(receipt.clone());
    assert!(parsed.is_ok(), "{parsed:?}");

    let mut old_field = receipt.clone();
    let object = old_field.as_object_mut().unwrap();
    let id = object.remove("registration_receipt_id").unwrap();
    object.insert("receipt_id".to_owned(), id);
    assert!(serde_json::from_value::<ServiceRegistrationReceipt>(old_field).is_err());

    let mut invalid_id = receipt;
    invalid_id["registration_receipt_id"] = json!(format!(
        "ak:service_registration_receipt:{}",
        "A".repeat(64)
    ));
    assert!(serde_json::from_value::<ServiceRegistrationReceipt>(invalid_id).is_err());
}
