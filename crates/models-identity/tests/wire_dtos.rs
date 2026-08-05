use arkret_models_identity::ActorProfile;
use arkret_models_identity::identity_link_cache::compute_policy_frontier_digest;
use arkret_models_identity::service_identity::ServiceRegistrationReceipt;
use arkret_wire::{ActorKind, ActorStatus, SchemaId};
use serde_json::json;

#[test]
fn actor_profile_rejects_unknown_fields_and_accepts_schema_statuses() {
    let value = json!({
        "id": "ak:actor_profile:01904100-0000-8000-8000-aaaaaaaaaaaa",
        "schema": SchemaId::ACTOR_PROFILE_V1,
        "principal_id": "did:webvh:z6mkfixture:ghost.example",
        "actor_kind": "integration",
        "display_name": "Ghost",
        "status": "locked",
        "accountable_principal_ids": ["did:webvh:z6mkfixture:owner.example"],
        "profile_fields": {
            "managed_by_applet": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        },
        "created_at": "2026-04-30T00:00:00.000Z",
        "updated_by": "did:webvh:z6mkfixture:owner.example",
        "updated_at": "2026-04-30T00:01:00.000Z"
    });
    let profile: ActorProfile = serde_json::from_value(value).unwrap();
    assert_eq!(profile.status, Some(ActorStatus::Locked));
    assert_eq!(profile.actor_kind, ActorKind::Integration);

    let bad = json!({
        "id": "ak:actor_profile:01904100-0000-8000-8000-aaaaaaaaaaaa",
        "schema": SchemaId::ACTOR_PROFILE_V1,
        "principal_id": "did:webvh:z6mkfixture:ghost.example",
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
            "service_kind": "auth_server",
            "public_base": "https://auth.example/"
        },
        "service_id": "did:webvh:z6mkfixture:auth.example",
        "version_id": "1-zVersion",
        "log_head_digest": format!("sha256:{}", "b".repeat(64)),
        "control_key_digest": format!("sha256:{}", "c".repeat(64)),
        "issued_at": "2026-08-01T00:00:00.000Z",
        "provider_service_id": "did:webvh:z6mkfixture:provider.example",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:webvh:z6mkfixture:provider.example#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z1"
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

#[test]
fn policy_frontier_digest_is_deterministic() {
    let h1 = compute_policy_frontier_digest(
        &json!({"mode": "strict"}),
        &json!("members_only"),
        &json!({"profile": "default"}),
        &json!(false),
    )
    .unwrap();
    let h2 = compute_policy_frontier_digest(
        &json!({"mode": "strict"}),
        &json!("members_only"),
        &json!({"profile": "default"}),
        &json!(false),
    )
    .unwrap();
    assert_eq!(h1, h2);
    let h3 = compute_policy_frontier_digest(
        &json!({"mode": "strict"}),
        &json!("members_only"),
        &json!({"profile": "default"}),
        &json!(true),
    )
    .unwrap();
    assert_ne!(h1, h3);
}
