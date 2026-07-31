use arkret_models_identity::ActorProfile;
use arkret_models_identity::identity_link_cache::compute_policy_frontier_digest;
use arkret_wire::{ActorKind, ActorStatus, SchemaId};
use serde_json::json;

#[test]
fn actor_profile_rejects_unknown_fields_and_accepts_schema_statuses() {
    let value = json!({
        "id": "ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa",
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
        "id": "ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa",
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
