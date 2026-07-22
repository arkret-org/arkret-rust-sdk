use arkret_models_identity::ActorProfile;
use arkret_wire::{ACTOR_PROFILE_SCHEMA, ActorKind, ActorStatus};
use serde_json::json;

#[test]
fn actor_profile_rejects_unknown_fields_and_accepts_schema_statuses() {
    let value = json!({
        "id": "ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa",
        "schema": ACTOR_PROFILE_SCHEMA,
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
        "schema": ACTOR_PROFILE_SCHEMA,
        "principal_id": "did:webvh:z6mkfixture:ghost.example",
        "actor_kind": "integration",
        "display_name": "Ghost",
        "created_at": "2026-04-30T00:00:00.000Z",
        "managed_by_applet": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
    });
    assert!(serde_json::from_value::<ActorProfile>(bad).is_err());
}
