//! Ordinary single-kind operation targets retain their concrete typed identity.

use arkret_models_collaboration::events_payloads::{
    ActorProfileUpdatePayload, MorphUpdatePayload, ProfileRealmOverridePayload, StrandPatchPayload,
};
use arkret_schema_conformance::event_payload_validator_catalog;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const TOKEN: &str = "Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";

fn assert_closed_target<T: DeserializeOwned + Serialize>(
    event_kind: &str,
    field: &str,
    kind: &str,
    payload: Value,
) {
    let catalog = event_payload_validator_catalog().unwrap();
    let decoded: T = serde_json::from_value(payload.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), payload);
    catalog.validate_payload(event_kind, &payload).unwrap();

    let mut old = payload.clone();
    let target = old.as_object_mut().unwrap().remove(field).unwrap();
    old["target_ref"] = target.clone();
    assert!(serde_json::from_value::<T>(old.clone()).is_err());
    assert!(catalog.validate_payload(event_kind, &old).is_err());

    let mut both = payload.clone();
    both["target_ref"] = target;
    assert!(serde_json::from_value::<T>(both.clone()).is_err());
    assert!(catalog.validate_payload(event_kind, &both).is_err());

    for wrong_kind in ["strand", "morph", "actor_profile", "event"] {
        if wrong_kind == kind {
            continue;
        }
        let mut wrong = payload.clone();
        wrong[field] = json!(format!("ak:{wrong_kind}:{TOKEN}"));
        assert!(serde_json::from_value::<T>(wrong.clone()).is_err());
        assert!(catalog.validate_payload(event_kind, &wrong).is_err());
    }
}

#[test]
fn strand_update_and_tracks_update_use_strand_id() {
    for (event_kind, patch) in [
        (
            "ak.strand.update",
            json!({"metadata.title": {"$op": "set", "value": "Title"}}),
        ),
        (
            "ak.strand.tracks.update",
            json!({"tracks.discussion.enabled": {"$op": "set", "value": true}}),
        ),
    ] {
        assert_closed_target::<StrandPatchPayload>(
            event_kind,
            "strand_id",
            "strand",
            json!({"strand_id": format!("ak:strand:{TOKEN}"), "patch": patch}),
        );
    }
}

#[test]
fn morph_update_uses_morph_id() {
    assert_closed_target::<MorphUpdatePayload>(
        "ak.morph.update",
        "morph_id",
        "morph",
        json!({"morph_id": format!("ak:morph:{TOKEN}"), "patch": {"metadata.title": {"$op": "set", "value": "Title"}}}),
    );
}

#[test]
fn profile_update_uses_actor_profile_id() {
    assert_closed_target::<ActorProfileUpdatePayload>(
        "ak.profile.update",
        "actor_profile_id",
        "actor_profile",
        json!({"actor_profile_id": format!("ak:actor_profile:{TOKEN}"), "patch": {"display_name": {"$op": "set", "value": "Name"}}}),
    );
}

#[test]
fn realm_override_uses_typed_actor_profile_id_and_retains_target_realm() {
    assert_closed_target::<ProfileRealmOverridePayload>(
        "ak.profile.realm_override",
        "actor_profile_id",
        "actor_profile",
        json!({
            "actor_profile_id": format!("ak:actor_profile:{TOKEN}"),
            "target_realm_id": format!("ak:realm:{TOKEN}"),
            "patch": {"display_name": {"$op": "set", "value": "Local name"}}
        }),
    );
}
