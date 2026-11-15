//! Writer matching binds one retained original to its exact selector. These
//! tests do not replace independent original signature or current-row checks.

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::KeyBackupActiveSeries;
use arkret_models_integration::{
    RealmActorArchiveInventoryEntry, RealmActorArchiveInventoryManifest,
    realm_actor_selector_subject, validate_realm_actor_current_writer,
};
use arkret_schema_conformance::spec_json_artifact;
use arkret_wire::{
    ActorId, CircleId, CurrentSelector, DidCoreId, Event, EventId, EventKind, GrantId,
    RealmActorBackupKind, ScopeRef,
};
use serde_json::json;

fn native_series() -> (Event, CurrentSelector) {
    let fixture = spec_json_artifact("fixtures/realm-actor-content-backup-fixture.json").unwrap();
    let manifest: RealmActorArchiveInventoryManifest =
        serde_json::from_value(fixture["archive_inventory"].clone()).unwrap();
    let event = manifest
        .entries
        .into_iter()
        .find_map(|entry| match entry {
            RealmActorArchiveInventoryEntry::Series(entry) => Some(entry.source.event),
            _ => None,
        })
        .unwrap();
    let record: KeyBackupActiveSeries =
        serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
    let selector = CurrentSelector::RealmActorKeyBackupActiveSeries {
        actor_id: record.actor_id,
        effective_scope: record.effective_scope.unwrap(),
        backup_kind: RealmActorBackupKind::SecretStorage,
    };
    (event, selector)
}

#[test]
fn native_series_original_matches_only_its_registered_selector() {
    let (event, selector) = native_series();
    validate_realm_actor_current_writer(&selector, &event).unwrap();
    let actor_id = realm_actor_selector_subject(&selector).unwrap().clone();
    for unrelated in [
        CurrentSelector::RealmActorIdentity {
            actor_id: actor_id.clone(),
        },
        CurrentSelector::RealmActorManager {
            actor_id: actor_id.clone(),
        },
        CurrentSelector::RealmActorRecovery { actor_id },
    ] {
        assert!(validate_realm_actor_current_writer(&unrelated, &event).is_err());
    }
}

#[test]
fn native_series_writer_binds_complete_actor_and_scope() {
    let (event, selector) = native_series();
    let CurrentSelector::RealmActorKeyBackupActiveSeries {
        actor_id,
        effective_scope,
        ..
    } = &selector
    else {
        unreachable!()
    };
    let mut another_actor = actor_id.clone();
    let ActorId::Realm { realm_actor_id } = &mut another_actor else {
        unreachable!()
    };
    realm_actor_id.principal_id = DidCoreId::new("ak:did_core:web:other-actor.example").unwrap();
    let wrong_actor = CurrentSelector::RealmActorKeyBackupActiveSeries {
        actor_id: another_actor,
        effective_scope: effective_scope.clone(),
        backup_kind: RealmActorBackupKind::SecretStorage,
    };
    assert!(validate_realm_actor_current_writer(&wrong_actor, &event).is_err());
    let realm = actor_id.as_realm_actor_id().unwrap().realm_id.clone();
    let circle = ScopeRef::Circle {
        realm_id: realm,
        circle_id: CircleId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [97; 32])),
    };
    let circle_selector = CurrentSelector::RealmActorKeyBackupActiveSeries {
        actor_id: actor_id.clone(),
        effective_scope: circle.clone(),
        backup_kind: RealmActorBackupKind::SecretStorage,
    };
    assert!(validate_realm_actor_current_writer(&circle_selector, &event).is_err());
    // This is only a writer-mapping projection; the modified Event is not
    // presented as a cryptographically accepted original.
    let mut circle_event = event.clone();
    circle_event
        .payload
        .insert("effective_scope".into(), json!(circle));
    validate_realm_actor_current_writer(&circle_selector, &circle_event).unwrap();
    let mut wrong_target = event;
    wrong_target.payload.insert(
        "actor_id".into(),
        json!(realm_actor_selector_subject(&wrong_actor).unwrap()),
    );
    assert!(validate_realm_actor_current_writer(&selector, &wrong_target).is_err());
}

#[test]
fn native_series_writer_requires_its_service_control_branch() {
    let (event, selector) = native_series();
    for case in [
        "kind",
        "actor",
        "realm",
        "scope",
        "applet",
        "authorization",
        "executed_by",
    ] {
        let mut wrong = event.clone();
        match case {
            "kind" => wrong.kind = EventKind::RealmActorCreate,
            "actor" => wrong.actor_id = realm_actor_selector_subject(&selector).unwrap().clone(),
            "realm" => {
                wrong.realm_id = arkret_wire::RealmId::from_event_id(&EventId::from_digest(
                    DigestSuite::Sha256,
                    [99; 32],
                ));
            }
            "scope" => {
                wrong.scope_ref = ScopeRef::Realm {
                    realm_id: wrong.realm_id.clone(),
                };
            }
            "applet" => wrong.applet_id = None,
            "authorization" => {
                wrong.authorization_ref = Some(
                    GrantId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [98; 32]))
                        .into(),
                );
            }
            "executed_by" => wrong.executed_by = Some(event.actor_id.clone()),
            _ => unreachable!(),
        }
        assert!(
            validate_realm_actor_current_writer(&selector, &wrong).is_err(),
            "{case} cannot supply the native current writer"
        );
    }
}

#[test]
fn native_series_writer_uses_current_v1_typed_record_validation() {
    let (event, selector) = native_series();
    for case in [
        "schema",
        "class",
        "zero_version",
        "scope",
        "manager",
        "device_proof",
        "extra",
    ] {
        let mut wrong = event.clone();
        match case {
            "schema" => {
                wrong.payload.insert(
                    "schema".into(),
                    json!("ak.schema.key_backup_active_series.v0"),
                );
            }
            "class" => {
                wrong.payload.insert("backup_kind".into(), json!("other"));
            }
            "zero_version" => {
                wrong
                    .payload
                    .insert("series_pointer_version".into(), json!(0));
            }
            "scope" => {
                wrong.payload.insert(
                    "effective_scope".into(),
                    json!(ScopeRef::RealmControl {
                        realm_id: wrong.realm_id.clone(),
                    }),
                );
            }
            "manager" => {
                wrong.payload.remove("manager_ref");
            }
            "device_proof" => {
                let proof = wrong.payload.get_mut("signature_proof").unwrap();
                proof["device_authorize_event_id"] = json!(event.event_id);
            }
            "extra" => {
                wrong
                    .payload
                    .insert("target_actor_id".into(), json!(event.actor_id));
            }
            _ => unreachable!(),
        }
        assert!(
            validate_realm_actor_current_writer(&selector, &wrong).is_err(),
            "{case} must fail the existing typed native record contract"
        );
    }
}
