use arkret_canonical::canonical_json_bytes;
use arkret_models_crypto::{ContentRecoveryPreparation, ContentRecoveryPreparationState};
use arkret_schema_conformance::spec_json_artifact;
use serde_json::{Value, json};

fn fixture() -> Value {
    spec_json_artifact("fixtures/content-history-fixture.json").unwrap()
        ["recovery_preparation_encoding"]
        .clone()
}

#[test]
fn formal_preparation_bytes_and_original_episode_remain_bound() {
    let f = fixture();
    let pending: ContentRecoveryPreparation = serde_json::from_value(f["pending"].clone()).unwrap();
    let prepared: ContentRecoveryPreparation =
        serde_json::from_value(f["prepared"].clone()).unwrap();
    for (name, value) in [("pending", &pending), ("prepared", &prepared)] {
        value
            .validate_for_episode(
                &pending.replacement.authorization_event_ref,
                &pending.replacement,
                &pending.pcr_cut,
                Some(&pending),
            )
            .unwrap();
        let bytes = canonical_json_bytes(value).unwrap();
        assert_eq!(hex::encode(bytes), f[format!("{name}_jcs_hex")]);
    }
    prepared
        .validate_for_episode(
            &pending.replacement.authorization_event_ref,
            &pending.replacement,
            &pending.pcr_cut,
            Some(&prepared),
        )
        .unwrap();
    assert!(
        pending
            .validate_for_episode(
                &pending.replacement.authorization_event_ref,
                &pending.replacement,
                &pending.pcr_cut,
                Some(&prepared),
            )
            .is_err()
    );

    for pointer in [
        "/replacement/signature_key_base64url",
        "/replacement/endpoint/device_id",
        "/replacement/actor_id/account_id/station_id",
        "/replacement/authorization_event_ref",
        "/pcr_cut/stream_position",
        "/inventory_blob_ref",
    ] {
        let mut changed = f["prepared"].clone();
        *changed.pointer_mut(pointer).unwrap() = match pointer {
            "/replacement/signature_key_base64url" => {
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            }
            "/replacement/endpoint/device_id" => {
                json!("ak:device:019a0000-0000-7000-8000-000000000003")
            }
            "/replacement/actor_id/account_id/station_id" => {
                json!("ak:did_core:webvh:z6mkotherstation")
            }
            "/replacement/authorization_event_ref" => {
                json!("ak:event:AURERERERERERERERERERERERERERERERERERERERERE")
            }
            "/pcr_cut/stream_position" => json!(2),
            "/inventory_blob_ref" => json!(format!("ak:blob:sha256:{}", "00".repeat(32))),
            _ => unreachable!(),
        };
        let changed: ContentRecoveryPreparation = serde_json::from_value(changed).unwrap();
        assert!(
            changed
                .validate_for_episode(
                    &pending.replacement.authorization_event_ref,
                    &pending.replacement,
                    &pending.pcr_cut,
                    Some(&prepared),
                )
                .is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn preparation_rejects_phase_mismatch_null_extra_and_non_account_subject() {
    let f = fixture();
    for name in ["state", "replacement", "pcr_cut"] {
        let mut changed = f["pending"].clone();
        changed.as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<ContentRecoveryPreparation>(changed).is_err());
    }
    for name in ["inventory_blob_ref", "ready", "cleanup_completed"] {
        let mut changed = f["pending"].clone();
        changed[name] = Value::Null;
        assert!(serde_json::from_value::<ContentRecoveryPreparation>(changed).is_err());
    }
    let mut pending: ContentRecoveryPreparation =
        serde_json::from_value(f["pending"].clone()).unwrap();
    pending.state = ContentRecoveryPreparationState::Prepared;
    assert!(pending.validate().is_err());
    let mut prepared: ContentRecoveryPreparation =
        serde_json::from_value(f["prepared"].clone()).unwrap();
    prepared.state = ContentRecoveryPreparationState::Pending;
    assert!(prepared.validate().is_err());
    prepared.state = ContentRecoveryPreparationState::Prepared;
    prepared.replacement.actor_id = arkret_wire::ActorId::service(
        arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkservice").unwrap(),
    );
    assert!(prepared.validate().is_err());
}
