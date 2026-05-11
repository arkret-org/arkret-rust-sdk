use super::*;
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn device(id: &str) -> DeviceId {
    DeviceId::new(format!("dev_{id}")).unwrap()
}

#[test]
fn devices_tracks_lists_metadata_and_changes() {
    let alice = did("alice");
    let device_id = device("phone");
    let mut manager = DeviceManager::new();

    manager.upsert_device(
        alice.clone(),
        device_id.clone(),
        DeviceMetadata {
            name: Some("Phone".to_owned()),
            model: Some("Pixel".to_owned()),
            os: Some("Android".to_owned()),
            last_seen_at: None,
        },
    );

    assert_eq!(manager.user_devices(&alice).len(), 1);
    assert_eq!(
        manager.device(&alice, &device_id).unwrap().metadata.name,
        Some("Phone".to_owned())
    );
    assert_eq!(manager.drain_changes().len(), 1);
}

#[test]
fn devices_queues_to_device_messages() {
    let alice = did("alice");
    let bob = did("bob");
    let device_id = device("laptop");
    let mut manager = DeviceManager::new();

    manager.send_to_device(alice, bob, device_id, "cx.keys.room_key", json!({"session":"abc"}));

    let messages = manager.drain_to_device();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_type, "cx.keys.room_key");
    assert!(manager.drain_to_device().is_empty());
}

#[test]
fn devices_verifies_blocks_and_deletes() {
    let alice = did("alice");
    let device_id = device("tablet");
    let mut manager = DeviceManager::new();
    manager.upsert_device(
        alice.clone(),
        device_id.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
    );

    manager.start_verification(&alice, &device_id).unwrap();
    assert_eq!(
        manager.device(&alice, &device_id).unwrap().verification,
        DeviceVerificationState::VerificationStarted
    );
    manager.verify_device(&alice, &device_id, Some("master-key".to_owned())).unwrap();
    assert_eq!(
        manager.device(&alice, &device_id).unwrap().verification,
        DeviceVerificationState::Verified
    );
    manager.block_device(&alice, &device_id).unwrap();
    manager.delete_device(&alice, &device_id).unwrap();
    assert!(manager.device(&alice, &device_id).is_none());
}

#[test]
fn devices_run_challenge_response_verification_flow() {
    let alice = did("alice");
    let device_id = device("desktop");
    let mut manager = DeviceManager::new();
    manager.upsert_device(
        alice.clone(),
        device_id.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
    );

    let challenge =
        manager.begin_verification_flow(&alice, &device_id, "sas", "123456").unwrap();
    manager
        .confirm_verification_flow(&challenge.transaction_id, "123456", Some("key".to_owned()))
        .unwrap();

    assert_eq!(
        manager.device(&alice, &device_id).unwrap().verification,
        DeviceVerificationState::Verified
    );
}

#[test]
fn devices_support_sas_qr_mismatch_and_trust_propagation() {
    let alice = did("alice");
    let phone = device("phone");
    let laptop = device("laptop");
    let mut manager = DeviceManager::new();
    for device_id in [&phone, &laptop] {
        manager.upsert_device(
            alice.clone(),
            device_id.clone(),
            DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        );
    }

    let challenge = manager.begin_sas_verification(&alice, &phone, "123456").unwrap();
    assert!(challenge.commitment.starts_with("sha256:"));
    let qr = manager.qr_verification_payload(&challenge.transaction_id).unwrap();
    DeviceManager::validate_qr_verification_payload(&qr, &alice, &phone).unwrap();
    assert!(
        manager.confirm_verification_flow(&challenge.transaction_id, "000000", None).is_err()
    );
    assert_eq!(
        manager.device(&alice, &phone).unwrap().verification,
        DeviceVerificationState::VerificationFailed
    );

    manager.start_verification(&alice, &phone).unwrap();
    manager.verify_device(&alice, &phone, Some("master-key".to_owned())).unwrap();
    manager.propagate_trust(&alice, &phone, &laptop).unwrap();
    assert_eq!(
        manager.device(&alice, &laptop).unwrap().verification,
        DeviceVerificationState::Verified
    );
}

#[test]
fn devices_uploads_downloads_and_restores_key_backup() {
    let mut manager = DeviceManager::new();
    manager.upload_key_backup("1", "m.megolm_backup.v1", json!({"ciphertext":"abc"}));

    assert!(manager.download_key_backup("1").is_some());
    assert_eq!(manager.restore_key_backup("1").unwrap(), json!({"ciphertext":"abc"}));
    assert!(manager.restore_key_backup("missing").is_err());
}

#[test]
fn devices_revoke_and_fail_closed() {
    let alice = did("alice");
    let device_id = device("phone");
    let mut manager = DeviceManager::new();
    manager.upsert_device(
        alice.clone(),
        device_id.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
    );

    assert!(!manager.is_device_revoked(&alice, &device_id));
    manager.revoke_device(&alice, &device_id);
    assert!(manager.is_device_revoked(&alice, &device_id));
    assert_eq!(manager.revoked_devices_for_user(&alice).len(), 1);
}

#[test]
fn devices_rotate_and_validate_authenticated_key_backups() {
    let alice = did("alice");
    let mut manager = DeviceManager::new();
    manager.upload_authenticated_key_backup(
        "1",
        "m.megolm_backup.v1",
        json!({"ciphertext":"abc"}),
        Some(alice.clone()),
        None,
    );
    let rotated = manager.upload_authenticated_key_backup(
        "2",
        "m.megolm_backup.v1",
        json!({"ciphertext":"def"}),
        Some(alice.clone()),
        Some("1".to_owned()),
    );

    assert_eq!(rotated.previous_version.as_deref(), Some("1"));
    assert_eq!(
        manager.restore_key_backup_from_sender("2", &alice).unwrap(),
        json!({"ciphertext":"def"})
    );
    assert!(manager.restore_key_backup_from_sender("2", &did("bob")).is_err());
}
