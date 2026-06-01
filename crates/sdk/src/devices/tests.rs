use super::*;
use chrono::Utc;
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn device(id: &str) -> DeviceId {
    let mut acc = 0xcbf29ce484222325u64;
    for byte in id.bytes() {
        acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    DeviceId::new(format!("cx:device:01904100-0000-7000-8000-{:012x}", acc & 0x0000_ffff_ffff_ffff))
        .unwrap()
}

fn fake_binding(generation: u64) -> DeviceTrustBinding {
    DeviceTrustBinding {
        verification_method: "did:web:alice.example#cx_self_signing_v1".to_owned(),
        alg: "EdDSA".to_owned(),
        ssk_generation: generation,
        signature: format!("test-sig-gen-{generation}"),
    }
}

fn sample_publish(principal: &Did, generation: u64) -> CrossSigningPublishContent {
    CrossSigningPublishContent {
        principal_id: principal.clone(),
        trust_domain: contrix_core::TypedTrustDomainId::new("cx:trust_domain:example.net").unwrap(),
        principal_signing_key: CrossSigningKeyRecord {
            kid: format!("{principal}#cx_principal_signing_v1"),
            alg: "EdDSA".to_owned(),
            public_key: "z6MkPrincipalAlice".to_owned(),
            key_format: "multibase".to_owned(),
        },
        self_signing_key: SignedCrossSigningKey {
            key: CrossSigningKeyRecord {
                kid: format!("{principal}#cx_self_signing_v1"),
                alg: "EdDSA".to_owned(),
                public_key: "z6MkSelfAlice".to_owned(),
                key_format: "multibase".to_owned(),
            },
            binding: CrossSigningBinding {
                verification_method: format!("{principal}#cx_principal_signing_v1"),
                alg: "EdDSA".to_owned(),
                signature: format!("psk-sig-ssk-gen-{generation}"),
            },
        },
        user_signing_key: SignedCrossSigningKey {
            key: CrossSigningKeyRecord {
                kid: format!("{principal}#cx_user_signing_v1"),
                alg: "EdDSA".to_owned(),
                public_key: "z6MkUserAlice".to_owned(),
                key_format: "multibase".to_owned(),
            },
            binding: CrossSigningBinding {
                verification_method: format!("{principal}#cx_principal_signing_v1"),
                alg: "EdDSA".to_owned(),
                signature: format!("psk-sig-usk-gen-{generation}"),
            },
        },
        expected_previous_generation: generation.saturating_sub(1),
        generation,
        issued_at: Utc::now(),
    }
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
    assert_eq!(manager.device(&alice, &device_id).unwrap().metadata.name, Some("Phone".to_owned()));
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
    manager.verify_device(&alice, &device_id, Some(fake_binding(1))).unwrap();
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

    let challenge = manager.begin_verification_flow(&alice, &device_id, "sas", "123456").unwrap();
    manager
        .confirm_verification_flow(&challenge.transaction_id, "123456", Some(fake_binding(1)))
        .unwrap();

    assert_eq!(
        manager.device(&alice, &device_id).unwrap().verification,
        DeviceVerificationState::Verified
    );
}

#[test]
fn devices_support_sas_qr_mismatch_with_trust_chain_propagation() {
    let alice = did("alice");
    let phone = device("phone");
    let laptop = device("laptop");
    let mut manager = DeviceManager::new();

    // Phone has a known verify_key; laptop too.
    manager.upsert_device_with_key(
        alice.clone(),
        phone.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        "z6MkPhoneVerifyKey",
    );
    manager.upsert_device_with_key(
        alice.clone(),
        laptop.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        "z6MkLaptopVerifyKey",
    );

    let challenge = manager.begin_sas_verification(&alice, &phone, "123456").unwrap();
    assert!(challenge.commitment.starts_with("sha256:"));
    let qr = manager.qr_verification_payload(&challenge.transaction_id).unwrap();
    DeviceManager::validate_qr_verification_payload(&qr, &alice, &phone).unwrap();
    assert!(manager.confirm_verification_flow(&challenge.transaction_id, "000000", None).is_err());
    assert_eq!(
        manager.device(&alice, &phone).unwrap().verification,
        DeviceVerificationState::VerificationFailed
    );

    // Record a cross-signing publish for Alice and a proper per-device
    // binding for both devices.
    manager.record_cross_signing_publish(sample_publish(&alice, 1)).unwrap();
    manager.start_verification(&alice, &phone).unwrap();
    manager.verify_device(&alice, &phone, Some(fake_binding(1))).unwrap();
    manager.attach_cross_signing_binding(&alice, &laptop, fake_binding(1)).unwrap();

    // propagate_trust now requires the target to already have its own
    // binding — sibling trust isn't transitive.
    manager.propagate_trust(&alice, &phone, &laptop).unwrap();
    assert_eq!(
        manager.device(&alice, &laptop).unwrap().verification,
        DeviceVerificationState::Verified
    );
}

#[test]
fn propagate_trust_requires_binding_on_target() {
    let alice = did("alice");
    let phone = device("phone");
    let laptop = device("laptop");
    let mut manager = DeviceManager::new();
    for d in [&phone, &laptop] {
        manager.upsert_device_with_key(
            alice.clone(),
            d.clone(),
            DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
            "z6MkVerifyKey",
        );
    }
    manager.record_cross_signing_publish(sample_publish(&alice, 1)).unwrap();
    manager.verify_device(&alice, &phone, Some(fake_binding(1))).unwrap();
    // Laptop has no binding yet — propagation MUST fail.
    let err = manager.propagate_trust(&alice, &phone, &laptop).unwrap_err();
    assert!(format!("{err}").contains("target device has no cross_signing_binding"));
}

#[test]
fn cross_signing_reset_marks_devices_needing_reverification() {
    let alice = did("alice");
    let phone = device("phone");
    let laptop = device("laptop");
    let mut manager = DeviceManager::new();
    for d in [&phone, &laptop] {
        manager.upsert_device_with_key(
            alice.clone(),
            d.clone(),
            DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
            "z6MkVerifyKey",
        );
    }
    manager.record_cross_signing_publish(sample_publish(&alice, 1)).unwrap();
    manager.verify_device(&alice, &phone, Some(fake_binding(1))).unwrap();
    manager.verify_device(&alice, &laptop, Some(fake_binding(1))).unwrap();

    let reset = CrossSigningResetContent {
        principal_id: alice.clone(),
        previous_generation: 1,
        new_generation: 2,
        reset_reason: "rotation".to_owned(),
        proof: CrossSigningResetProof::PrincipalSigning {
            verification_method: "did:web:alice.example#did-control".to_owned(),
            alg: "EdDSA".to_owned(),
            signature: "test-psk-sig".to_owned(),
        },
        issued_at: Utc::now(),
    };
    manager.record_cross_signing_reset(&reset).unwrap();

    for d in [&phone, &laptop] {
        let dev = manager.device(&alice, d).unwrap();
        assert_eq!(dev.verification, DeviceVerificationState::NeedsReverification);
        assert!(dev.cross_signing_binding.is_none());
    }
    // No publish accepted right now — attaching a new binding must fail.
    assert!(manager.attach_cross_signing_binding(&alice, &phone, fake_binding(2)).is_err());

    // Round 4 (spec a77b995): reset bumps generation high-water to
    // `new_generation = 2`, so the next publish chains from there —
    // expected_previous_generation = 2, generation = 3. The
    // pre-round-4 wire (publish(gen=2) directly after reset) is rejected.
    manager.record_cross_signing_publish(sample_publish(&alice, 3)).unwrap();
    manager.attach_cross_signing_binding(&alice, &phone, fake_binding(3)).unwrap();
    let dev = manager.device(&alice, &phone).unwrap();
    assert!(dev.cross_signing_binding.is_some());
}

#[test]
fn publish_generation_must_advance_and_invalidates_old_bindings() {
    let alice = did("alice");
    let phone = device("phone");
    let mut manager = DeviceManager::new();
    manager.upsert_device_with_key(
        alice.clone(),
        phone.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        "z6MkVerifyKey",
    );
    manager.record_cross_signing_publish(sample_publish(&alice, 1)).unwrap();
    manager.verify_device(&alice, &phone, Some(fake_binding(1))).unwrap();

    // Same generation rejected.
    assert!(manager.record_cross_signing_publish(sample_publish(&alice, 1)).is_err());

    // Advancing the publish invalidates the existing device binding.
    manager.record_cross_signing_publish(sample_publish(&alice, 2)).unwrap();
    let dev = manager.device(&alice, &phone).unwrap();
    assert!(dev.cross_signing_binding.is_none());
    assert_eq!(dev.verification, DeviceVerificationState::NeedsReverification);
}

#[test]
fn evaluate_trust_chain_states() {
    let alice = did("alice");
    let phone = device("phone");
    let mut manager = DeviceManager::new();
    manager.upsert_device_with_key(
        alice.clone(),
        phone.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        "z6MkVerifyKey",
    );

    // No publish, no binding → Unverified.
    let outcome = manager.evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true)).unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::Unverified);

    // Attach bootstrap binding before any publish → Bootstrap.
    manager
        .attach_bootstrap_binding(
            &alice,
            &phone,
            DeviceBootstrapBinding {
                kind: "inception_self_authorized".to_owned(),
                did_method_evidence_ref: "did:webvh:alice.example/entry-0".to_owned(),
            },
        )
        .unwrap();
    let outcome = manager.evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true)).unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::Bootstrap);

    // After a publish, bootstrap is no longer accepted.
    manager.record_cross_signing_publish(sample_publish(&alice, 1)).unwrap();
    let outcome = manager.evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true)).unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::NeedsReverification);

    // Real binding + verifier that always returns true → CrossSigned.
    manager.attach_cross_signing_binding(&alice, &phone, fake_binding(1)).unwrap();
    let outcome = manager.evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true)).unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::CrossSigned);

    // Verifier rejects → Invalid.
    let outcome = manager.evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(false)).unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::Invalid);

    // Generation behind accepted → NeedsReverification.
    manager.record_cross_signing_publish(sample_publish(&alice, 2)).unwrap();
    manager.attach_cross_signing_binding(&alice, &phone, fake_binding(2)).unwrap();
    // Manually back-date the binding to test the stale-generation branch.
    let device_ref = manager.user_devices(&alice).into_iter().next().unwrap().clone();
    let mut stale = device_ref.clone();
    stale.cross_signing_binding = Some(fake_binding(1));
    // Replace via upsert+attach.
    manager.upsert_device_with_key(
        alice.clone(),
        phone.clone(),
        device_ref.metadata,
        "z6MkVerifyKey",
    );
    // Force-set the stale binding back through the manager API:
    manager.verify_device(&alice, &phone, Some(fake_binding(1))).unwrap();
    let outcome = manager.evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true)).unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::NeedsReverification);
}

#[test]
fn cross_signing_reset_cancels_in_flight_verifications() {
    let alice = did("alice");
    let phone = device("phone");
    let mut manager = DeviceManager::new();
    manager.upsert_device_with_key(
        alice.clone(),
        phone.clone(),
        DeviceMetadata { name: None, model: None, os: None, last_seen_at: None },
        "z6MkVerifyKey",
    );
    manager.record_cross_signing_publish(sample_publish(&alice, 1)).unwrap();

    // Start a SAS verification (no confirm yet).
    let challenge = manager.begin_sas_verification(&alice, &phone, "000000").unwrap();
    let reset = CrossSigningResetContent {
        principal_id: alice.clone(),
        previous_generation: 1,
        new_generation: 2,
        reset_reason: "compromise".to_owned(),
        proof: CrossSigningResetProof::PrincipalSigning {
            verification_method: "did:web:alice.example#did-control".to_owned(),
            alg: "EdDSA".to_owned(),
            signature: "psk-sig".to_owned(),
        },
        issued_at: Utc::now(),
    };
    manager.record_cross_signing_reset(&reset).unwrap();

    // In-flight transaction MUST have been cancelled.
    assert!(manager.confirm_verification_flow(&challenge.transaction_id, "000000", None).is_err());
    let dev = manager.device(&alice, &phone).unwrap();
    assert!(matches!(
        dev.verification,
        DeviceVerificationState::VerificationCancelled
            | DeviceVerificationState::NeedsReverification
    ));
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
