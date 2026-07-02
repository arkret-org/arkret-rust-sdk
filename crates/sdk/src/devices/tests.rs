use chrono::Utc;
use serde_json::json;

use super::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

fn device(id: &str) -> DeviceId {
    let mut acc = 0xcbf29ce484222325u64;
    for byte in id.bytes() {
        acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    DeviceId::new(format!(
        "ck:device:01904100-0000-7000-8000-{:012x}",
        acc & 0x0000_ffff_ffff_ffff
    ))
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
        trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap(),
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

    manager.send_to_device(
        alice,
        bob,
        device_id,
        "ck.keys.room_key",
        json!({"session":"abc"}),
    );

    let messages = manager.drain_to_device();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].message_type, "ck.keys.room_key");
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
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
    );

    manager.start_verification(&alice, &device_id).unwrap();
    assert_eq!(
        manager.device(&alice, &device_id).unwrap().verification,
        DeviceVerificationState::VerificationStarted
    );
    manager
        .verify_device(&alice, &device_id, Some(fake_binding(1)))
        .unwrap();
    assert_eq!(
        manager.device(&alice, &device_id).unwrap().verification,
        DeviceVerificationState::Verified
    );
    manager.block_device(&alice, &device_id).unwrap();
    manager.delete_device(&alice, &device_id).unwrap();
    assert!(manager.device(&alice, &device_id).is_none());
}

#[test]
fn devices_run_challenge_response_verification_strand() {
    let alice = did("alice");
    let device_id = device("desktop");
    let mut manager = DeviceManager::new();
    manager.upsert_device(
        alice.clone(),
        device_id.clone(),
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
    );

    let challenge = manager
        .begin_verification_strand(&alice, &device_id, "sas", "123456")
        .unwrap();
    manager
        .confirm_verification_strand(&challenge.transaction_id, "123456", Some(fake_binding(1)))
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
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
        "z6MkPhoneVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );
    manager.upsert_device_with_key(
        alice.clone(),
        laptop.clone(),
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
        "z6MkLaptopVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );

    let challenge = manager
        .begin_sas_verification(&alice, &phone, "123456")
        .unwrap();
    assert!(challenge.commitment.starts_with("sha256:"));
    let qr = manager
        .qr_verification_payload(&challenge.transaction_id)
        .unwrap();
    DeviceManager::validate_qr_verification_payload(&qr, &alice, &phone).unwrap();
    assert!(
        manager
            .confirm_verification_strand(&challenge.transaction_id, "000000", None)
            .is_err()
    );
    assert_eq!(
        manager.device(&alice, &phone).unwrap().verification,
        DeviceVerificationState::VerificationFailed
    );

    // Record a cross-signing publish for Alice and a proper per-device
    // binding for both devices.
    manager
        .record_cross_signing_publish(sample_publish(&alice, 1))
        .unwrap();
    manager.start_verification(&alice, &phone).unwrap();
    manager
        .verify_device(&alice, &phone, Some(fake_binding(1)))
        .unwrap();
    manager
        .attach_cross_signing_binding(&alice, &laptop, fake_binding(1))
        .unwrap();

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
            DeviceMetadata {
                name: None,
                model: None,
                os: None,
                last_seen_at: None,
            },
            "z6MkVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );
    }
    manager
        .record_cross_signing_publish(sample_publish(&alice, 1))
        .unwrap();
    manager
        .verify_device(&alice, &phone, Some(fake_binding(1)))
        .unwrap();
    // Laptop has no binding yet — propagation MUST fail.
    let err = manager
        .propagate_trust(&alice, &phone, &laptop)
        .unwrap_err();
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
            DeviceMetadata {
                name: None,
                model: None,
                os: None,
                last_seen_at: None,
            },
            "z6MkVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );
    }
    manager
        .record_cross_signing_publish(sample_publish(&alice, 1))
        .unwrap();
    manager
        .verify_device(&alice, &phone, Some(fake_binding(1)))
        .unwrap();
    manager
        .verify_device(&alice, &laptop, Some(fake_binding(1)))
        .unwrap();

    let reset = CrossSigningResetContent {
        principal_id: alice.clone(),
        trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap(),
        reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
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
        assert_eq!(
            dev.verification,
            DeviceVerificationState::NeedsReverification
        );
        assert!(dev.cross_signing_binding.is_none());
    }
    // No publish accepted right now — attaching a new binding must fail.
    assert!(
        manager
            .attach_cross_signing_binding(&alice, &phone, fake_binding(2))
            .is_err()
    );

    // Round 4 (spec a77b995): reset bumps generation high-water to
    // `new_generation = 2`, so the next publish chains from there —
    // expected_previous_generation = 2, generation = 3. The
    // pre-round-4 wire (publish(gen=2) directly after reset) is rejected.
    manager
        .record_cross_signing_publish(sample_publish(&alice, 3))
        .unwrap();
    manager
        .attach_cross_signing_binding(&alice, &phone, fake_binding(3))
        .unwrap();
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
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
        "z6MkVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );
    manager
        .record_cross_signing_publish(sample_publish(&alice, 1))
        .unwrap();
    manager
        .verify_device(&alice, &phone, Some(fake_binding(1)))
        .unwrap();

    // Same generation rejected.
    assert!(
        manager
            .record_cross_signing_publish(sample_publish(&alice, 1))
            .is_err()
    );

    // Advancing the publish invalidates the existing device binding.
    manager
        .record_cross_signing_publish(sample_publish(&alice, 2))
        .unwrap();
    let dev = manager.device(&alice, &phone).unwrap();
    assert!(dev.cross_signing_binding.is_none());
    assert_eq!(
        dev.verification,
        DeviceVerificationState::NeedsReverification
    );
}

#[test]
fn evaluate_trust_chain_states() {
    let alice = did("alice");
    let phone = device("phone");
    let mut manager = DeviceManager::new();
    manager.upsert_device_with_key(
        alice.clone(),
        phone.clone(),
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
        "z6MkVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );

    // No publish, no binding → Unverified.
    let outcome = manager
        .evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true))
        .unwrap();
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
    let outcome = manager
        .evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true))
        .unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::Bootstrap);

    // After a publish, bootstrap is no longer accepted.
    manager
        .record_cross_signing_publish(sample_publish(&alice, 1))
        .unwrap();
    let outcome = manager
        .evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true))
        .unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::NeedsReverification);

    // Real binding + verifier that always returns true → CrossSigned.
    manager
        .attach_cross_signing_binding(&alice, &phone, fake_binding(1))
        .unwrap();
    let outcome = manager
        .evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true))
        .unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::CrossSigned);

    // Verifier rejects → Invalid.
    let outcome = manager
        .evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(false))
        .unwrap();
    assert_eq!(outcome, DeviceTrustChainOutcome::Invalid);

    // Generation behind accepted → NeedsReverification.
    manager
        .record_cross_signing_publish(sample_publish(&alice, 2))
        .unwrap();
    manager
        .attach_cross_signing_binding(&alice, &phone, fake_binding(2))
        .unwrap();
    // Manually back-date the binding to test the stale-generation branch.
    let device_ref = manager
        .user_devices(&alice)
        .into_iter()
        .next()
        .unwrap()
        .clone();
    let mut stale = device_ref.clone();
    stale.cross_signing_binding = Some(fake_binding(1));
    // Replace via upsert+attach.
    manager.upsert_device_with_key(
        alice.clone(),
        phone.clone(),
        device_ref.metadata,
        "z6MkVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );
    // Force-set the stale binding back through the manager API:
    manager
        .verify_device(&alice, &phone, Some(fake_binding(1)))
        .unwrap();
    let outcome = manager
        .evaluate_trust_chain(&alice, &phone, |_, _, _, _| Ok(true))
        .unwrap();
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
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
        "z6MkVerifyKey",
        "z6LSTestHpkeKey".to_owned(),
        vec!["ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(), "ck.mls.v1".to_owned()],
    );
    manager
        .record_cross_signing_publish(sample_publish(&alice, 1))
        .unwrap();

    // Start a SAS verification (no confirm yet).
    let challenge = manager
        .begin_sas_verification(&alice, &phone, "000000")
        .unwrap();
    let reset = CrossSigningResetContent {
        principal_id: alice.clone(),
        trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap(),
        reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
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
    assert!(
        manager
            .confirm_verification_strand(&challenge.transaction_id, "000000", None)
            .is_err()
    );
    let dev = manager.device(&alice, &phone).unwrap();
    assert!(matches!(
        dev.verification,
        DeviceVerificationState::VerificationCancelled
            | DeviceVerificationState::NeedsReverification
    ));
}

// ---- Tier-2 stateless chain verifier (`verify_device_cross_signing_chain`) ----

/// Build a fully-signed `(publish, device binding)` pair plus the raw PSK key
/// material a DID-anchoring caller would supply, using real Ed25519 keys and the
const TEST_HPKE_KEY: &str = "z6LSTestChainHpkeKey";

fn test_algorithms() -> Vec<String> {
    vec![
        "ck.hpke_x25519_aead_xchacha20poly1305.v1".to_owned(),
        "ck.mls.v1".to_owned(),
    ]
}

/// SAME canonical-input constructors the verifier uses. `psk_seed` / `ssk_seed`
/// pick the keypairs; `publish_generation` is the accepted publish generation;
/// `binding_generation` is the `ssk_generation` baked into the device binding.
#[allow(clippy::type_complexity)]
fn signed_chain_fixture(
    principal: &Did,
    device_id: &DeviceId,
    device_public_key: &str,
    psk_seed: [u8; 32],
    ssk_seed: [u8; 32],
    publish_generation: u64,
    binding_generation: u64,
) -> (
    CrossSigningPublishContent,
    DeviceTrustBinding,
    cokret_signatures::PublicKeyMaterial,
) {
    use ed25519_dalek::{Signer, SigningKey};

    let psk = SigningKey::from_bytes(&psk_seed);
    let ssk = SigningKey::from_bytes(&ssk_seed);
    let psk_multibase =
        cokret_core::ed25519_pubkey_to_did_key_multibase(&psk.verifying_key().to_bytes());
    let ssk_multibase =
        cokret_core::ed25519_pubkey_to_did_key_multibase(&ssk.verifying_key().to_bytes());

    // The published SSK record (PSK signs this over the §5.1 canonical input).
    let mut publish = CrossSigningPublishContent {
        principal_id: principal.clone(),
        trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap(),
        principal_signing_key: CrossSigningKeyRecord {
            kid: format!("{principal}#ck_principal_signing_v1"),
            alg: "EdDSA".to_owned(),
            public_key: psk_multibase,
            key_format: "multibase".to_owned(),
        },
        self_signing_key: SignedCrossSigningKey {
            key: CrossSigningKeyRecord {
                kid: format!("{principal}#ck_self_signing_v1"),
                alg: "EdDSA".to_owned(),
                public_key: ssk_multibase,
                key_format: "multibase".to_owned(),
            },
            binding: CrossSigningBinding {
                verification_method: format!("{principal}#ck_principal_signing_v1"),
                alg: "EdDSA".to_owned(),
                signature: String::new(),
            },
        },
        user_signing_key: SignedCrossSigningKey {
            key: CrossSigningKeyRecord {
                kid: format!("{principal}#ck_user_signing_v1"),
                alg: "EdDSA".to_owned(),
                public_key: "z6MkUserDistinct".to_owned(),
                key_format: "multibase".to_owned(),
            },
            binding: CrossSigningBinding {
                verification_method: format!("{principal}#ck_principal_signing_v1"),
                alg: "EdDSA".to_owned(),
                signature: "unused".to_owned(),
            },
        },
        expected_previous_generation: publish_generation.saturating_sub(1),
        generation: publish_generation,
        issued_at: Utc::now(),
    };
    // PSK signs the SSK record over the canonical §5.1 input.
    let ssk_input = publish.self_signing_binding_input().unwrap();
    publish.self_signing_key.binding.signature =
        cokret_core::base64url_encode(psk.sign(&ssk_input).to_bytes());

    // SSK signs the device binding over the canonical §5.2 input.
    let device_input = DeviceTrustBinding::canonical_input(
        principal,
        device_id,
        device_public_key,
        TEST_HPKE_KEY,
        &test_algorithms(),
        binding_generation,
    )
    .unwrap();
    let binding = DeviceTrustBinding {
        verification_method: format!("{principal}#ck_self_signing_v1"),
        alg: "EdDSA".to_owned(),
        ssk_generation: binding_generation,
        signature: cokret_core::base64url_encode(ssk.sign(&device_input).to_bytes()),
    };

    let anchored_psk = cokret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: psk.verifying_key().to_bytes().to_vec(),
    };
    (publish, binding, anchored_psk)
}

#[test]
fn verify_chain_accepts_well_formed_cross_signed_device() {
    let alice = did("alice");
    let phone = device("phone");
    let device_public_key = "z6MkDevicePhoneVerifyKey";
    let (publish, binding, anchored_psk) = signed_chain_fixture(
        &alice,
        &phone,
        device_public_key,
        [11u8; 32],
        [22u8; 32],
        1,
        1,
    );
    let state = verify_device_cross_signing_chain(
        &publish,
        &binding,
        &alice,
        &phone,
        device_public_key,
        TEST_HPKE_KEY,
        &test_algorithms(),
        &anchored_psk,
    );
    assert_eq!(state, DeviceTrustState::CrossSigned);
}

#[test]
fn verify_chain_rejects_tampered_device_binding() {
    let alice = did("alice");
    let phone = device("phone");
    let device_public_key = "z6MkDevicePhoneVerifyKey";
    let (publish, mut binding, anchored_psk) = signed_chain_fixture(
        &alice,
        &phone,
        device_public_key,
        [11u8; 32],
        [22u8; 32],
        1,
        1,
    );
    // Flip a byte in the device-binding signature → SSK→device check fails.
    let mut raw = cokret_core::base64url_decode(&binding.signature).unwrap();
    raw[0] ^= 0xff;
    binding.signature = cokret_core::base64url_encode(&raw);
    let state = verify_device_cross_signing_chain(
        &publish,
        &binding,
        &alice,
        &phone,
        device_public_key,
        TEST_HPKE_KEY,
        &test_algorithms(),
        &anchored_psk,
    );
    assert_eq!(state, DeviceTrustState::Unverified);
}

#[test]
fn verify_chain_rejects_device_key_substitution() {
    let alice = did("alice");
    let phone = device("phone");
    let signed_key = "z6MkDevicePhoneVerifyKey";
    let (publish, binding, anchored_psk) =
        signed_chain_fixture(&alice, &phone, signed_key, [11u8; 32], [22u8; 32], 1, 1);
    // The binding was signed over `signed_key`; verifying against a DIFFERENT
    // device_public_key must fail (closes "directory key ⇔ cross-signed key").
    let state = verify_device_cross_signing_chain(
        &publish,
        &binding,
        &alice,
        &phone,
        "z6MkAttackerSubstituteKey",
        TEST_HPKE_KEY,
        &test_algorithms(),
        &anchored_psk,
    );
    assert_eq!(state, DeviceTrustState::Unverified);
}

#[test]
fn verify_chain_rejects_tampered_ssk_binding() {
    let alice = did("alice");
    let phone = device("phone");
    let device_public_key = "z6MkDevicePhoneVerifyKey";
    let (mut publish, binding, anchored_psk) = signed_chain_fixture(
        &alice,
        &phone,
        device_public_key,
        [11u8; 32],
        [22u8; 32],
        1,
        1,
    );
    // Corrupt the PSK→SSK binding signature → first check fails.
    let mut raw =
        cokret_core::base64url_decode(&publish.self_signing_key.binding.signature).unwrap();
    raw[5] ^= 0xff;
    publish.self_signing_key.binding.signature = cokret_core::base64url_encode(&raw);
    let state = verify_device_cross_signing_chain(
        &publish,
        &binding,
        &alice,
        &phone,
        device_public_key,
        TEST_HPKE_KEY,
        &test_algorithms(),
        &anchored_psk,
    );
    assert_eq!(state, DeviceTrustState::Unverified);
}

#[test]
fn verify_chain_rejects_wrong_anchored_psk() {
    let alice = did("alice");
    let phone = device("phone");
    let device_public_key = "z6MkDevicePhoneVerifyKey";
    let (publish, binding, _) = signed_chain_fixture(
        &alice,
        &phone,
        device_public_key,
        [11u8; 32],
        [22u8; 32],
        1,
        1,
    );
    // Caller anchors a DIFFERENT PSK than the one that signed the SSK record.
    let wrong_psk = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
    let wrong = cokret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: wrong_psk.verifying_key().to_bytes().to_vec(),
    };
    let state = verify_device_cross_signing_chain(
        &publish,
        &binding,
        &alice,
        &phone,
        device_public_key,
        TEST_HPKE_KEY,
        &test_algorithms(),
        &wrong,
    );
    assert_eq!(state, DeviceTrustState::Unverified);
}

#[test]
fn verify_chain_stale_generation_needs_reverification() {
    let alice = did("alice");
    let phone = device("phone");
    let device_public_key = "z6MkDevicePhoneVerifyKey";
    // Accepted publish is generation 2, but the device binding was signed under
    // generation 1 (cross-signing reset since). SSK binding is valid → the
    // generation comparison drives the verdict to NeedsReverification.
    let (publish, binding, anchored_psk) = signed_chain_fixture(
        &alice,
        &phone,
        device_public_key,
        [11u8; 32],
        [22u8; 32],
        2,
        1,
    );
    let state = verify_device_cross_signing_chain(
        &publish,
        &binding,
        &alice,
        &phone,
        device_public_key,
        TEST_HPKE_KEY,
        &test_algorithms(),
        &anchored_psk,
    );
    assert_eq!(state, DeviceTrustState::NeedsReverification);
}

#[test]
fn verify_chain_future_generation_unverified() {
    let alice = did("alice");
    let phone = device("phone");
    let device_public_key = "z6MkDevicePhoneVerifyKey";
    // Binding references generation 3 but only generation 1 is accepted → future
    // generation → Unverified (caller must re-sync the control stream).
    let (publish, binding, anchored_psk) = signed_chain_fixture(
        &alice,
        &phone,
        device_public_key,
        [11u8; 32],
        [22u8; 32],
        1,
        3,
    );
    let state = verify_device_cross_signing_chain(
        &publish,
        &binding,
        &alice,
        &phone,
        device_public_key,
        TEST_HPKE_KEY,
        &test_algorithms(),
        &anchored_psk,
    );
    assert_eq!(state, DeviceTrustState::Unverified);
}

#[test]
fn devices_revoke_and_fail_closed() {
    let alice = did("alice");
    let device_id = device("phone");
    let mut manager = DeviceManager::new();
    manager.upsert_device(
        alice.clone(),
        device_id.clone(),
        DeviceMetadata {
            name: None,
            model: None,
            os: None,
            last_seen_at: None,
        },
    );

    assert!(!manager.is_device_revoked(&alice, &device_id));
    manager.revoke_device(&alice, &device_id);
    assert!(manager.is_device_revoked(&alice, &device_id));
    assert_eq!(manager.revoked_devices_for_user(&alice).len(), 1);
}
