//! Known-answer tests for the shared protocol test material.
//!
//! A test-kit that silently changes what it produces is worse than seven
//! copies: every consumer moves at once and nothing goes red. These pin the
//! observable outputs — subject spellings, the HLC template, the derived key,
//! and the canonical bytes and identity of a standard signed Event — so a
//! change to any of them has to be a deliberate edit here.

use arkret_signatures::proof::{PublicKeyMaterial, verify_ed25519_detached_jws_proof};
use arkret_test_kit::hlc::{pinned_hlc, wall_hlc};
use arkret_test_kit::keys::{development_signing_key_seed, seeded_signer};
use arkret_test_kit::negative::wire_negative_from_sdk;
use arkret_test_kit::proof::{ProofFidelity, StructuralOnlyPayloadSigner};
use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
use arkret_test_kit::subjects;
use arkret_wire::{ActorId, EventRef, ScopeRef};
use chrono::{DateTime, Utc};
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn standard_subjects_are_pinned() {
    assert_eq!(subjects::alice_did().as_str(), "did:web:alice.example");
    assert_eq!(
        subjects::alice_core_id().as_str(),
        "ak:did_core:web:alice.example"
    );
    assert_eq!(
        subjects::alice_verification_method().as_str(),
        "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001"
    );
    assert_eq!(
        subjects::bob_verification_method().as_str(),
        "did:web:bob.example#ak:device:01904100-0000-7000-8000-000000000002"
    );
    assert_eq!(
        subjects::station_core_id().as_str(),
        "ak:did_core:web:station.example"
    );
}

#[test]
fn the_pinned_hlc_logical_counter_is_hexadecimal_past_nine() {
    assert_eq!(pinned_hlc(0).as_str(), "01970e589d21-0000-a13f9c2e");
    assert_eq!(pinned_hlc(9).as_str(), "01970e589d21-0009-a13f9c2e");
    // The two formats that were in use across the workspace agree below ten
    // and diverge here: decimal would produce `0010`.
    assert_eq!(pinned_hlc(16).as_str(), "01970e589d21-0010-a13f9c2e");
    assert_eq!(pinned_hlc(255).as_str(), "01970e589d21-00ff-a13f9c2e");
}

#[test]
fn a_wall_clock_hlc_keeps_the_pinned_node_component() {
    let at = "2026-01-01T00:00:00Z"
        .parse::<DateTime<Utc>>()
        .expect("fixture instant");
    assert_eq!(wall_hlc(at, 1).as_str(), "019b76daa800-0001-a13f9c2e");
}

#[test]
fn the_derived_fixture_key_is_bound_to_its_verification_method() {
    let alice = development_signing_key_seed(subjects::alice_verification_method().as_str());
    let bob = development_signing_key_seed(subjects::bob_verification_method().as_str());
    assert_ne!(alice, bob);
    assert_eq!(
        hex(&alice),
        "94e7b9f2cb8f119ac4bfbb53483ae46f3ba0bc73b4cd559a2f68678580c3dd6c"
    );
}

#[test]
fn the_standard_signed_event_identity_is_pinned() {
    let signed = SignedEventFixtureBuilder::new(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: subjects::realm_id(),
        },
        ActorId::account(subjects::alice_account_id()),
        json!({"track_name": subjects::DISCUSSION_TRACK}),
    )
    .sign_verifiable(&seeded_signer(
        subjects::alice_did(),
        subjects::alice_verification_method(),
    ))
    .expect("the standard fixture Event signs");

    assert_eq!(signed.fidelity(), ProofFidelity::Verifiable);
    let event = signed.event();
    assert_eq!(
        event.event_id.as_str(),
        "ak:event:AeZlbBfFlhs4ObtXms3ev-RJ-yXkEdeVYmx5EV5IOKde"
    );
    assert_eq!(event.proofs.len(), 1);
}

#[test]
fn a_placeholder_proof_is_never_reported_as_verifiable() {
    let signed = SignedEventFixtureBuilder::new(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: subjects::realm_id(),
        },
        ActorId::account(subjects::alice_account_id()),
        json!({"track_name": subjects::DISCUSSION_TRACK}),
    )
    .sign_structural_only(&StructuralOnlyPayloadSigner::new(
        subjects::alice_did(),
        subjects::alice_verification_method(),
    ))
    .expect("the placeholder fixture Event builds");

    assert_eq!(signed.fidelity(), ProofFidelity::StructuralOnly);
    assert!(!signed.fidelity().is_verifiable());
}

#[test]
fn a_negative_body_carries_the_mutation_verbatim() {
    let body = wire_negative_from_sdk(&json!({"schema": "ak.schema.message.v1"}), |value| {
        value["schema"] = json!("ak.schema.not_a_message.v1");
    })
    .expect("the baseline serializes");
    assert_eq!(
        body.as_value()["schema"].as_str(),
        Some("ak.schema.not_a_message.v1")
    );
}

#[test]
fn a_verifiable_proof_really_verifies_and_one_changed_byte_breaks_it() {
    let signer = seeded_signer(subjects::alice_did(), subjects::alice_verification_method());
    let event = SignedEventFixtureBuilder::new(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: subjects::realm_id(),
        },
        ActorId::account(subjects::alice_account_id()),
        json!({"track_name": subjects::DISCUSSION_TRACK}),
    )
    .sign_verifiable(&signer)
    .expect("the standard fixture Event signs")
    .expect_verifiable();

    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signer.verifying_key().to_bytes().to_vec(),
    };
    let proof = event.proofs[0].clone();
    let canonical_bytes = arkret_canonical::canonical::canonical_json_bytes(
        &event.digest_payload().expect("the fixture digest payload"),
    )
    .expect("the fixture canonical bytes");

    verify_ed25519_detached_jws_proof(&proof, &canonical_bytes, &event.actor_id, &public_key)
        .expect("a Verifiable fixture proof verifies against its own transcript");

    // One changed byte of the covered transcript must break it. If this ever
    // stops failing, the fixture is signing something other than what it says.
    let mut tampered = canonical_bytes;
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    assert!(
        verify_ed25519_detached_jws_proof(&proof, &tampered, &event.actor_id, &public_key).is_err(),
        "a Verifiable fixture proof must reject a mutated transcript"
    );
}

#[test]
fn a_placeholder_proof_never_verifies() {
    let event = SignedEventFixtureBuilder::new(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: subjects::realm_id(),
        },
        ActorId::account(subjects::alice_account_id()),
        json!({"track_name": subjects::DISCUSSION_TRACK}),
    )
    .sign_structural_only(&StructuralOnlyPayloadSigner::new(
        subjects::alice_did(),
        subjects::alice_verification_method(),
    ))
    .expect("the placeholder fixture Event builds")
    .expect_structural_only();

    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: seeded_signer(subjects::alice_did(), subjects::alice_verification_method())
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let proof = event.proofs[0].clone();
    let canonical_bytes = arkret_canonical::canonical::canonical_json_bytes(
        &event.digest_payload().expect("the fixture digest payload"),
    )
    .expect("the fixture canonical bytes");

    assert!(
        verify_ed25519_detached_jws_proof(&proof, &canonical_bytes, &event.actor_id, &public_key)
            .is_err(),
        "a StructuralOnly placeholder must never satisfy a signature verifier"
    );
}

#[test]
fn complete_event_signing_preserves_inputs_and_matches_direct_sdk_bytes() {
    use arkret_canonical::DigestSuite;
    use arkret_signatures::{SignEventOptions, sign_event};
    use arkret_wire::AuthoredEvent;

    let signer = seeded_signer(subjects::alice_did(), subjects::alice_verification_method());
    let created_at = "2026-08-17T12:34:56.789Z".parse::<DateTime<Utc>>().unwrap();
    let mut event = SignedEventFixtureBuilder::new(
        "ak.message.create",
        ScopeRef::Realm {
            realm_id: subjects::realm_id(),
        },
        ActorId::account(subjects::alice_account_id()),
        json!({"track_name": subjects::DISCUSSION_TRACK}),
    )
    .with_created_at(created_at)
    .build_unsigned()
    .unwrap();
    event.refs.push(EventRef::new(
        "ak:event:AYWFNfF8FDwLazsD2l4T6VYTFaH_DSzEOh9I05VjH0_l",
        "fixture_dependency",
    ));
    let before = event.clone();
    let mut direct =
        AuthoredEvent::finalize_with_digest_suite(event.clone(), DigestSuite::Sha256).unwrap();
    sign_event(
        &mut direct,
        &signer,
        SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    let shared = arkret_test_kit::sign_verifiable_event(event, &signer, DigestSuite::Sha256)
        .unwrap()
        .expect_verifiable();
    assert_eq!(
        serde_json::to_vec(&shared).unwrap(),
        serde_json::to_vec(&direct.into_event()).unwrap()
    );
    assert_eq!(shared.refs, before.refs);
    assert_eq!(shared.scope_ref, before.scope_ref);
    assert_eq!(shared.payload, before.payload);
    assert_eq!(shared.created_at, created_at);
    assert_eq!(shared.proofs[0].created_at, created_at);
}
