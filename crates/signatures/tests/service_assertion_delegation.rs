#![cfg(feature = "webvh")]

use arkret_models_identity::service_identity::{
    ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT, CanonicalServiceUrl, ServiceRegistrationKey,
};
use arkret_signatures::eddsa_jcs_2022::verify_eddsa_jcs_2022_proof;
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, ServiceRotationInput,
    prepare_service_registration_inception_with_assertion_keys, prepare_service_rotation,
};
use arkret_wire::ServiceKind;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

#[test]
fn delegated_assertion_key_is_bound_by_the_station_inception_proof() {
    let endpoint = url::Url::parse("https://station.example/").unwrap();
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(endpoint.as_str()).unwrap(),
    )
    .unwrap();
    let input = ServiceRegistrationInceptionInput {
        provider_endpoint: &endpoint,
        registration_key: &registration,
        also_known_as: &[],
        version_time: chrono::Utc::now(),
        did_key_fragment: Some("notary-key"),
    };
    let delegated_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes(),
    );
    let prepared = prepare_service_registration_inception_with_assertion_keys(
        &mut ChaCha20Rng::from_seed([3; 32]),
        &input,
        &[7; 32],
        &[(
            ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT,
            delegated_key.as_str(),
        )],
    )
    .unwrap();
    let method_id = format!(
        "{}#{ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT}",
        prepared.did
    );
    let state = &prepared.log_entry["state"];
    assert!(
        state["assertionMethod"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(method_id))
    );
    let method = state["verificationMethod"]
        .as_array()
        .unwrap()
        .iter()
        .find(|method| method["id"] == method_id)
        .unwrap();
    assert_eq!(method["controller"], prepared.did);
    assert_eq!(method["publicKeyMultibase"], delegated_key);
    assert_eq!(state["service"].as_array().unwrap().len(), 1);
    assert_eq!(state["service"][0]["serviceKind"], "station");

    let mut unsigned = prepared.log_entry.clone();
    let proofs = unsigned.as_object_mut().unwrap().remove("proof").unwrap();
    let update_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&prepared.update_key_seed)
            .verifying_key()
            .as_bytes(),
    );
    verify_eddsa_jcs_2022_proof(&unsigned, &proofs[0], &update_key).unwrap();
    unsigned["state"]["assertionMethod"] = serde_json::json!([]);
    assert!(verify_eddsa_jcs_2022_proof(&unsigned, &proofs[0], &update_key).is_err());

    for keys in [
        vec![("notary-key", delegated_key.as_str())],
        vec![("account-authority", "invalid-key")],
        vec![
            ("account-authority", delegated_key.as_str()),
            ("account-authority", delegated_key.as_str()),
        ],
    ] {
        assert!(
            prepare_service_registration_inception_with_assertion_keys(
                &mut ChaCha20Rng::from_seed([3; 32]),
                &input,
                &[7; 32],
                &keys,
            )
            .is_err()
        );
    }
}

/// A Station that minted without a delegated assertion key is not stuck with
/// that document forever: the same key material that proves control at
/// inception advances the log, so an Account Authority can be authorized after
/// the fact instead of forcing the deployment to re-provision its identity.
#[test]
fn a_delegated_assertion_key_can_be_added_after_inception() {
    let inception_time = chrono::Utc::now();
    let endpoint = url::Url::parse("https://station.example/").unwrap();
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(endpoint.as_str()).unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception_with_assertion_keys(
        &mut ChaCha20Rng::from_seed([3; 32]),
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &endpoint,
            registration_key: &registration,
            also_known_as: &[],
            version_time: inception_time,
            did_key_fragment: Some("notary-key"),
        },
        &[7; 32],
        &[],
    )
    .unwrap();
    let method_id = format!(
        "{}#{ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT}",
        inception.did
    );
    assert!(
        !inception.log_entry["state"]["assertionMethod"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(method_id)),
        "the inception under test deliberately carries no delegated key"
    );

    let delegated_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes(),
    );
    let mut state = inception.log_entry["state"].clone();
    state["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": method_id,
            "type": "Multikey",
            "controller": inception.did,
            "publicKeyMultibase": delegated_key,
        }));
    state["assertionMethod"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(method_id));

    let third_update_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes(),
    );
    let rotation = prepare_service_rotation(&ServiceRotationInput {
        did: &inception.did,
        previous_entries: &[inception.log_entry.clone()],
        state: &state,
        // The inception pre-committed this key, so it is the only one that may
        // sign the successor.
        current_update_seed: &inception.next_update_key_seed,
        next_update_public_key_multibase: &third_update_key,
        version_time: inception_time + chrono::Duration::seconds(1),
    })
    .unwrap();

    assert_eq!(rotation.previous_version_id, inception.version_id);
    assert!(rotation.version_id.starts_with("2-"));
    assert_eq!(
        rotation.log_entry["parameters"]["updateKeys"][0],
        serde_json::json!(rotation.current_update_public_key_multibase)
    );
    assert_eq!(
        rotation.log_entry["parameters"]["scid"], inception.log_entry["parameters"]["scid"],
        "a document change keeps the DID, so the SCID never moves"
    );
    let rotated_state = &rotation.log_entry["state"];
    let method = rotated_state["verificationMethod"]
        .as_array()
        .unwrap()
        .iter()
        .find(|method| method["id"] == method_id)
        .expect("the delegated key is now published");
    assert_eq!(method["publicKeyMultibase"], delegated_key);
    assert!(
        rotated_state["assertionMethod"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(method_id))
    );

    // The successor carries a real proof over its own bytes, verified against
    // the key the previous entry named.
    let mut unsigned = rotation.log_entry.clone();
    let proofs = unsigned.as_object_mut().unwrap().remove("proof").unwrap();
    verify_eddsa_jcs_2022_proof(
        &unsigned,
        &proofs[0],
        &rotation.current_update_public_key_multibase,
    )
    .expect("successor proof verifies under the pre-committed update key");
}

/// The pre-rotation chain is what makes a hosted log unforgeable by its host,
/// so the builder refuses to emit an entry that breaks it rather than leaving
/// the Provider to reject it after publication.
#[test]
fn service_rotation_refuses_a_broken_pre_rotation_chain() {
    let inception_time = chrono::Utc::now();
    let endpoint = url::Url::parse("https://station.example/").unwrap();
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(endpoint.as_str()).unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception_with_assertion_keys(
        &mut ChaCha20Rng::from_seed([5; 32]),
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &endpoint,
            registration_key: &registration,
            also_known_as: &[],
            version_time: inception_time,
            did_key_fragment: Some("notary-key"),
        },
        &[11; 32],
        &[],
    )
    .unwrap();
    let state = inception.log_entry["state"].clone();
    let fresh_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[12; 32]).verifying_key().as_bytes(),
    );

    // Signing with a key the previous entry never pre-committed.
    let error = prepare_service_rotation(&ServiceRotationInput {
        did: &inception.did,
        previous_entries: &[inception.log_entry.clone()],
        state: &state,
        current_update_seed: &[13; 32],
        next_update_public_key_multibase: &fresh_key,
        version_time: inception_time + chrono::Duration::seconds(1),
    })
    .err()
    .expect("an unannounced update key must not produce an entry");
    assert!(
        format!("{error}").contains("precommitted"),
        "unexpected error: {error}"
    );

    // Pre-committing a key this log has already burned. `identity-did.md` §3.7
    // I-4 marks a replaced update key spent; re-announcing it would let a
    // compromised past key become live again.
    let inception_update_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&inception.update_key_seed)
            .verifying_key()
            .as_bytes(),
    );
    let error = prepare_service_rotation(&ServiceRotationInput {
        did: &inception.did,
        previous_entries: &[inception.log_entry.clone()],
        state: &state,
        current_update_seed: &inception.next_update_key_seed,
        next_update_public_key_multibase: &inception_update_key,
        version_time: inception_time + chrono::Duration::seconds(1),
    })
    .err()
    .expect("a spent update key must not be re-announced");
    assert!(
        format!("{error}").contains("already activated"),
        "unexpected error: {error}"
    );
}

#[test]
fn service_rotation_requires_a_strictly_later_version_time() {
    let endpoint = url::Url::parse("https://station.example/").unwrap();
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(endpoint.as_str()).unwrap(),
    )
    .unwrap();
    let version_time = chrono::Utc::now();
    let inception = prepare_service_registration_inception_with_assertion_keys(
        &mut ChaCha20Rng::from_seed([15; 32]),
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &endpoint,
            registration_key: &registration,
            also_known_as: &[],
            version_time,
            did_key_fragment: Some("notary-key"),
        },
        &[16; 32],
        &[],
    )
    .unwrap();
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[17; 32]).verifying_key().as_bytes(),
    );

    let error = prepare_service_rotation(&ServiceRotationInput {
        did: &inception.did,
        previous_entries: &[inception.log_entry.clone()],
        state: &inception.log_entry["state"],
        current_update_seed: &inception.next_update_key_seed,
        next_update_public_key_multibase: &next_key,
        version_time,
    })
    .err()
    .expect("equal versionTime must be rejected");
    assert!(format!("{error}").contains("later than the previous entry"));
}
