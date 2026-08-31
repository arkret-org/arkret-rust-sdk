#![cfg(feature = "webvh")]

use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_signatures::eddsa_jcs_2022::verify_eddsa_jcs_2022_proof;
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception_with_assertion_keys,
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
        &[("account-authority", delegated_key.as_str())],
    )
    .unwrap();
    let method_id = format!("{}#account-authority", prepared.did);
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
