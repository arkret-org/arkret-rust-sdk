//! KAT for the PCR genesis founding-device key digests.
//!
//! Review 2026-09-02-1955 deleted `device_key_digest` and `hpke_key_digest` from
//! `founding_device_descriptor`, leaving the receipt (`pcr_genesis_scope`) as
//! their only carrier and this SDK as their only implementation. That matters
//! because the previous three implementations all digested the *whole*
//! `did:key:` URI while the receipt schema binds the bare multikey; they agreed
//! with each other and with nothing else. These tests pin the receipt's formula
//! against the shipped fixture, including the retired convention as a negative.

use arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor;
use arkret_schema_conformance::spec_json_artifact;

fn fixture() -> serde_json::Value {
    spec_json_artifact("fixtures/pcr-genesis-fixture.json").unwrap()
}

fn descriptor() -> FoundingDeviceDescriptor {
    serde_json::from_value(fixture()["founding_device_descriptor"].clone()).unwrap()
}

#[test]
fn device_key_digest_matches_the_fixture_kat() {
    let kat = fixture();
    let kat = &kat["founding_device_key_digest_kat"]["device_key_digest"];
    let expected = kat["expected"].as_str().unwrap();
    assert_eq!(descriptor().device_key_digest().unwrap().as_str(), expected);
}

#[test]
fn hpke_key_digest_matches_the_fixture_kat() {
    let kat = fixture();
    let kat = &kat["founding_device_key_digest_kat"]["hpke_key_digest"];
    let expected = kat["expected"].as_str().unwrap();
    assert_eq!(descriptor().hpke_key_digest().unwrap().as_str(), expected);
}

#[test]
fn the_retired_whole_uri_preimage_is_not_what_the_sdk_computes() {
    let kat = fixture();
    let kat = &kat["founding_device_key_digest_kat"]["device_key_digest"];
    let retired = kat["rejected_retired_expected"].as_str().unwrap();
    assert_ne!(
        descriptor().device_key_digest().unwrap().as_str(),
        retired,
        "digesting the whole did:key: URI is the retired convention"
    );
}

#[test]
fn the_descriptor_wire_form_carries_neither_digest() {
    // Serialising the typed descriptor is the check that matters: a struct field
    // would put the mirror back on the wire even if nothing read it.
    let encoded = serde_json::to_value(descriptor()).unwrap();
    let object = encoded.as_object().unwrap();
    assert!(!object.contains_key("device_key_digest"));
    assert!(!object.contains_key("hpke_key_digest"));
    assert!(object.contains_key("device_public_key_did"));
    assert!(object.contains_key("hpke_key"));
}

#[test]
fn a_descriptor_carrying_either_digest_is_rejected() {
    for mirror in ["device_key_digest", "hpke_key_digest"] {
        let mut encoded = serde_json::to_value(descriptor()).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert(mirror.to_owned(), serde_json::json!(format!("sha256:{}", "0".repeat(64))));
        assert!(
            serde_json::from_value::<FoundingDeviceDescriptor>(encoded).is_err(),
            "{mirror} must not deserialize into the descriptor"
        );
    }
}

#[test]
fn a_device_public_key_did_without_the_did_key_prefix_fails_closed() {
    let mut descriptor = descriptor();
    descriptor.device_public_key_did =
        arkret_wire::NonEmptyString::new("z6MkNotADidKeyUri".to_owned()).unwrap();
    assert!(descriptor.device_key_digest().is_err());
}
