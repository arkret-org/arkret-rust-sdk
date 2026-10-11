//! Negative round-trip coverage for the canonical v1 `verification_method`
//! DID URL fragment charset.
//!
//! `did-usage-and-verification.md` §2.2 requires every `verification_method` to
//! be a DID URL. `common-ids.schema.json#/$defs/did_url` and every field below
//! use the ASCII `[A-Za-z0-9._:-]+` fragment contract implemented by
//! `arkret_wire::DidUrl`.
//!
//! Companion file for the `arkret-models-collaboration` and `arkret-schema`
//! members of the same list.

use arkret_models_identity::member_identity::MemberIdentityProof;
use arkret_models_identity::service_identity::ServiceWebvhDataIntegrityProof;
use serde_json::{Value, json};

/// Fragments outside the canonical DID URL fragment character class.
const INVALID_DID_URLS: &[&str] = &[
    "did:web:alice.example#key/1",
    "did:web:alice.example#键1",
    "did:web:alice.example#key%201",
];

const CANONICAL: &str = "did:web:alice.example#key-1";

fn hash() -> String {
    format!("sha256:{}", "0".repeat(64))
}

/// Swap `verification_method` (or its camelCase spelling) in a JSON object.
fn with_verification_method(mut value: Value, key: &str, replacement: &str) -> Value {
    value[key] = Value::String(replacement.to_owned());
    value
}

fn member_identity_proof(verification_method: &str) -> Value {
    json!({
        "verification_method": verification_method,
        "signature_algorithm": "Ed25519",
        "payload_digest": hash(),
        "signature": "c2ln",
    })
}

fn service_webvh_proof(verification_method: &str) -> Value {
    json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "proofValue": "zProof",
    })
}

#[test]
fn member_identity_proof_rejects_invalid_did_url_fragments() {
    let accepted = member_identity_proof(CANONICAL);
    let parsed: MemberIdentityProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for invalid in INVALID_DID_URLS {
        let value = with_verification_method(
            member_identity_proof(CANONICAL),
            "verification_method",
            invalid,
        );
        assert!(
            serde_json::from_value::<MemberIdentityProof>(value).is_err(),
            "MemberIdentityProof must reject invalid DID URL {invalid}"
        );
    }
}

#[test]
fn service_webvh_data_integrity_proof_rejects_invalid_did_url_fragments() {
    // The wire member uses its registered camelCase spelling.
    let accepted = service_webvh_proof(CANONICAL);
    let parsed: ServiceWebvhDataIntegrityProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for invalid in INVALID_DID_URLS {
        let value = with_verification_method(
            service_webvh_proof(CANONICAL),
            "verificationMethod",
            invalid,
        );
        assert!(
            serde_json::from_value::<ServiceWebvhDataIntegrityProof>(value).is_err(),
            "ServiceWebvhDataIntegrityProof must reject invalid DID URL {invalid}"
        );
    }
}

/// A bare DID is never a verification method
/// (producer proof contract: a bare DID is not a verification method).
#[test]
fn bare_did_is_rejected_by_every_migrated_field() {
    const BARE: &str = "did:web:alice.example";
    assert!(
        serde_json::from_value::<MemberIdentityProof>(member_identity_proof(BARE)).is_err(),
        "MemberIdentityProof must reject a bare DID"
    );
    assert!(
        serde_json::from_value::<ServiceWebvhDataIntegrityProof>(service_webvh_proof(BARE))
            .is_err(),
        "ServiceWebvhDataIntegrityProof must reject a bare DID"
    );
}
