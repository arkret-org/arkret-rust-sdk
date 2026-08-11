//! Negative round-trip coverage for `SdkClaimIssuer.verification_method`.
//!
//! `sdk-conformance-claim.schema.json#/$defs/issuer` and the SDK both enforce
//! the canonical `common-ids#/$defs/did_url` ASCII fragment character class.

use arkret_schema::sdk_conformance::SdkClaimIssuer;
use serde_json::{Value, json};

const INVALID_DID_URLS: &[&str] = &[
    "did:web:release.example#key/1",
    "did:web:release.example#键1",
    "did:web:release.example#key%201",
];

const CANONICAL: &str = "did:web:release.example#claim-key-1";

fn issuer(verification_method: &str) -> Value {
    json!({
        "id": "ak:did_core:webvh:z6mkfixture",
        "verification_method": verification_method,
    })
}

#[test]
fn sdk_claim_issuer_rejects_invalid_did_url_fragments() {
    let accepted = issuer(CANONICAL);
    let parsed: SdkClaimIssuer = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for invalid in INVALID_DID_URLS {
        assert!(
            serde_json::from_value::<SdkClaimIssuer>(issuer(invalid)).is_err(),
            "SdkClaimIssuer must reject invalid DID URL {invalid}"
        );
    }
}

/// `issuer.id` is the stable actor identity core and
/// `issuer.verification_method` is a DID URL; the two value domains are
/// disjoint.
#[test]
fn sdk_claim_issuer_id_and_verification_method_are_disjoint() {
    assert!(
        serde_json::from_value::<SdkClaimIssuer>(issuer("did:web:release.example")).is_err(),
        "an identity core is not a verification method"
    );
    assert!(
        serde_json::from_value::<SdkClaimIssuer>(json!({
            "id": "did:web:release.example#claim-key-1",
            "verification_method": CANONICAL,
        }))
        .is_err(),
        "a DID URL is not an identity core"
    );
}
