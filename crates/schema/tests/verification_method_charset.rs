//! Negative round-trip coverage for `SdkClaimIssuer.verification_method`.
//!
//! `sdk-conformance-claim.schema.json#/$defs/issuer` spells the fragment
//! `[^\s]+`, the widest of the four spellings used across v1. The SDK enforces
//! `common-ids#/$defs/did_url` (`[A-Za-z0-9._:-]+`) instead, so the code is
//! stricter than this schema.
//!
//! See `crates/models-identity/tests/verification_method_charset.rs` for the
//! full rationale and `review/spec-open/` gap G1
//! (`verification-method-fragment-charset-inconsistent`). Together the three
//! files are the complete list of what would have to change if the spec ever
//! chose to widen instead of narrow.

use arkret_schema::sdk_conformance::SdkClaimIssuer;
use serde_json::{Value, json};

const WIDER_THAN_DID_URL: &[&str] = &[
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
fn sdk_claim_issuer_rejects_fragments_wider_than_did_url() {
    let accepted = issuer(CANONICAL);
    let parsed: SdkClaimIssuer = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for wide in WIDER_THAN_DID_URL {
        assert!(
            serde_json::from_value::<SdkClaimIssuer>(issuer(wide)).is_err(),
            "SdkClaimIssuer must reject schema-wider fragment {wide}"
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
