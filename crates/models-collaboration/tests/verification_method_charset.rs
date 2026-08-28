//! Negative round-trip coverage for the canonical v1 `verification_method`
//! DID URL fragment charset.
//!
//! See `crates/models-identity/tests/verification_method_charset.rs` for the
//! shared contract; this file covers the `arkret-models-collaboration` members.

use arkret_models_collaboration::governance::membership_invite::{
    InviteClaimBindingProof, InviteSubjectProof,
};
use arkret_models_collaboration::objects::profiles::IdentityLinkProof;
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

fn with_verification_method(mut value: Value, replacement: &str) -> Value {
    value["verification_method"] = Value::String(replacement.to_owned());
    value
}

fn invite_claim_binding_proof(verification_method: &str) -> Value {
    json!({
        "verification_id": "ak:did_core:web:verify.example",
        "verification_method": verification_method,
        "subject_id": "ak:did_core:web:bob.example",
        "realm_id": "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
        "audience": "did:web:realm.example",
        "claim_nonce": "nonce-claim-proof-1",
        "expires_at": "2099-01-01T00:00:00.000Z",
        "signature": "c2ln",
    })
}

fn invite_subject_proof(verification_method: &str) -> Value {
    json!({
        "verification_method": verification_method,
        "signature_algorithm": "Ed25519",
        "transcript_digest": hash(),
        "signature": "c2ln",
    })
}

fn identity_link_proof(verification_method: &str) -> Value {
    json!({
        "verification_method": verification_method,
        "signature_algorithm": "Ed25519",
        "payload_digest": hash(),
        "signature": "c2ln",
    })
}

#[test]
fn invite_claim_binding_proof_rejects_invalid_did_url_fragments() {
    let accepted = invite_claim_binding_proof(CANONICAL);
    let parsed: InviteClaimBindingProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for invalid in INVALID_DID_URLS {
        let value = with_verification_method(invite_claim_binding_proof(CANONICAL), invalid);
        assert!(
            serde_json::from_value::<InviteClaimBindingProof>(value).is_err(),
            "InviteClaimBindingProof must reject invalid DID URL {invalid}"
        );
    }
}

#[test]
fn invite_subject_proof_rejects_invalid_did_url_fragments() {
    let accepted = invite_subject_proof(CANONICAL);
    let parsed: InviteSubjectProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for invalid in INVALID_DID_URLS {
        let value = with_verification_method(invite_subject_proof(CANONICAL), invalid);
        assert!(
            serde_json::from_value::<InviteSubjectProof>(value).is_err(),
            "InviteSubjectProof must reject invalid DID URL {invalid}"
        );
    }
}

#[test]
fn identity_link_proof_rejects_invalid_did_url_fragments() {
    let accepted = identity_link_proof(CANONICAL);
    let parsed: IdentityLinkProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for invalid in INVALID_DID_URLS {
        let value = with_verification_method(identity_link_proof(CANONICAL), invalid);
        assert!(
            serde_json::from_value::<IdentityLinkProof>(value).is_err(),
            "IdentityLinkProof must reject invalid DID URL {invalid}"
        );
    }
}

#[test]
fn bare_did_is_rejected_by_every_migrated_field() {
    const BARE: &str = "did:web:alice.example";
    assert!(
        serde_json::from_value::<InviteClaimBindingProof>(invite_claim_binding_proof(BARE))
            .is_err(),
        "InviteClaimBindingProof must reject a bare DID"
    );
    assert!(
        serde_json::from_value::<InviteSubjectProof>(invite_subject_proof(BARE)).is_err(),
        "InviteSubjectProof must reject a bare DID"
    );
    assert!(
        serde_json::from_value::<IdentityLinkProof>(identity_link_proof(BARE)).is_err(),
        "IdentityLinkProof must reject a bare DID"
    );
}
