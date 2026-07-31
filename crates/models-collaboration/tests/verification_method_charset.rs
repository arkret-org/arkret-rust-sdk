//! Negative round-trip coverage for `verification_method` fields whose v1
//! schema pattern is **wider** than the `DidUrl` charset the SDK enforces.
//!
//! See `crates/models-identity/tests/verification_method_charset.rs` for the
//! full rationale; this file covers the `arkret-models-collaboration` members of
//! the same seven-field list and pins the exact values that would have to start
//! being accepted if `review/spec-open/` gap G1
//! (`verification-method-fragment-charset-inconsistent`) ever widened the
//! charset instead of narrowing the schemas.

use arkret_models_collaboration::governance::membership_invite::{
    InviteClaimBindingProof, InviteSubjectProof,
};
use arkret_models_collaboration::objects::profiles::IdentityLinkProof;
use serde_json::{Value, json};

/// Fragments the wider schema patterns accept but `DidUrl` rejects.
const WIDER_THAN_DID_URL: &[&str] = &[
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
        "verification_service_id": "did:web:verify.example",
        "verification_method": verification_method,
        "subject_id": "did:web:bob.example",
        "realm_id": "ak:realm:0196419b-0000-7000-8000-00000000014a",
        "audience": "did:web:realm.example",
        "claim_nonce": "nonce-claim-proof-1",
        "expires_at": "2099-01-01T00:00:00.000Z",
        "signature": "c2ln",
    })
}

fn invite_subject_proof(verification_method: &str) -> Value {
    json!({
        "verification_method": verification_method,
        "alg": "EdDSA",
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
fn invite_claim_binding_proof_rejects_fragments_wider_than_did_url() {
    // `event-payload.schema.json#/$defs/invite_payload/.../binding_proof`
    // fragment class: `[^\s#]+`.
    let accepted = invite_claim_binding_proof(CANONICAL);
    let parsed: InviteClaimBindingProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for wide in WIDER_THAN_DID_URL {
        let value = with_verification_method(invite_claim_binding_proof(CANONICAL), wide);
        assert!(
            serde_json::from_value::<InviteClaimBindingProof>(value).is_err(),
            "InviteClaimBindingProof must reject schema-wider fragment {wide}"
        );
    }
}

#[test]
fn invite_subject_proof_rejects_fragments_wider_than_did_url() {
    // `event-payload.schema.json#/$defs/invite_payload/.../subject_proof`
    // fragment class: `[^\s#]+`.
    let accepted = invite_subject_proof(CANONICAL);
    let parsed: InviteSubjectProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for wide in WIDER_THAN_DID_URL {
        let value = with_verification_method(invite_subject_proof(CANONICAL), wide);
        assert!(
            serde_json::from_value::<InviteSubjectProof>(value).is_err(),
            "InviteSubjectProof must reject schema-wider fragment {wide}"
        );
    }
}

#[test]
fn identity_link_proof_rejects_fragments_wider_than_did_url() {
    // `identity-link.schema.json#/properties/proof` fragment class: `[^\s#]+`.
    // Its description already says "this is a DID URL, not a bare DID".
    let accepted = identity_link_proof(CANONICAL);
    let parsed: IdentityLinkProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for wide in WIDER_THAN_DID_URL {
        let value = with_verification_method(identity_link_proof(CANONICAL), wide);
        assert!(
            serde_json::from_value::<IdentityLinkProof>(value).is_err(),
            "IdentityLinkProof must reject schema-wider fragment {wide}"
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
