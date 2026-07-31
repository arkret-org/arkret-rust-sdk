//! Negative round-trip coverage for `verification_method` fields whose v1
//! schema pattern is **wider** than the `DidUrl` charset the SDK enforces.
//!
//! `did-usage-and-verification.md` §2.2 requires every `verification_method` to
//! be a DID URL, but the published schemas spell the fragment four different
//! ways: `[A-Za-z0-9._:-]+` (`common-ids#/$defs/did_url`), `[^\s#]+`, `[^\s]+`,
//! and "no pattern at all". `arkret_wire::DidUrl` deliberately implements the
//! strictest of them, so for the fields below the **code is stricter than the
//! schema**.
//!
//! The 2026-07-31 ruling kept the strict behaviour (every official fixture and
//! every value in the nine implementation repositories already satisfies it).
//! These tests pin that decision: they are the complete, per-field list of what
//! would have to change if the spec ever chose to widen the charset instead.
//! See `review/spec-open/` gap G1
//! (`verification-method-fragment-charset-inconsistent`).
//!
//! Companion file for the `arkret-models-collaboration` and `arkret-schema`
//! members of the same list.

use arkret_models_identity::did_continuity::DidContinuitySignatureLink;
use arkret_models_identity::member_identity::MemberIdentityProof;
use arkret_models_identity::service_identity::ServiceWebvhDataIntegrityProof;
use serde_json::{Value, json};

/// Fragments that the wider schema patterns accept but `DidUrl` rejects.
///
/// `#key/1` is legal under `[^\s#]+` and `[^\s]+`; `#键1` is legal under both as
/// well (neither excludes non-ASCII); `#key%201` is legal under `[^\s]+`.
const WIDER_THAN_DID_URL: &[&str] = &[
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

fn did_continuity_link(verification_method: &str) -> Value {
    json!({
        "principal_id": "did:web:alice.example",
        "verification_method": verification_method,
        "algorithm": "Ed25519",
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
fn member_identity_proof_rejects_fragments_wider_than_did_url() {
    // `member-identity.schema.json` fragment class: `[^\s#]+`.
    let accepted = member_identity_proof(CANONICAL);
    let parsed: MemberIdentityProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for wide in WIDER_THAN_DID_URL {
        let value = with_verification_method(
            member_identity_proof(CANONICAL),
            "verification_method",
            wide,
        );
        assert!(
            serde_json::from_value::<MemberIdentityProof>(value).is_err(),
            "MemberIdentityProof must reject schema-wider fragment {wide}"
        );
    }
}

#[test]
fn did_continuity_signature_link_rejects_fragments_wider_than_did_url() {
    // `did-continuity-proof.schema.json` fragment class: `[^\s#]+`.
    let accepted = did_continuity_link(CANONICAL);
    let parsed: DidContinuitySignatureLink = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for wide in WIDER_THAN_DID_URL {
        let value =
            with_verification_method(did_continuity_link(CANONICAL), "verification_method", wide);
        assert!(
            serde_json::from_value::<DidContinuitySignatureLink>(value).is_err(),
            "DidContinuitySignatureLink must reject schema-wider fragment {wide}"
        );
    }
}

#[test]
fn service_webvh_data_integrity_proof_rejects_fragments_wider_than_did_url() {
    // `service-operation-dtos.schema.json#/$defs/ServiceWebvhDataIntegrityProof`
    // fragment class: `[^\s]+` — the widest of the four. Note the wire member is
    // `verificationMethod` (camelCase); the migration does not change that.
    let accepted = service_webvh_proof(CANONICAL);
    let parsed: ServiceWebvhDataIntegrityProof = serde_json::from_value(accepted.clone()).unwrap();
    assert_eq!(parsed.verification_method, CANONICAL);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), accepted);

    for wide in WIDER_THAN_DID_URL {
        let value =
            with_verification_method(service_webvh_proof(CANONICAL), "verificationMethod", wide);
        assert!(
            serde_json::from_value::<ServiceWebvhDataIntegrityProof>(value).is_err(),
            "ServiceWebvhDataIntegrityProof must reject schema-wider fragment {wide}"
        );
    }
}

/// A bare DID is never a verification method, whatever the fragment charset
/// debate settles on (`seal.schema.json#/$defs/signature`: "Bare DID is not
/// valid for signatures").
#[test]
fn bare_did_is_rejected_by_every_migrated_field() {
    const BARE: &str = "did:web:alice.example";
    assert!(
        serde_json::from_value::<MemberIdentityProof>(member_identity_proof(BARE)).is_err(),
        "MemberIdentityProof must reject a bare DID"
    );
    assert!(
        serde_json::from_value::<DidContinuitySignatureLink>(did_continuity_link(BARE)).is_err(),
        "DidContinuitySignatureLink must reject a bare DID"
    );
    assert!(
        serde_json::from_value::<ServiceWebvhDataIntegrityProof>(service_webvh_proof(BARE))
            .is_err(),
        "ServiceWebvhDataIntegrityProof must reject a bare DID"
    );
}
