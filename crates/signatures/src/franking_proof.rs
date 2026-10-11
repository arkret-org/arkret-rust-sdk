//! Production verification for receiving-service franking proofs.
//!
//! The caller resolves `verification_method` at `received_at` and supplies
//! that exact Ed25519 key. This module owns the object-family checks that must
//! not be left to a generic crypto primitive: the method controller projects
//! to `received_by`, and the signature covers the formal flat seven-field
//! transcript.

use arkret_models_collaboration::events_payloads::FrankingProof;
use arkret_wire::{Did, project_did_to_core_id};

use crate::{Error, PublicKeyMaterial, Result};

/// Verify the canonical receiving-service signature and controller binding.
///
/// Successful verification establishes that the supplied key signed this
/// exact proof and belongs to a DID whose stable core is `received_by`. Realm
/// authorization and historical key validity remain caller-owned state checks:
/// the key must be resolved from accepted evidence effective at `received_at`.
pub fn verify_franking_proof_signature(
    proof: &FrankingProof,
    public_key: &PublicKeyMaterial,
) -> Result<()> {
    let controller = proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            Error::Protocol("franking proof verification method has no controller".to_owned())
        })?;
    let projected = project_did_to_core_id(&Did::new(controller)?)?;
    if projected != proof.received_by {
        return Err(Error::Protocol(
            "franking proof verification method controller does not project to received_by"
                .to_owned(),
        ));
    }

    crate::proof::verify_ed25519_raw_transcript_signature(
        &proof.canonical_signing_bytes()?,
        &proof.signature,
        public_key,
    )
    .map_err(|error| Error::Crypto(format!("franking proof signature is invalid: {error}")))
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url_decode;
    use arkret_wire::{DidCoreId, DidUrl};

    use super::*;

    fn fixture() -> serde_json::Value {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
            .expect("franking-proof KAT requires the spec artifacts");
        serde_json::from_str(
            &std::fs::read_to_string(
                artifacts.join("fixtures/franking-proof-transcript-fixture.json"),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn material() -> (FrankingProof, PublicKeyMaterial) {
        let fixture = fixture();
        let proof = serde_json::from_value(fixture["case"]["source_payload"].clone()).unwrap();
        let bytes = base64url_decode(fixture["test_key"]["public_key"].as_str().unwrap()).unwrap();
        (proof, PublicKeyMaterial::Ed25519Raw { bytes })
    }

    #[test]
    fn formal_known_answer_verifies_through_the_production_path() {
        let fixture = fixture();
        let (proof, key) = material();
        assert_eq!(
            proof.canonical_signing_bytes().unwrap(),
            fixture["case"]["transcript_jcs"]
                .as_str()
                .unwrap()
                .as_bytes()
        );
        verify_franking_proof_signature(&proof, &key).unwrap();
    }

    #[test]
    fn controller_mismatch_precedes_crypto_verification() {
        let (mut proof, key) = material();
        proof.received_by = DidCoreId::new("ak:did_core:webvh:z6mkotherprincipalexample").unwrap();
        let error = verify_franking_proof_signature(&proof, &key).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not project to received_by")
        );
    }

    #[test]
    fn same_controller_method_mutation_reaches_crypto_and_fails() {
        let (mut proof, key) = material();
        proof.verification_method =
            DidUrl::new("did:webvh:z6mkfixtureprincipalexample:principal.example#rotated-key")
                .unwrap();
        let error = verify_franking_proof_signature(&proof, &key).unwrap_err();
        assert!(error.to_string().contains("signature is invalid"));
    }

    #[test]
    fn foreign_key_fails_crypto_after_the_controller_binding() {
        let (proof, _) = material();
        let foreign = PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(&[73_u8; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let error = verify_franking_proof_signature(&proof, &foreign).unwrap_err();
        assert!(error.to_string().contains("signature is invalid"));
    }
}
