//! Contact source-service receipt signing inputs and verification.

use arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt;
use arkret_wire::{EventId, Result, WireError};

use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};

/// Canonical bytes signed by the source service for a Contact request
/// acceptance receipt. The non-recursive `receipt_digest` covers `core`; the
/// signature then covers both values.
pub fn contact_request_acceptance_receipt_signing_bytes(
    receipt: &RequestAcceptanceReceipt,
) -> Result<Vec<u8>> {
    receipt.canonical_signing_bytes().map_err(Into::into)
}

/// Verify a pending-incoming Contact receipt after the caller has resolved the
/// issuer service key at `receipt.core.accepted_at`.
///
/// `expected_request_event_ref` must come from the exact request Event, not
/// from the list projection's summary alone. Its digest is encoded in the
/// suite-tagged full-digest EventId.
pub fn verify_contact_request_acceptance_receipt(
    receipt: &RequestAcceptanceReceipt,
    expected_request_event_ref: &EventId,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    receipt.validate_shape()?;
    if &receipt.core.request_event_ref != expected_request_event_ref {
        return Err(WireError::Protocol(
            "Contact request receipt does not bind the exact request Event".to_owned(),
        ));
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &receipt.signature.jws,
            &contact_request_acceptance_receipt_signing_bytes(receipt)?,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: verifying_key.to_bytes().to_vec(),
            },
        )
        .map_err(|_| WireError::Protocol("Contact request receipt signature is invalid".to_owned()))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Base64UrlString, DidUrl};

    use super::*;

    fn fixture() -> serde_json::Value {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
            .expect("Contact KAT requires the spec artifacts");
        serde_json::from_str(
            &std::fs::read_to_string(artifacts.join("fixtures/contact-round-kat.json")).unwrap(),
        )
        .unwrap()
    }
    fn material() -> (RequestAcceptanceReceipt, ed25519_dalek::VerifyingKey) {
        let fixture = fixture();
        let case = fixture["producer_signer_kat"]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "request_0")
            .unwrap();
        let receipt = serde_json::from_value(case["signed_object"].clone()).unwrap();
        let key: [u8; 32] = arkret_canonical::base64url_decode(
            fixture["producer_signer_kat"]["source_public_key_b64u"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        (
            receipt,
            ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap(),
        )
    }
    #[test]
    fn contact_receipt_known_signing_fixture_verifies() {
        let fixture = fixture();
        let case = fixture["producer_signer_kat"]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "request_0")
            .unwrap();
        let (receipt, key) = material();
        assert_eq!(
            contact_request_acceptance_receipt_signing_bytes(&receipt).unwrap(),
            case["canonical_unsigned"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            receipt.computed_receipt_digest().unwrap().as_str(),
            case["expected_signed_digest"].as_str().unwrap()
        );
        verify_contact_request_acceptance_receipt(&receipt, &receipt.core.request_event_ref, &key)
            .unwrap();
    }
    #[test]
    fn contact_current_proof_builder_returns_a_real_signature_over_its_exact_fields() {
        use arkret_models_collaboration::contact_operations::ContactCurrentProof;
        let fixture = fixture();
        let seed: [u8; 32] = arkret_canonical::base64url_decode(
            fixture["producer_signer_kat"]["source_private_seed_b64u"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let (receipt, _) = material();
        let signature_metadata = receipt.signature.clone();
        let current = ContactCurrentProof::sign_with(
            receipt.core.source_checkpoint.clone(),
            receipt.core.issuer_id.clone(),
            receipt.core.peer.clone(),
            false,
            receipt.core.request_event_ref.clone(),
            vec![receipt.core.request_event_ref.clone()],
            1,
            receipt.core.accepted_at + chrono::Duration::minutes(1),
            |bytes| {
                let mut signature = signature_metadata;
                signature.jws = crate::sign_ed25519_detached_jws(&key, bytes).unwrap();
                Ok(signature)
            },
        )
        .unwrap();
        let mut fields = serde_json::to_value(&current).unwrap();
        fields.as_object_mut().unwrap().remove("signature");
        Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &current.signature.jws,
                &arkret_canonical::canonical_json_bytes(&fields).unwrap(),
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            )
            .unwrap();
        let mut changed = current;
        changed.complete_through += 1;
        assert!(
            Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(
                    &changed.signature.jws,
                    &changed.canonical_signing_bytes().unwrap(),
                    &PublicKeyMaterial::Ed25519Raw {
                        bytes: key.verifying_key().to_bytes().to_vec(),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn contact_receipt_rejects_wrong_request_tampering_and_signer() {
        let (receipt, key) = material();
        let wrong_event = EventId::from_event_digest(
            &arkret_wire::Hash::new(arkret_canonical::sha256_digest([44; 32])).unwrap(),
        )
        .unwrap();
        assert!(verify_contact_request_acceptance_receipt(&receipt, &wrong_event, &key).is_err());
        let mut tampered = receipt.clone();
        let last = tampered.signature.jws.pop().unwrap();
        tampered
            .signature
            .jws
            .push(if last == 'A' { 'B' } else { 'A' });
        assert!(
            verify_contact_request_acceptance_receipt(
                &tampered,
                &tampered.core.request_event_ref,
                &key
            )
            .is_err()
        );
        let mut tampered = receipt.clone();
        tampered.signature.verification_method =
            DidUrl::new("did:web:attacker.example#key-1").unwrap();
        assert!(tampered.validate_shape().is_err());
        let mut tampered = receipt.clone();
        tampered.core.producer_signer =
            arkret_models_collaboration::contact_operations::ContactProducerSigner::direct(
                tampered.core.producer_signer.verification_method().clone(),
                Base64UrlString::new(arkret_canonical::base64url_encode([21; 32])).unwrap(),
            )
            .unwrap();
        tampered.receipt_digest = tampered.computed_core_digest().unwrap();
        assert!(
            verify_contact_request_acceptance_receipt(
                &tampered,
                &tampered.core.request_event_ref,
                &key
            )
            .is_err(),
            "recomputing the core digest cannot replace source-bound producer material"
        );
        let mut tampered = receipt;
        tampered.core.producer_signer =
            arkret_models_collaboration::contact_operations::ContactProducerSigner::direct(
                DidUrl::new("did:web:attacker.example#device").unwrap(),
                tampered.core.producer_signer.public_key_b64u().clone(),
            )
            .unwrap();
        tampered.receipt_digest = tampered.computed_core_digest().unwrap();
        assert!(
            verify_contact_request_acceptance_receipt(
                &tampered,
                &tampered.core.request_event_ref,
                &key
            )
            .is_err()
        );
    }
}
