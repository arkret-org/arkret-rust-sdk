//! Typed `ServiceRegistrationReceipt` proof signing and verification.

use arkret_canonical::multibase::decode_ed25519_multibase;
use arkret_models_identity::service_identity::{ServiceDidDocument, ServiceRegistrationReceipt};
use arkret_wire::PayloadProof;
use ed25519_dalek::SigningKey;

use crate::{Ed25519DetachedJwsVerifier, Error, Result, sign_ed25519_detached_jws};

/// Produce the canonical Provider proof for a typed service-registration
/// receipt. Transcript construction remains owned by the `arkret` umbrella.
pub fn sign_registration_receipt_proof(
    receipt: &ServiceRegistrationReceipt,
    signing_key: &SigningKey,
) -> Result<PayloadProof> {
    receipt.validate_proof_binding()?;
    let mut proof = receipt.proof.clone();
    proof.jws = sign_ed25519_detached_jws(signing_key, &receipt.proof_binding_bytes()?)?;
    Ok(proof)
}

/// Verify a typed service-registration receipt against the resolved Provider
/// DID Document and its authorized assertion method.
pub fn verify_registration_receipt_proof(
    receipt: &ServiceRegistrationReceipt,
    provider_document: &ServiceDidDocument,
) -> Result<()> {
    receipt.validate_proof_binding()?;
    receipt.validate_provider_did(&provider_document.id)?;
    if !provider_document
        .assertion_method
        .iter()
        .any(|method| method == receipt.proof.verification_method.as_str())
    {
        return Err(Error::Protocol(
            "receipt proof verificationMethod is not an authorized Provider assertion method"
                .to_owned(),
        ));
    }
    let method = provider_document
        .verification_method
        .iter()
        .find(|method| method.id == receipt.proof.verification_method.as_str())
        .ok_or_else(|| {
            Error::Protocol(
                "receipt proof verificationMethod is missing from the Provider DID Document"
                    .to_owned(),
            )
        })?;
    if method.controller != provider_document.id {
        return Err(Error::Protocol(
            "receipt proof verification method is not controlled by the Provider DID".to_owned(),
        ));
    }
    let public_key = decode_ed25519_multibase(&method.public_key_multibase).map_err(|error| {
        Error::Protocol(format!("invalid Provider Ed25519 public key: {error}"))
    })?;
    let public_key = crate::proof::PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_vec(),
    };
    Ed25519DetachedJwsVerifier
        .verify_detached_jws(
            &receipt.proof.jws,
            &receipt.proof_binding_bytes()?,
            &public_key,
        )
        .map(|_| ())
        .map_err(|_| {
            Error::Protocol("service registration receipt signature is invalid".to_owned())
        })
}

#[cfg(test)]
mod tests {
    use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
    use arkret_models_identity::service_identity::{
        CanonicalServiceUrl, ServiceDidVerificationMethod, ServiceRegistrationKey,
    };
    use arkret_wire::{
        Did, DidUrl, Hash, PayloadProof, ServiceKind, project_did_to_core_id, proof_kind,
    };

    use super::*;

    fn receipt() -> ServiceRegistrationReceipt {
        let provider_did = Did::new("did:webvh:QmProvider:identity.example:webvh:service").unwrap();
        let provider_service_id = project_did_to_core_id(&provider_did).unwrap();
        let did = Did::new("did:webvh:QmService:identity.example:webvh:auth").unwrap();
        let mut receipt = ServiceRegistrationReceipt {
            registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{}",
                "a".repeat(64)
            ))
            .unwrap(),
            registration_key: ServiceRegistrationKey::new(
                ServiceKind::AuthServer,
                CanonicalServiceUrl::new("https://auth.example/").unwrap(),
            )
            .unwrap(),
            service_id: project_did_to_core_id(&did).unwrap(),
            did,
            version_id: "1-QmVersion".to_owned(),
            log_head_digest: format!("sha256:{}", "a".repeat(64)),
            control_key_digest: format!("sha256:{}", "b".repeat(64)),
            issued_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
            provider_service_id,
            proof: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!("{provider_did}#service-key")).unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "placeholder".to_owned(),
            },
        };
        receipt.registration_receipt_id = receipt.expected_registration_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt
    }

    /// A signed receipt together with the Provider DID Document that
    /// authorizes its `verificationMethod`.
    fn signed_receipt_and_document() -> (ServiceRegistrationReceipt, ServiceDidDocument) {
        let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
        let mut receipt = receipt();
        receipt.proof = sign_registration_receipt_proof(&receipt, &signing_key).unwrap();
        let public_key_multibase =
            ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes());
        let provider_did = Did::new(
            receipt
                .proof
                .verification_method
                .as_str()
                .split_once('#')
                .unwrap()
                .0,
        )
        .unwrap();
        let provider_document = ServiceDidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: provider_did.clone(),
            also_known_as: Vec::new(),
            verification_method: vec![ServiceDidVerificationMethod {
                id: receipt.proof.verification_method.as_str().to_owned(),
                method_type: "Multikey".to_owned(),
                controller: provider_did,
                public_key_multibase,
            }],
            authentication: vec![receipt.proof.verification_method.as_str().to_owned()],
            assertion_method: vec![receipt.proof.verification_method.as_str().to_owned()],
            service: Vec::new(),
        };
        (receipt, provider_document)
    }

    #[test]
    fn receipt_proof_round_trips_and_rejects_tampering() {
        let (mut receipt, provider_document) = signed_receipt_and_document();
        verify_registration_receipt_proof(&receipt, &provider_document).unwrap();

        receipt.version_id.push_str("-tampered");
        assert!(verify_registration_receipt_proof(&receipt, &provider_document).is_err());
    }

    /// `identity-did.md` §3.7 transcript step 4: the signing method must be an
    /// `assertionMethod` of the Provider DID Document. Publishing the same key
    /// for authentication only is not enough.
    #[test]
    fn method_outside_the_provider_assertion_method_set_is_rejected() {
        let (receipt, mut provider_document) = signed_receipt_and_document();
        provider_document.assertion_method.clear();

        assert!(verify_registration_receipt_proof(&receipt, &provider_document).is_err());
    }

    /// The method must be controlled by the Provider DID itself; a document
    /// that delegates it to another controller never authorizes the receipt.
    #[test]
    fn method_controlled_by_another_did_is_rejected() {
        let (receipt, mut provider_document) = signed_receipt_and_document();
        provider_document.verification_method[0].controller =
            Did::new("did:webvh:QmOther:identity.example:webvh:service").unwrap();

        assert!(verify_registration_receipt_proof(&receipt, &provider_document).is_err());
    }
}
