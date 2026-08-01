//! Typed `ServiceRegistrationReceipt` proof signing and verification.

use arkret_canonical::multibase::{
    decode_ed25519_multibase, decode_multibase_base58btc, encode_base58btc,
};
use arkret_models_identity::service_identity::{
    ServiceDidDocument, ServiceRegistrationReceipt, ServiceWebvhDataIntegrityProof,
};
use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Signer, SigningKey, VerifyingKey};

use crate::{Error, Result};

/// Produce the canonical Provider proof for a typed service-registration
/// receipt. Transcript construction remains owned by the `arkret` umbrella.
pub fn sign_registration_receipt_proof(
    receipt: &ServiceRegistrationReceipt,
    signing_key: &SigningKey,
) -> Result<ServiceWebvhDataIntegrityProof> {
    receipt.validate_proof_binding()?;
    let signature = signing_key.sign(&receipt.proof_binding_bytes()?);
    let mut proof = receipt.proof.clone();
    proof.proof_value = format!("z{}", encode_base58btc(signature.to_bytes()));
    Ok(proof)
}

/// Verify a typed service-registration receipt against the resolved Provider
/// DID Document and its authorized assertion method.
pub fn verify_registration_receipt_proof(
    receipt: &ServiceRegistrationReceipt,
    provider_document: &ServiceDidDocument,
) -> Result<()> {
    receipt.validate_proof_binding()?;
    if provider_document.id != receipt.provider_service_id
        || !provider_document
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
    if method.controller != receipt.provider_service_id {
        return Err(Error::Protocol(
            "receipt proof verification method is not controlled by the Provider DID".to_owned(),
        ));
    }
    let public_key = decode_ed25519_multibase(&method.public_key_multibase).map_err(|error| {
        Error::Protocol(format!("invalid Provider Ed25519 public key: {error}"))
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| Error::Protocol("invalid Provider Ed25519 public key".to_owned()))?;
    let signature = decode_multibase_base58btc(&receipt.proof.proof_value)
        .map_err(|error| Error::Protocol(format!("invalid receipt proofValue: {error}")))?;
    if signature.len() != SIGNATURE_LENGTH {
        return Err(Error::Protocol(
            "service registration receipt proofValue must contain a 64-byte Ed25519 signature"
                .to_owned(),
        ));
    }
    let mut signature_bytes = [0_u8; SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(&signature);
    verifying_key
        .verify_strict(
            &receipt.proof_binding_bytes()?,
            &Signature::from_bytes(&signature_bytes),
        )
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
    use arkret_wire::{Did, DidUrl, ServiceKind};

    use super::*;

    fn receipt() -> ServiceRegistrationReceipt {
        let provider_service_id =
            Did::new("did:webvh:QmProvider:identity.example:webvh:service").unwrap();
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
            service_id: Did::new("did:webvh:QmService:identity.example:webvh:auth").unwrap(),
            version_id: "1-QmVersion".to_owned(),
            log_head_digest: format!("sha256:{}", "a".repeat(64)),
            control_key_digest: format!("sha256:{}", "b".repeat(64)),
            issued_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
            provider_service_id: provider_service_id.clone(),
            proof: ServiceWebvhDataIntegrityProof {
                proof_type: "DataIntegrityProof".to_owned(),
                cryptosuite: "eddsa-jcs-2022".to_owned(),
                verification_method: DidUrl::new(format!("{provider_service_id}#service-key"))
                    .unwrap(),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: "z1".to_owned(),
            },
        };
        receipt.registration_receipt_id = receipt.expected_registration_receipt_id().unwrap();
        receipt
    }

    #[test]
    fn receipt_proof_round_trips_and_rejects_tampering() {
        let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
        let mut receipt = receipt();
        receipt.proof = sign_registration_receipt_proof(&receipt, &signing_key).unwrap();
        let public_key_multibase =
            ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes());
        let provider_document = ServiceDidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: receipt.provider_service_id.clone(),
            also_known_as: Vec::new(),
            verification_method: vec![ServiceDidVerificationMethod {
                id: receipt.proof.verification_method.as_str().to_owned(),
                method_type: "Multikey".to_owned(),
                controller: receipt.provider_service_id.clone(),
                public_key_multibase,
            }],
            authentication: vec![receipt.proof.verification_method.as_str().to_owned()],
            assertion_method: vec![receipt.proof.verification_method.as_str().to_owned()],
            service: Vec::new(),
        };
        verify_registration_receipt_proof(&receipt, &provider_document).unwrap();

        receipt.version_id.push_str("-tampered");
        assert!(verify_registration_receipt_proof(&receipt, &provider_document).is_err());
    }
}
