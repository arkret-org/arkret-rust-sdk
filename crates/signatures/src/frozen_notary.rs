//! Frozen Realm-notary signature verification.

use arkret_wire::{
    Error, Hash, NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor, SealSignature,
};
use p256::ecdsa::signature::Verifier;

/// Verify one Seal signature against the exact predecessor-state descriptor.
///
/// The descriptor is the complete historical key authority. This verifier
/// never resolves a current DID document and never substitutes another key.
pub fn verify_frozen_notary_signature(
    signature: &SealSignature,
    descriptor: &NotarySignerDescriptor,
    canonical_body: &[u8],
    digest_suite: arkret_canonical::DigestSuite,
) -> arkret_wire::Result<()> {
    signature.validate_descriptor_binding(descriptor)?;
    let expected_payload_digest =
        Hash::new(arkret_canonical::digest(digest_suite, canonical_body))?;
    if signature.payload_digest != expected_payload_digest {
        return Err(Error::Protocol(
            "Seal signature payload_digest does not match canonical body".to_owned(),
        ));
    }
    let mut segments = signature.jws.split('.');
    let protected_b64u = segments.next().unwrap_or_default();
    let payload = segments.next().unwrap_or_default();
    let signature_b64u = segments.next().unwrap_or_default();
    if segments.next().is_some() || !payload.is_empty() {
        return Err(Error::Protocol(
            "Seal signature is not a compact detached JWS".to_owned(),
        ));
    }
    let public_key = arkret_canonical::base64url_decode(&descriptor.frozen_public_key_b64u)?;
    let signature_bytes = arkret_canonical::base64url_decode(signature_b64u)?;
    let signing_input = format!(
        "{protected_b64u}.{}",
        arkret_canonical::base64url_encode(canonical_body)
    );

    match (descriptor.key_kind, descriptor.jose_algorithm) {
        (NotaryKeyKind::Ed25519Raw32, NotaryJoseAlgorithm::Ed25519) => {
            let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| {
                Error::Protocol("frozen Ed25519 notary key is not 32 bytes".to_owned())
            })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|error| {
                Error::Protocol(format!("frozen Ed25519 notary key is invalid: {error}"))
            })?;
            let signature =
                ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|error| {
                    Error::Protocol(format!("Seal Ed25519 signature is invalid: {error}"))
                })?;
            key.verify_strict(signing_input.as_bytes(), &signature)
                .map_err(|error| {
                    Error::Protocol(format!(
                        "Seal Ed25519 signature verification failed: {error}"
                    ))
                })
        }
        (NotaryKeyKind::P256Sec1Compressed33, NotaryJoseAlgorithm::ES256) => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key).map_err(|error| {
                Error::Protocol(format!("frozen P-256 notary key is invalid: {error}"))
            })?;
            let signature =
                p256::ecdsa::Signature::from_slice(&signature_bytes).map_err(|error| {
                    Error::Protocol(format!("Seal ES256 signature is invalid: {error}"))
                })?;
            key.verify(signing_input.as_bytes(), &signature)
                .map_err(|error| {
                    Error::Protocol(format!("Seal ES256 signature verification failed: {error}"))
                })
        }
        _ => Err(Error::Protocol(
            "unsupported frozen notary key and algorithm pair".to_owned(),
        )),
    }
}
