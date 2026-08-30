//! Frozen Realm-notary signature verification.

use arkret_wire::{
    Hash, NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor, SealSignature, WireError,
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
    let expected_payload_digest =
        Hash::new(arkret_canonical::digest(digest_suite, canonical_body))?;
    if signature.payload_digest != expected_payload_digest {
        return Err(WireError::Protocol(
            "Seal signature payload_digest does not match canonical body".to_owned(),
        ));
    }
    verify_frozen_notary_detached_jws(signature, descriptor, canonical_body)
}

/// Verify a domain-specific detached JWS against a frozen notary descriptor.
///
/// Unlike [`verify_frozen_notary_signature`], this helper deliberately does
/// not reinterpret `payload_digest` as the digest of `signed_payload`.
/// Protocol objects such as Control Proposal Acks bind their statement digest
/// inside a domain-separated transcript; their structural validators check
/// that binding before this cryptographic verification step.
pub fn verify_frozen_notary_detached_jws(
    signature: &SealSignature,
    descriptor: &NotarySignerDescriptor,
    signed_payload: &[u8],
) -> arkret_wire::Result<()> {
    signature.validate_descriptor_binding(descriptor)?;
    let mut segments = signature.jws.split('.');
    let protected_b64u = segments.next().unwrap_or_default();
    let payload = segments.next().unwrap_or_default();
    let signature_b64u = segments.next().unwrap_or_default();
    if segments.next().is_some() || !payload.is_empty() {
        return Err(WireError::Protocol(
            "Seal signature is not a compact detached JWS".to_owned(),
        ));
    }
    let public_key = arkret_canonical::base64url_decode(&descriptor.frozen_public_key_b64u)?;
    let signature_bytes = arkret_canonical::base64url_decode(signature_b64u)?;
    let signing_input = format!(
        "{protected_b64u}.{}",
        arkret_canonical::base64url_encode(signed_payload)
    );

    match (descriptor.key_kind, descriptor.jose_algorithm) {
        (NotaryKeyKind::Ed25519Raw32, NotaryJoseAlgorithm::Ed25519) => {
            let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| {
                WireError::Protocol("frozen Ed25519 notary key is not 32 bytes".to_owned())
            })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|error| {
                WireError::Protocol(format!("frozen Ed25519 notary key is invalid: {error}"))
            })?;
            let signature =
                ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|error| {
                    WireError::Protocol(format!("Seal Ed25519 signature is invalid: {error}"))
                })?;
            key.verify_strict(signing_input.as_bytes(), &signature)
                .map_err(|error| {
                    WireError::Protocol(format!(
                        "Seal Ed25519 signature verification failed: {error}"
                    ))
                })
        }
        (NotaryKeyKind::P256Sec1Compressed33, NotaryJoseAlgorithm::ES256) => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key).map_err(|error| {
                WireError::Protocol(format!("frozen P-256 notary key is invalid: {error}"))
            })?;
            let signature =
                p256::ecdsa::Signature::from_slice(&signature_bytes).map_err(|error| {
                    WireError::Protocol(format!("Seal ES256 signature is invalid: {error}"))
                })?;
            key.verify(signing_input.as_bytes(), &signature)
                .map_err(|error| {
                    WireError::Protocol(format!(
                        "Seal ES256 signature verification failed: {error}"
                    ))
                })
        }
        _ => Err(WireError::Protocol(
            "unsupported frozen notary key and algorithm pair".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url::base64url_encode;
    use arkret_wire::{ActorId, DidCoreId, DidUrl};
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    use super::*;

    fn descriptor(seed: [u8; 32], method: &DidUrl) -> NotarySignerDescriptor {
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        NotarySignerDescriptor {
            actor_id: ActorId::service(
                DidCoreId::new("ak:did_core:web:replay-kat.example").unwrap(),
            ),
            verification_method: method.clone(),
            key_kind: NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: base64url_encode(public_key),
            frozen_public_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
                public_key,
            ))
            .unwrap(),
        }
    }

    fn signature(seed: [u8; 32], method: &DidUrl, body: &[u8]) -> SealSignature {
        let protected = arkret_canonical::canonical::canonical_json_bytes(&json!({
            "alg": "Ed25519",
            "kid": method,
        }))
        .unwrap();
        let protected = base64url_encode(&protected);
        let signing_input = format!("{protected}.{}", base64url_encode(body));
        let signature = SigningKey::from_bytes(&seed).sign(signing_input.as_bytes());
        SealSignature {
            verification_method: method.clone(),
            payload_digest: Hash::new(arkret_canonical::canonical::sha256_digest(body)).unwrap(),
            jws: format!("{protected}..{}", base64url_encode(signature.to_bytes())),
        }
    }

    #[test]
    fn same_method_current_key_cannot_replace_the_frozen_historical_key() {
        let method = DidUrl::new("did:web:replay-kat.example#notary-key-1").unwrap();
        let historical_seed = [0x11; 32];
        let current_seed = [0x22; 32];
        let historical = descriptor(historical_seed, &method);
        let current = descriptor(current_seed, &method);
        let body = br#"{"realm_id":"historical-replay"}"#;

        verify_frozen_notary_signature(
            &signature(historical_seed, &method, body),
            &historical,
            body,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("historical signature verifies under the frozen descriptor");
        let error = verify_frozen_notary_signature(
            &signature(current_seed, &method, body),
            &historical,
            body,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect_err("same method id must not substitute current key bytes");
        assert_ne!(
            historical.frozen_public_key_b64u,
            current.frozen_public_key_b64u
        );
        assert!(error.to_string().contains("signature verification failed"));
    }

    #[test]
    fn domain_transcript_verification_does_not_reinterpret_payload_digest() {
        let method = DidUrl::new("did:web:replay-kat.example#notary-key-1").unwrap();
        let seed = [0x33; 32];
        let descriptor = descriptor(seed, &method);
        let transcript = br#"{\"context\":\"ak.control_proposal_authority_ack_proof.v1\"}"#;
        let mut signature = signature(seed, &method, transcript);
        signature.payload_digest = Hash::new(arkret_canonical::canonical::sha256_digest(
            b"authority-ack-body",
        ))
        .unwrap();

        verify_frozen_notary_detached_jws(&signature, &descriptor, transcript)
            .expect("domain transcript signature must verify under the frozen descriptor");
        let error = verify_frozen_notary_signature(
            &signature,
            &descriptor,
            transcript,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect_err("the Seal verifier must retain its direct body-digest contract");
        assert!(error.to_string().contains("payload_digest"));
    }
}
