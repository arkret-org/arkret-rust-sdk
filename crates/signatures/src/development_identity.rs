//! Deterministic local-development signing identities.
//!
//! This is a fixture-key derivation surface, not a relaxed proof profile:
//! callers still produce and verify ordinary Ed25519 `detached_jws` proofs.
//! Services MUST gate its use behind an explicit development-mode setting.

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const DEVELOPMENT_KEY_CONTEXT: &[u8] = b"arkret-sdk:development-signing-key-v1\0";

/// Derive a deterministic Ed25519 seed for a local-development verification
/// method. The verification method is part of the derivation, so distinct
/// fixture methods receive distinct keys.
pub fn development_signing_key_seed(verification_method: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DEVELOPMENT_KEY_CONTEXT);
    hasher.update(verification_method.as_bytes());
    hasher.finalize().into()
}

/// Build the deterministic local-development Ed25519 signing key for a
/// verification method.
pub fn development_signing_key(verification_method: &str) -> SigningKey {
    SigningKey::from_bytes(&development_signing_key_seed(verification_method))
}

/// Build the matching deterministic local-development Ed25519 verification
/// key. This lets test producers and development servers share one derivation
/// without copying it into each repository.
pub fn development_verifying_key(verification_method: &str) -> VerifyingKey {
    development_signing_key(verification_method).verifying_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_keys_are_deterministic_and_method_bound() {
        let alice = "did:web:alice.example#cotest";
        assert_eq!(
            development_signing_key_seed(alice),
            development_signing_key_seed(alice)
        );
        assert_ne!(
            development_verifying_key(alice),
            development_verifying_key("did:web:bob.example#cotest")
        );
    }
}
