//! Deterministic fixture key material.
//!
//! Three unrelated schemes were in use: raw byte seeds (`[21u8; 32]`),
//! `seed_from_u64(n)` and `SHA-256(domain ‖ verification_method)`. Only the
//! third binds the key to the identity it signs for, so it is the one this
//! crate exposes; the other two remain reachable through
//! [`seeded_signer_for_seed`] for a repository that still has golden material
//! pinned to a raw seed and cannot recompute it in the same change.

use arkret_signatures::Ed25519PayloadSigner;
use arkret_wire::{Did, DidUrl};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// The signer for a verification method, with the key derived from the method
/// itself.
///
/// Two fixtures that name the same verification method therefore hold the same
/// key without sharing a constant, which is what lets a test producer and a
/// isolated harness agree without either copying the other's seed table.
#[must_use]
pub fn seeded_signer(did: Did, verification_method: DidUrl) -> Ed25519PayloadSigner {
    let seed = development_signing_key_seed(verification_method.as_str());
    Ed25519PayloadSigner::from_did_key_seed(seed, did, verification_method)
}

/// The signer for an explicit raw seed.
///
/// Reach for this only when existing golden material is pinned to a raw seed;
/// new fixtures take [`seeded_signer`] so their key follows their identity.
#[must_use]
pub fn seeded_signer_for_seed(
    seed: [u8; 32],
    did: Did,
    verification_method: DidUrl,
) -> Ed25519PayloadSigner {
    Ed25519PayloadSigner::from_did_key_seed(seed, did, verification_method)
}

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
/// key. This lets isolated test producers share one derivation
/// without copying it into each repository.
pub fn development_verifying_key(verification_method: &str) -> VerifyingKey {
    development_signing_key(verification_method).verifying_key()
}
