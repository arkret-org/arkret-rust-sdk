//! Deterministic fixture key material.
//!
//! Three unrelated schemes were in use: raw byte seeds (`[21u8; 32]`),
//! `seed_from_u64(n)` and `SHA-256(domain ‖ verification_method)`. Only the
//! third binds the key to the identity it signs for, so it is the one this
//! crate exposes; the other two remain reachable through
//! [`seeded_signer_for_seed`] for a repository that still has golden material
//! pinned to a raw seed and cannot recompute it in the same change.

use arkret_signatures::Ed25519PayloadSigner;
pub use arkret_signatures::{
    development_signing_key, development_signing_key_seed, development_verifying_key,
};
use arkret_wire::{Did, DidUrl};

/// The signer for a verification method, with the key derived from the method
/// itself.
///
/// Two fixtures that name the same verification method therefore hold the same
/// key without sharing a constant, which is what lets a test producer and a
/// development server agree without either copying the other's seed table.
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
