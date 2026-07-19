//! RFC 7515 detached Ed25519 JWS surface (shim).
//!
//! The single canonical implementation is split across two behavior crates:
//! `arkret_signatures::jws` owns the resolver-free signer
//! (`sign_jws_ed25519`), and `arkret_identity::jws` owns the
//! DID-resolver-driven verify / replay-window pipeline (`verify_jws_ed25519`,
//! `resolve_ed25519_pubkey`, `JwsVerifyError`, `ReplayWindowError`, …). This
//! shim re-exports both halves so every consumer (inkson, floria, cotest,
//! teabay, soland) keeps reaching the same verifier through `arkret::jws::*`.

pub use arkret_identity::jws::*;
pub use arkret_signatures::jws::*;
