//! Shim: MLS governance proof verification and control-state root derivation
//! moved to `arkret-state` (`arkret_state::mls_governance_proof`) in phase 5-a,
//! next to the Move/Seal state-root machinery it consumes. The proof request /
//! bundle / chunk data shapes it re-exports still originate in
//! `arkret_models_crypto::mls_governance_proof` (re-exported transitively).
//!
//! `verify_mls_governance_proof_bundle` is now generic over the caller's error
//! type; the `arkret-core` facade `Error` bridges `arkret_wire::WireError`, so
//! callers that inject `arkret_core::Result` signature callbacks keep compiling
//! unchanged.

pub use arkret_state::mls_governance_proof::*;
