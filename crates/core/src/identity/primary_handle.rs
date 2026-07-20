//! R3.2 (arkret-spec @ b56cab1) — §3.2.1 primary handle selection,
//! `claim_digest(c)`, and §3.8.2 mention rendering.
//!
//! The authoritative, wasm-safe implementation now lives in
//! `arkret-models-identity` (`arkret_models_identity::primary_handle`) —
//! its only inputs are the identity-domain handle wire shapes plus
//! `arkret-wire` / `arkret-canonical` primitives, so it belongs in the
//! identity data crate. Core re-exports the symbols here so the
//! `arkret_core::identity::primary_handle::*` (and `arkret::identity::*`)
//! API surface stays unchanged for existing consumers.

pub use arkret_models_identity::primary_handle::*;
