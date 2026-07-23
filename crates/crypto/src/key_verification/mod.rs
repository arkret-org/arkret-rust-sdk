//! Stateless key-verification crypto: X25519 key agreement, SAS derivation, and
//! the `accept.commitment` hash commitment (`crypto-media/device-lifecycle.md`
//! §4.5 / §10.3).
//!
//! This module is the reusable, runtime-independent owner for the
//! key-verification cryptographic primitives.

mod commitment;
pub mod key_agreement;

pub use commitment::compute_key_commitment;
pub use key_agreement::*;
