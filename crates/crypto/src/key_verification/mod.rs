//! Stateless key-verification crypto: X25519 key agreement, SAS derivation, and
//! the `accept.commitment` hash commitment (`crypto-media/device-lifecycle.md`
//! §4.5 / §10.3).
//!
//! The typed strand state machine and step envelopes stay in the SDK; only the
//! pure crypto primitives live here so they are reachable without the umbrella
//! client runtime.

mod commitment;
pub mod key_agreement;

pub use commitment::compute_key_commitment;
pub use key_agreement::*;
