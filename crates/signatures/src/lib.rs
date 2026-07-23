//! Canonical signatures, proof binding and HTTP message signature helpers.

mod development_identity;
pub mod http_signature;
#[cfg(feature = "collaboration")]
pub mod media;

// RFC 9421 federation trust-domain transcript fragment. Pure wire-string
// formatting (no crypto/model deps), so it is available without the
// model features alongside the other HTTP message-signature helpers.
pub mod federation;

pub use development_identity::{
    development_signing_key, development_signing_key_seed, development_verifying_key,
};

// Agent key-pairing canonical binding digests. Gated by `collaboration` because
// they validate against the `PublicKey` wire model owned by
// arkret-models-collaboration.
#[cfg(feature = "collaboration")]
pub mod agent;

#[cfg(feature = "keypackages")]
pub mod keypackages;

mod protocol_api;
pub use protocol_api::*;
