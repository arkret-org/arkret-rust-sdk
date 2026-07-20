//! Canonical signatures, proof binding and HTTP message signature helpers.

mod development_identity;
pub mod http_signature;

// RFC 9421 federation trust-domain transcript fragment. Pure wire-string
// formatting (no crypto/model deps), so it is available without the
// `protocol` feature alongside the other HTTP message-signature helpers.
pub mod federation;

pub use development_identity::{
    development_signing_key, development_signing_key_seed, development_verifying_key,
};

// Agent key-pairing canonical binding digests. Gated by `protocol` because
// they validate against the `PublicKey` wire model owned by
// arkret-models-collaboration.
#[cfg(feature = "protocol")]
pub mod agent;

#[cfg(feature = "protocol")]
mod protocol_api;
#[cfg(feature = "protocol")]
pub use protocol_api::*;
