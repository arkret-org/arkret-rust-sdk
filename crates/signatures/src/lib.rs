//! Canonical signatures, proof binding and HTTP message signature helpers.

mod development_identity;
pub mod http_signature;

pub use development_identity::{
    development_signing_key, development_signing_key_seed, development_verifying_key,
};

#[cfg(feature = "protocol")]
mod protocol_api;
#[cfg(feature = "protocol")]
pub use protocol_api::*;
