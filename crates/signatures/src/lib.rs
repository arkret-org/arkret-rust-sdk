//! Canonical signatures, proof binding and HTTP message signature helpers.

pub mod http_signature;

#[cfg(feature = "protocol")]
mod protocol_api;
#[cfg(feature = "protocol")]
pub use protocol_api::*;
