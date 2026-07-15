//! Pure Rust Arkret v1 canonical encoding and digest primitives.

mod error;

pub mod base64url;
pub mod binding_contexts;
pub mod canonical;
pub mod multibase;
pub mod serde_helpers;

pub use base64url::{
    base64_standard_decode, base64_standard_encode, base64url_decode, base64url_encode,
};
pub use canonical::*;
pub use error::{CanonicalError, Result};
pub use multibase::{
    MULTICODEC_ED25519_PUB, decode_base58btc, decode_ed25519_multibase, decode_multibase_base58btc,
    decode_multicodec_varint, ed25519_pubkey_to_did_key_multibase, encode_base58btc,
    encode_multibase_base58btc,
};
