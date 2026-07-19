//! Canonical encrypted attachment codec (`ak.blob.stream_aead.v1` /
//! `ak.blob.whole_file_aead.v1`, `media-and-blob.md` §3.2/§3.3).
//!
//! The implementation now lives in [`arkret_crypto::blob_aead`]; this module
//! re-exports it so the historical `arkret::blob_aead::*` /
//! `arkret_sdk::blob_aead::*` paths stay stable.

pub use arkret_crypto::blob_aead::*;
