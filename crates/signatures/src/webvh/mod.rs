//! Shared `did:webvh` builders.
//!
//! The inception builder mints a fresh embedded `did:webvh` for soland's
//! protocol identity provider. It owns only the pure build + cryptography path
//! (keygen, SCID derivation, eddsa-jcs-2022 proof); HTTP submission stays with
//! the caller so clients (sodmin / yougen) and servers (soland / coauth) share
//! one byte-for-byte implementation.

pub mod inception;

pub use inception::{
    InceptionInput, PreparedInception, SubmittedInception, SuppliedInceptionInput,
    WebvhInceptionError, prepare_inception, prepare_supplied_inception,
};
