//! Shared constructors for Arkret conformance tests.
//!
//! A test helper belongs here when it is protocol-generic — every
//! implementation's suite needs the same construction — and needs no transport.
//! Helpers bound to one HTTP client, or to a single implementation's harness,
//! stay in that implementation.
//!
//! Nothing in this crate is a dependency of any runtime crate.

pub mod negative;

pub use negative::{WireNegativeBody, WireNegativeError, wire_negative_from_sdk};
