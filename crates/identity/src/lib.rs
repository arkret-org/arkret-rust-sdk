//! Arkret v1 DID identity behavior layer.
//!
//! DID resolution (`did:key` / `did:web` / `did:webvh`, composite + caching),
//! handle-claim challenges, DID key-log records with controller proofs, and the
//! DID-resolver-driven detached-JWS verify pipeline. Depends only on the wire /
//! model / signature data crates and the outbound egress classifier; the
//! umbrella `arkret` crate re-exports this surface under `arkret::identity::*`.

mod error;
mod handles;
pub(crate) mod helpers;
pub mod jws;
mod records;
mod resolvers;
pub mod service_identity;
#[cfg(test)]
mod tests;

// Data types the identity behavior operates on, re-exported so the umbrella
// `arkret` crate can surface `arkret::identity::*` unchanged via its shim.
// Internal shared names the migrated modules reach through `use super::*` /
// `use crate::*`, mirroring what the former `arkret::identity` module brought
// into scope for its children.
pub(crate) use std::collections::BTreeMap;

pub use arkret_models_identity::{
    DID_WEB_MAX_DOCUMENT_BYTES, DidDocument, DidKeyLogEntry, DidKeyLogOperation, HandleAttestation,
};
pub(crate) use arkret_wire::{Did, Event, Hash, Proof};
pub(crate) use chrono::{DateTime, Utc};
pub(crate) use error::IdentityError as Error;
pub use error::{IdentityError, Result};
pub use handles::*;
pub(crate) use helpers::*;
/// Public re-export of the `did:webvh` splitter + outbound SSRF egress guard so
/// downstream crates (e.g. starid) reuse the low-level classifier instead of
/// re-implementing address tables (STA-05-001).
pub use helpers::{did_webvh_parts, host_is_safe_for_outbound, ip_is_public};
pub use records::*;
pub use resolvers::*;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use serde_json::Value;
