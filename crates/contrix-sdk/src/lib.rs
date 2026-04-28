//! Contrix v1 Rust SDK.
//!
//! This crate exposes Contrix protocol concepts directly. The source of truth
//! is signed Events / Operations in append-only Repos; Views are derived
//! projections.

pub mod canonical;
#[cfg(feature = "client")]
pub mod client;
pub mod cursor;
pub mod error;
pub mod hlc;
#[cfg(feature = "mls")]
pub mod mls;
pub mod model;
pub mod service;
pub mod store;

pub use canonical::{canonical_json_bytes, canonical_json_string, sha256_digest};
#[cfg(feature = "client")]
pub use client::{Auth, Client, ClientBuilder};
pub use cursor::{Cursor, SpacePosition, SyncPositions, SyncTracker};
pub use error::{Error, Result};
pub use hlc::{compare_hlc, is_clock_skew_acceptable, parse_hlc, time_until_hlc, validate_hlc_format, HlcComponents, HlcGenerator};
#[cfg(feature = "mls")]
pub use mls::*;
pub use model::*;
pub use service::{ServiceRequirements, ServiceType};
pub use store::{MemoryRepoStore, RepoStore};
