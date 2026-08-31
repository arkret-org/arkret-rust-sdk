//! Filesystem-backed conformance tooling for an explicit Arkret spec checkout.
//!
//! This crate is intentionally excluded from the SDK's default members and
//! production dependency graph. Runtime crates use generated typed contracts;
//! tests, drift checks, and dedicated conformance tools may load full artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub use arkret_schema::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod artifacts;
mod payloads;

pub use artifacts::*;
pub use payloads::*;
