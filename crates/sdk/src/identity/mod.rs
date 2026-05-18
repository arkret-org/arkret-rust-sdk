//! DID, DID document and handle management.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
pub use contrix_api::identity::{DID_WEB_MAX_DOCUMENT_BYTES, DidDocument};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Did, Error, Result};

pub mod binding;
mod handles;
pub(crate) mod helpers;
mod records;
mod resolvers;
#[cfg(test)]
mod tests;

use helpers::*;

pub use handles::*;
pub use records::*;
pub use resolvers::*;
