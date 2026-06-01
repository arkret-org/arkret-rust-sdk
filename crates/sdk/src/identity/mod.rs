//! DID, DID document and handle management.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
pub use contrix_contracts::identity::{DID_WEB_MAX_DOCUMENT_BYTES, DidDocument};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Did, Error, Result};

pub mod binding;
mod handles;
pub(crate) mod helpers;
pub mod primary_handle;
mod records;
mod resolvers;
#[cfg(test)]
mod tests;

use helpers::*;

pub use handles::*;
pub use primary_handle::{
    DidDocumentSnapshotResolver, MentionRender, NoHolderPreferenceResolver,
    PrimaryHandleSelectInput, claim_digest, render_mention, select_primary_handle,
};
pub use records::*;
pub use resolvers::*;
