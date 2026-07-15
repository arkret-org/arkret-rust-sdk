//! DID, DID document and handle management.

use std::collections::BTreeMap;

pub use arkret_core::identity::{DID_WEB_MAX_DOCUMENT_BYTES, DidDocument, HandleAttestation};
pub use arkret_core::{DidKeyLogEntry, DidKeyLogOperation};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Did, Error, Result};

pub mod binding;
mod bootstrap;
mod handles;
pub(crate) mod helpers;
pub mod primary_handle;
mod records;
mod resolvers;
#[cfg(test)]
mod tests;

pub use bootstrap::*;
pub use handles::*;
/// Public re-export of the `did:webvh` splitter so downstream crates
/// (e.g. starid) can parse a webvh DID into its parts without depending
/// on the SDK's internal module layout.
pub use helpers::did_webvh_parts;
use helpers::*;
/// Public re-export of the outbound SSRF egress guard (`host_is_safe_for_outbound`)
/// and its IP classifier (`ip_is_public`) so downstream crates (e.g. starid)
/// reuse one canonical private/metadata/CGN/NAT64/link-local blacklist instead
/// of re-implementing it (STA-05-001).
pub use helpers::{host_is_safe_for_outbound, ip_is_public};
pub use primary_handle::{
    DidDocumentSnapshotResolver, MentionRender, NoHolderPreferenceResolver,
    PrimaryHandleSelectInput, SubjectRender, claim_digest, render_mention, render_subject,
    select_primary_handle, select_primary_handle_string,
};
pub use records::*;
pub use resolvers::*;
