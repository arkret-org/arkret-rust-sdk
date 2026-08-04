//! Detached payload proof wire shape
//! (`event-envelope.schema.json#/$defs/proof`).
//!
//! The proof travels next to a canonical payload digest instead of the
//! payload bytes: identity records (DID key-log entries, service
//! registration receipts), invite locators, and other governed artifacts
//! all reuse this envelope. Signature production and verification live in
//! the behavior crates.

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{Audience, DidUrl, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedPayloadProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}
