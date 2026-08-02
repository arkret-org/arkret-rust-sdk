//! Account-operations schema artifact counterparts (identity face).
//!
//! The account-subscribe sync frame containers stay in the `arkret` umbrella
//! (`models/artifacts/account_sync.rs`).

use arkret_wire::{EventId, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summaries`.
pub type DeviceSummaries = Vec<DeviceSummary>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DeviceSummaryStatus {
    Active,
    Revoked,
    Unknown,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summary`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSummary {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<DisplayName>,
    pub status: DeviceSummaryStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
}

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/display_name`.
pub type DisplayName = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_digests`.
pub type HandleClaimDigests = Vec<Hash>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_ref`.
pub type HandleClaimRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/sha256_digest`.
pub type Sha256Digest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/timestamp`.
pub type Timestamp = DateTime<Utc>;
