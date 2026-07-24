//! Agent lifecycle schema artifact leaf shapes (public keys, grant
//! snapshots, device metadata, key-authorization state, seal signatures).
//!
//! The `AgentOperations` aggregation enum and `KeyState` stay in
//! the `arkret` umbrella because they bind the agent lifecycle status/scope
//! enums (`AgentStatus`, `AgentPcrRecoveryState`, `AgentPairingMode`) that
//! remain core-resident.

use std::collections::BTreeMap;

use arkret_wire::{Base64UrlString, Did, EventId, GrantId, Hash, NonEmptyString};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/base64url`.
pub type Base64url = String;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/grant_snapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct GrantSnapshot {
    pub grant_id: GrantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<NonEmptyString>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/agent_key_authorization_state`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentKeyAuthorizationState {
    pub key_id: String,
    pub verification_method: String,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/opaque_local_id`.
pub type OpaqueLocalId = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/
/// pending_member_reconciliation_item`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingMemberReconciliationItem {
    pub agent_id: Did,
    pub reason: NonEmptyString,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/public_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PublicKey {
    pub kty: NonEmptyString,
    pub kid: NonEmptyString,
    pub alg: NonEmptyString,
    pub key: Base64UrlString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<Hash>,
}

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/seal_ref`.
pub type SealRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/event_digest`.
pub type EventDigest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/seal.schema.json#/$defs/signature`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub verification_method: Did,
    pub alg: String,
    pub payload_digest: Hash,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    pub jws: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
