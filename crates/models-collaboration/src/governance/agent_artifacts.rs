//! Agent lifecycle schema artifact leaf shapes (public keys, grant
//! snapshots, device metadata, key-authorization state, seal signatures).
//!
//! The `AgentOperations` aggregation enum and `KeyState` stay in
//! the `arkret` umbrella because they bind the agent lifecycle/scope enums
//! (`AgentLifecycleState`, `AgentRuntimeState`, `AgentPairingMode`) that
//! remain core-resident.

use arkret_wire::{
    Base64UrlString, DidCoreId, DidUrl, EventId, GrantId, Hash, NonEmptyString, RealmId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/grant_snapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct GrantSnapshot {
    pub grant_id: GrantId,
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    pub key_id: NonEmptyString,
    pub verification_method: DidUrl,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/
/// pending_member_reconciliation_item`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingMemberReconciliationItem {
    pub agent_id: DidCoreId,
    pub reason: NonEmptyString,
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/public_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PublicKey {
    pub kty: NonEmptyString,
    pub kid: NonEmptyString,
    pub algorithm: NonEmptyString,
    pub key: Base64UrlString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<Hash>,
}

// `seal.schema.json#/$defs/signature` is modelled by
// [`arkret_wire::PayloadSignature`]. A second, incompatible `Signature` struct
// used to live here with `verification_method: DidCoreId`, which rejected every legal
// wire value (the schema's own description says "Bare DID is not valid for
// signatures"). It had zero constructors and zero readers across all
// repositories — it only leaked into the facade through
// `arkret_sdk`'s glob re-export — so it was removed rather than migrated, and
// its `extra: BTreeMap` (schema `additionalProperties: true`) was folded into
// `PayloadSignature`.
