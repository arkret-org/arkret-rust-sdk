//! Agent lifecycle schema artifact leaf shapes (public keys, grant
//! snapshots, device metadata, key-authorization state, payload signatures).
//!
//! `KeyState` stays in the `arkret` umbrella because it binds the agent
//! lifecycle/scope enums (`AgentLifecycleState`, `AgentRuntimeState`,
//! Agent lifecycle types) that remain core-resident.

use arkret_wire::{Base64UrlString, DidUrl, EventId, GrantId, Hash, NonEmptyString, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

include!("generated/agent_artifacts_contracts.rs");
