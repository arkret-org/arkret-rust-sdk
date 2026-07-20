//! Event query request body wire model.
//!
//! Migrated from `arkret-core` (`models/event_query.rs`); a shim there
//! re-exports these shapes to preserve the `arkret_core::` path.

use std::collections::BTreeMap;

use arkret_wire::{Cursor, Did, RealmId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventsQueryPostRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<BTreeMap<String, Value>>,
}
