//! Identity wire models retained by `arkret-core`.
//!
//! The DID resolution/operation shapes migrated to
//! `arkret-models-identity` (re-exported below). [`IdentityLogListOutcome`]
//! stays here because it embeds the core-only [`DidKeyLogEntry`].

pub use arkret_models_identity::identity::*;

use super::*;
use crate::DidKeyLogEntry;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLogListOutcome {
    #[serde(default)]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub events: Vec<DidKeyLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}
