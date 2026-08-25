//! Event query request body wire model.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use std::collections::BTreeMap;

use arkret_wire::{Cursor, DidCoreId, RealmId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical QUERY content for `ak.self.events.read.describe`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsDescribeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
}

/// Canonical QUERY content for `ak.peer.events.read.describe`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventsDescribeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
}

/// Canonical QUERY content for `ak.self.events.read.frontier`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsFrontierRequestBody {
    pub actor_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
}

/// Canonical QUERY content shared by `ak.self.seals.read.frontier` and
/// `ak.peer.seals.read.frontier`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealFrontierRequestBody {
    pub realm_id: RealmId,
}

/// Canonical QUERY content for `ak.peer.events.read.frontier`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventsFrontierRequestBody {
    pub realm_id: RealmId,
}

/// Ordering for event query scans.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventsQueryOrder {
    #[default]
    Default,
    Ascending,
    Descending,
}

impl EventsQueryOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Ascending => "ascending",
            Self::Descending => "descending",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsQueryPostRequestBody {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<DidCoreId>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_completeness: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::{EventsFrontierRequestBody, EventsQueryOrder, SealFrontierRequestBody};

    #[test]
    fn query_order_uses_protocol_wire_values() {
        assert_eq!(EventsQueryOrder::Default.as_str(), "default");
        assert_eq!(EventsQueryOrder::Ascending.as_str(), "ascending");
        assert_eq!(EventsQueryOrder::Descending.as_str(), "descending");
        assert_eq!(
            serde_json::to_string(&EventsQueryOrder::Descending).unwrap(),
            "\"descending\""
        );
    }

    #[test]
    fn event_and_seal_frontier_requests_are_disjoint_closed_shapes() {
        assert!(
            serde_json::from_value::<EventsFrontierRequestBody>(serde_json::json!({
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SealFrontierRequestBody>(serde_json::json!({
                "actor_id": "ak:did_core:web:alice.example",
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            }))
            .is_err()
        );
    }
}
