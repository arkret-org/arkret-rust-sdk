//! Event query request body wire model.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use std::collections::BTreeMap;

use arkret_wire::{ActorId, Cursor, RealmId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical QUERY content for `ak.self.events.read.describe.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsDescribeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
}

/// Canonical QUERY content for `ak.self.events.read.frontier.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsFrontierRequestBody {
    pub actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
}

/// Canonical QUERY content shared by `ak.self.seals.read.frontier.v1` and
/// `ak.peer.seals.read.frontier.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealFrontierRequestBody {
    pub realm_id: RealmId,
}

/// Canonical QUERY content for `ak.peer.events.read.frontier.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventsFrontierRequestBody {
    pub realm_id: RealmId,
    /// Actor whose policy-check frontiers are requested. Generic federation
    /// probes omit this field and receive only the replication frontier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<ActorId>,
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
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_nonempty_selectors"
    )]
    pub realm_ids: Vec<RealmId>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_actor_selectors",
        serialize_with = "serialize_actor_selectors"
    )]
    pub actor_ids: Vec<ActorId>,
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

pub(crate) fn deserialize_nonempty_selectors<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(serde::de::Error::custom(
            "a present event selector must not be empty",
        ));
    }
    Ok(values)
}

fn validate_actor_selectors(values: &[ActorId]) -> Result<(), &'static str> {
    if values.len() > 256
        || values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != values.len()
    {
        return Err("actor selectors must contain at most 256 unique identities");
    }
    Ok(())
}

fn deserialize_actor_selectors<'de, D>(deserializer: D) -> Result<Vec<ActorId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = deserialize_nonempty_selectors(deserializer)?;
    validate_actor_selectors(&values).map_err(serde::de::Error::custom)?;
    Ok(values)
}

fn serialize_actor_selectors<S>(values: &[ActorId], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    validate_actor_selectors(values).map_err(serde::ser::Error::custom)?;
    values.serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::{EventsFrontierRequestBody, EventsQueryOrder, SealFrontierRequestBody};

    #[test]
    fn scan_rejects_present_empty_and_duplicate_actor_selectors() {
        let actor = serde_json::json!({
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            }
        });
        for value in [
            serde_json::json!({"actor_ids": []}),
            serde_json::json!({"actor_ids": [actor], "realm_ids": []}),
            serde_json::json!({"actor_ids": [actor.clone(), actor]}),
            serde_json::json!({"actor_ids": [actor], "realm_ids": null}),
        ] {
            assert!(serde_json::from_value::<super::EventsQueryPostRequestBody>(value).is_err());
        }
        let request: super::EventsQueryPostRequestBody =
            serde_json::from_value(serde_json::json!({"actor_ids": [actor]})).unwrap();
        assert!(
            !serde_json::to_value(&request)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("realm_ids")
        );
        let mut duplicate = request.clone();
        duplicate.actor_ids.push(request.actor_ids[0].clone());
        assert!(serde_json::to_value(duplicate).is_err());
    }

    #[test]
    fn scan_rejects_retired_historical_completeness_selector() {
        let mut value = serde_json::json!({
            "realm_ids": [
                "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs"
            ]
        });
        value.as_object_mut().unwrap().insert(
            format!("include_{}", "completeness"),
            serde_json::Value::Bool(true),
        );
        assert!(serde_json::from_value::<super::EventsQueryPostRequestBody>(value).is_err());
    }

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
