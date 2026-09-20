//! Event query request body wire models and the readable row shapes a query
//! answers with.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use std::collections::BTreeMap;

use arkret_wire::{ActorId, Cursor, DidCoreId, EventId, RealmId, WireError};
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

/// Caller-scoped, non-durable view of one authority-committed shared Event.
///
/// The full branch carries the exact independently signed Event and RealmCommit.
/// The withheld branch carries only the Commit plus a minimal disclosure marker
/// and is never reducer input.
pub use arkret_wire::{
    CommittedEventFullView, CommittedEventView, CommittedEventWithheldView, EventDisclosure,
    EventDisclosureStatus,
};
/// Opaque, stable identifier of one frozen Event fanout target.
///
/// This value deliberately cannot carry a service DID: the grammar is the
/// exact non-enumerating token shape published by
/// `EventDeliveryTargetStatus.target_id`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EventDeliveryTargetId(String);

impl EventDeliveryTargetId {
    pub fn new(value: impl Into<String>) -> arkret_wire::Result<Self> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid = (16..=128).contains(&bytes.len())
            && bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && bytes
                .iter()
                .skip(1)
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        if !valid {
            return Err(WireError::Protocol(
                "event delivery target_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EventDeliveryTargetId {
    type Error = WireError;

    fn try_from(value: String) -> arkret_wire::Result<Self> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for EventDeliveryTargetId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Closed lifecycle of one member of an Event's frozen fanout target set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventDeliveryTargetState {
    PendingRoute,
    PendingDelivery,
    Delivered,
    CancelledAuthorityLost,
}

/// Authorized projection of one frozen Event fanout target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDeliveryTargetStatus {
    pub target_id: EventDeliveryTargetId,
    pub status: EventDeliveryTargetState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
}

/// Authenticated query for the durable delivery state of one visible Event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDeliveryStatusRequestBody {
    pub event_id: EventId,
}

const MAX_EVENT_DELIVERY_TARGETS: usize = 1000;

fn validate_event_delivery_targets(
    targets: &[EventDeliveryTargetStatus],
) -> arkret_wire::Result<()> {
    if targets.len() > MAX_EVENT_DELIVERY_TARGETS {
        return Err(WireError::Protocol(
            "event delivery status exceeds 1000 frozen targets".to_owned(),
        ));
    }
    if targets
        .windows(2)
        .any(|rows| rows[0].target_id >= rows[1].target_id)
    {
        return Err(WireError::Protocol(
            "event delivery targets must be strictly sorted by unique target_id".to_owned(),
        ));
    }
    Ok(())
}

fn deserialize_event_delivery_targets<'de, D>(
    deserializer: D,
) -> Result<Vec<EventDeliveryTargetStatus>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let targets = Vec::<EventDeliveryTargetStatus>::deserialize(deserializer)?;
    validate_event_delivery_targets(&targets).map_err(serde::de::Error::custom)?;
    Ok(targets)
}

fn serialize_event_delivery_targets<S>(
    targets: &[EventDeliveryTargetStatus],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    validate_event_delivery_targets(targets).map_err(serde::ser::Error::custom)?;
    targets.serialize(serializer)
}

/// Complete durable frozen fanout target set for one caller-visible Event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDeliveryStatusOutcome {
    pub event_id: EventId,
    #[serde(
        deserialize_with = "deserialize_event_delivery_targets",
        serialize_with = "serialize_event_delivery_targets"
    )]
    pub targets: Vec<EventDeliveryTargetStatus>,
}

impl EventDeliveryStatusOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_event_delivery_targets(&self.targets)
    }
}

#[cfg(test)]
mod event_delivery_status_tests {
    use serde_json::json;

    use super::*;

    const EVENT: &str = "ak:event:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";

    fn outcome_value() -> Value {
        json!({
            "event_id": EVENT,
            "targets": [
                {
                    "target_id": "A_frozen_target_0001",
                    "status": "delivered",
                    "service_id": "ak:did_core:web:station.example"
                },
                {
                    "target_id": "B_frozen_target_0002",
                    "status": "pending_delivery"
                }
            ]
        })
    }

    #[test]
    fn delivery_status_request_and_outcome_round_trip_closed_shapes() {
        let request_value = json!({"event_id": EVENT});
        let request: EventDeliveryStatusRequestBody =
            serde_json::from_value(request_value.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), request_value);

        let outcome: EventDeliveryStatusOutcome = serde_json::from_value(outcome_value()).unwrap();
        outcome.validate().unwrap();
        assert_eq!(serde_json::to_value(outcome).unwrap(), outcome_value());

        for mut open in [json!({"event_id": EVENT}), outcome_value()] {
            open.as_object_mut()
                .unwrap()
                .insert("unregistered_member".to_owned(), json!(true));
            if open.get("targets").is_some() {
                assert!(serde_json::from_value::<EventDeliveryStatusOutcome>(open).is_err());
            } else {
                assert!(serde_json::from_value::<EventDeliveryStatusRequestBody>(open).is_err());
            }
        }
    }

    #[test]
    fn delivery_status_rejects_invalid_opaque_ids_and_noncanonical_sets() {
        let mut invalid_id = outcome_value();
        invalid_id["targets"][0]["target_id"] = json!("ak:did_core:web:station.example");
        assert!(serde_json::from_value::<EventDeliveryStatusOutcome>(invalid_id).is_err());

        let mut unsorted = outcome_value();
        unsorted["targets"].as_array_mut().unwrap().reverse();
        assert!(serde_json::from_value::<EventDeliveryStatusOutcome>(unsorted).is_err());

        let mut duplicate = outcome_value();
        duplicate["targets"][1]["target_id"] = json!("A_frozen_target_0001");
        assert!(serde_json::from_value::<EventDeliveryStatusOutcome>(duplicate).is_err());

        let target = json!({
            "target_id": "A_frozen_target_0001",
            "status": "delivered",
            "unregistered_member": true
        });
        assert!(serde_json::from_value::<EventDeliveryTargetStatus>(target).is_err());
    }

    #[test]
    fn delivery_status_rejects_more_than_the_registered_target_limit() {
        let targets = (0..=MAX_EVENT_DELIVERY_TARGETS)
            .map(|index| {
                json!({
                    "target_id": format!("T{index:015}"),
                    "status": "pending_route"
                })
            })
            .collect::<Vec<_>>();
        assert!(
            serde_json::from_value::<EventDeliveryStatusOutcome>(json!({
                "event_id": EVENT,
                "targets": targets
            }))
            .is_err()
        );
    }
}
