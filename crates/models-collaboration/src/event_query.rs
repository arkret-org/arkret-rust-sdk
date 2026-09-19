//! Event query request body wire models and the readable row shapes a query
//! answers with.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use std::collections::BTreeMap;

use arkret_wire::{
    ActorId, Cursor, DidCoreId, Event, EventId, EventKind, Hash, RealmId, WireError,
};
use chrono::{DateTime, Utc};
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

/// A readable event item.
///
/// A complete Event envelope is the only reducer input shape.
/// [`RedactedEventView`] and [`ReferenceLockedEventStub`] are
/// projection/completeness evidence for callers that may know the source Event
/// exists but may not receive its full canonical payload bytes.
// Variant declaration order is byte-for-byte the oneOf order of
// service-operation-dtos.schema.json#/$defs/EventReadRow.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum EventReadRow {
    Event(Event),
    Redacted(RedactedEventView),
    ReferenceLocked(ReferenceLockedEventStub),
}

impl EventReadRow {
    /// The complete Event, when this row carries reducer input at all.
    #[must_use]
    pub fn reducer_input(&self) -> Option<&Event> {
        match self {
            Self::Event(event) => Some(event),
            Self::Redacted(_) | Self::ReferenceLocked(_) => None,
        }
    }

    #[must_use]
    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Event(event) => &event.realm_id,
            Self::Redacted(view) => &view.realm_id,
            Self::ReferenceLocked(stub) => &stub.realm_id,
        }
    }
}

impl From<Event> for EventReadRow {
    fn from(event: Event) -> Self {
        Self::Event(event)
    }
}

/// Const-valued discriminator of [`RedactedEventView`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedEventViewKind {
    RedactedEventView,
}

/// Why a projection masked an Event it is still willing to name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventRedactionReason {
    ReferenceLocked,
    HistoryNotVisible,
    PolicyHidden,
    Redacted,
    RetentionPruned,
    Unknown,
}

/// One masked envelope member: `payload`, a dotted `payload.<path>`, `proofs`,
/// or `unsigned`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HiddenEventField(String);

impl HiddenEventField {
    pub fn new(value: impl Into<String>) -> arkret_wire::Result<Self> {
        let value = value.into();
        let valid = matches!(value.as_str(), "payload" | "proofs" | "unsigned")
            || value.strip_prefix("payload.").is_some_and(|path| {
                !path.is_empty()
                    && path.split('.').all(|segment| {
                        !segment.is_empty()
                            && segment.bytes().all(|byte| {
                                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                            })
                    })
            });
        if !valid {
            return Err(WireError::Protocol(
                "hidden event field must be payload, payload.<field path>, proofs, or unsigned"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HiddenEventField {
    type Error = WireError;

    fn try_from(value: String) -> arkret_wire::Result<Self> {
        Self::new(value)
    }
}

impl From<HiddenEventField> for String {
    fn from(value: HiddenEventField) -> Self {
        value.0
    }
}

/// The `uniqueItems` masked-member set of a [`RedactedEventView`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HiddenEventFields(Vec<HiddenEventField>);

impl HiddenEventFields {
    pub fn new(fields: Vec<HiddenEventField>) -> arkret_wire::Result<Self> {
        let unique = fields.iter().collect::<std::collections::BTreeSet<_>>();
        if unique.len() != fields.len() {
            return Err(WireError::Protocol(
                "hidden_fields must not contain duplicates".to_owned(),
            ));
        }
        Ok(Self(fields))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[HiddenEventField] {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<HiddenEventField> {
        self.0
    }
}

impl TryFrom<Vec<HiddenEventField>> for HiddenEventFields {
    type Error = WireError;

    fn try_from(fields: Vec<HiddenEventField>) -> arkret_wire::Result<Self> {
        Self::new(fields)
    }
}

impl<'de> Deserialize<'de> for HiddenEventFields {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = Vec::<HiddenEventField>::deserialize(deserializer)?;
        Self::new(fields).map_err(serde::de::Error::custom)
    }
}

/// The `const false` projection-only marker carried by both masked views.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReducerInputFalse;

impl Serialize for ReducerInputFalse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for ReducerInputFalse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            return Err(serde::de::Error::custom("reducer_input must be false"));
        }
        Ok(Self)
    }
}

/// Projection-only evidence that a named Event exists with some members
/// masked. It MUST NOT be fed into a reducer as Event Envelope input.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/RedactedEventView.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedEventView {
    pub view_kind: RedactedEventViewKind,
    pub event_id: EventId,
    pub kind: EventKind,
    pub realm_id: RealmId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    /// Digest commitment to the canonical payload object before masking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<Hash>,
    pub redaction_reason: EventRedactionReason,
    pub hidden_fields: HiddenEventFields,
    /// Proof that the suite-bearing digest decoded from `event_id` is included
    /// in an Event set or RealmCommit root visible to the caller; it does not
    /// prove historical completeness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<BTreeMap<String, Value>>,
    pub reducer_input: ReducerInputFalse,
}

impl RedactedEventView {
    #[must_use]
    pub fn event_digest(&self) -> Hash {
        self.event_id.event_digest()
    }
}

/// Const-valued discriminator of [`ReferenceLockedEventStub`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceLockedEventStubKind {
    ReferenceLockedEventStub,
}

/// Why a projection would not resolve a referenced Event. Reasons that would
/// reveal target existence collapse to `not_found_or_unauthorized` for
/// unauthorized callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceLockedReasonCode {
    ReferenceLocked,
    HistoryNotVisible,
    PolicyHidden,
    NotFoundOrUnauthorized,
}

/// Projection-only evidence that a reference exists without disclosing its
/// target. It MUST NOT be fed into a reducer as Event Envelope input.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/ReferenceLockedEventStub.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceLockedEventStub {
    pub view_kind: ReferenceLockedEventStubKind,
    /// Present only when the source Event id is already visible to the caller;
    /// omitted when even the id would distinguish target existence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<EventKind>,
    /// The source Realm boundary visible to the caller. Target Realm
    /// identifiers hidden by reference-disclosure policy never appear.
    pub realm_id: RealmId,
    pub reason_code: ReferenceLockedReasonCode,
    /// Non-disclosing proof commitment; it never carries hidden target refs or
    /// target Realm metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<BTreeMap<String, Value>>,
    pub reducer_input: ReducerInputFalse,
}

#[cfg(test)]
mod event_read_row_tests {
    use serde_json::json;

    use super::*;

    const EVENT: &str = "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REALM: &str = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";

    fn redacted_value() -> Value {
        json!({
            "view_kind": "redacted_event_view",
            "event_id": EVENT,
            "kind": "ak.message.create",
            "realm_id": REALM,
            "created_at": "2026-08-15T00:00:00.000Z",
            "payload_digest": format!("sha256:{}", "1".repeat(64)),
            "redaction_reason": "policy_hidden",
            "hidden_fields": ["payload.body", "proofs"],
            "inclusion_proof": {"root": "sha256"},
            "reducer_input": false
        })
    }

    fn reference_locked_value() -> Value {
        json!({
            "view_kind": "reference_locked_event_stub",
            "event_id": EVENT,
            "kind": "ak.message.create",
            "realm_id": REALM,
            "reason_code": "not_found_or_unauthorized",
            "inclusion_proof": {"root": "sha256"},
            "reducer_input": false
        })
    }

    fn assert_rejects_each_omitted_required_member<T>(value: Value, required: &[&str])
    where
        T: for<'de> Deserialize<'de>,
    {
        for member in required {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(*member);
            assert!(
                serde_json::from_value::<T>(missing).is_err(),
                "{member} must be required"
            );
        }
    }

    #[test]
    fn redacted_view_round_trips_and_is_closed() {
        let decoded: RedactedEventView = serde_json::from_value(redacted_value()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), redacted_value());
        assert_eq!(decoded.event_digest(), decoded.event_id.event_digest());

        let mut unknown = redacted_value();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unregistered_member".to_owned(), json!(1));
        assert!(serde_json::from_value::<RedactedEventView>(unknown).is_err());

        assert_rejects_each_omitted_required_member::<RedactedEventView>(
            redacted_value(),
            &[
                "view_kind",
                "event_id",
                "kind",
                "realm_id",
                "redaction_reason",
                "hidden_fields",
                "reducer_input",
            ],
        );
    }

    #[test]
    fn reference_locked_stub_round_trips_and_is_closed() {
        let decoded: ReferenceLockedEventStub =
            serde_json::from_value(reference_locked_value()).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            reference_locked_value()
        );

        let mut unknown = reference_locked_value();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unregistered_member".to_owned(), json!(1));
        assert!(serde_json::from_value::<ReferenceLockedEventStub>(unknown).is_err());

        assert_rejects_each_omitted_required_member::<ReferenceLockedEventStub>(
            reference_locked_value(),
            &["view_kind", "realm_id", "reason_code", "reducer_input"],
        );
    }

    #[test]
    fn masked_views_are_never_reducer_input() {
        for value in [redacted_value(), reference_locked_value()] {
            let mut truthy = value.clone();
            truthy
                .as_object_mut()
                .unwrap()
                .insert("reducer_input".to_owned(), json!(true));
            assert!(serde_json::from_value::<EventReadRow>(truthy).is_err());

            let row: EventReadRow = serde_json::from_value(value).unwrap();
            assert!(row.reducer_input().is_none());
            assert_eq!(row.realm_id().as_str(), REALM);
        }
    }

    #[test]
    fn read_row_keeps_the_masked_branches_apart() {
        assert!(matches!(
            serde_json::from_value::<EventReadRow>(redacted_value()).unwrap(),
            EventReadRow::Redacted(_)
        ));
        assert!(matches!(
            serde_json::from_value::<EventReadRow>(reference_locked_value()).unwrap(),
            EventReadRow::ReferenceLocked(_)
        ));
    }

    #[test]
    fn hidden_fields_are_a_closed_unique_member_set() {
        assert!(HiddenEventField::new("payload").is_ok());
        assert!(HiddenEventField::new("payload.body.text").is_ok());
        assert!(HiddenEventField::new("unsigned").is_ok());
        assert!(HiddenEventField::new("event_id").is_err());
        assert!(HiddenEventField::new("payload.").is_err());
        assert!(HiddenEventField::new("payload.Body").is_err());

        let duplicated = HiddenEventFields::new(vec![
            HiddenEventField::new("proofs").unwrap(),
            HiddenEventField::new("proofs").unwrap(),
        ]);
        assert!(duplicated.is_err());

        let mut value = redacted_value();
        value.as_object_mut().unwrap().insert(
            "hidden_fields".to_owned(),
            json!(["payload.body", "payload.body"]),
        );
        assert!(serde_json::from_value::<RedactedEventView>(value).is_err());
    }
}

/// Result of `ak.self.events.resource.get.v1`. The redacted and
/// reference-locked rows are projection-only evidence and are never reducer
/// input.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/EventView.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventView {
    pub event: EventReadRow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<BTreeMap<String, Value>>,
}

impl EventView {
    /// The complete Event, when this view carries reducer input at all.
    #[must_use]
    pub fn reducer_input(&self) -> Option<&Event> {
        self.event.reducer_input()
    }
}

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

#[cfg(test)]
mod event_view_tests {
    use serde_json::json;

    use super::*;

    fn locked_stub_value() -> Value {
        json!({
            "view_kind": "reference_locked_event_stub",
            "event_id": "ak:event:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
            "realm_id": "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
            "reason_code": "not_found_or_unauthorized",
            "reducer_input": false
        })
    }

    #[test]
    fn event_view_round_trips_and_is_closed() {
        let value = json!({"event": locked_stub_value()});
        let parsed: EventView = serde_json::from_value(value.clone()).expect("closed view");
        assert!(
            parsed.reducer_input().is_none(),
            "a reference-locked row is projection-only evidence"
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("commit".to_owned(), json!({}));
        assert!(serde_json::from_value::<EventView>(unknown).is_err());

        assert!(
            serde_json::from_value::<EventView>(json!({})).is_err(),
            "event must not become optional"
        );
    }
}
