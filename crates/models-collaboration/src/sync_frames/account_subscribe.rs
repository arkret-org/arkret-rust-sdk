//! Account-aggregate subscription frames.
//!
//! The account cursor orders delivery of aggregate frames only. Durable Realm,
//! Circle, and Sidecar data remains in independent governance-authority commit
//! streams; each timeline item retains its own `CommitStreamRef` coordinate.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::account::AccountDataRow;
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventView, Cursor, DidCoreId, Event, EventId,
    Hash, RealmId, Result, SchemaId, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::account_subscribe_projections::AgentRuntimeApprovalNotificationData;
use crate::device_messages::RecipientDelivery;
use crate::events_payloads::account_data::parse_agent_draft_account_data_key;
use crate::events_payloads::agent::{AgentActionTarget, AgentDraftContentHandoff};
use crate::objects::read_receipts::{NotificationIdentity, OrdinaryProjectionContent};
use crate::sync_frames::account_sync::{
    AccountSubscribeRealmSummary, AccountSubscribeUnreadCounts, RealmStreamWindow,
    StateAtWindowStart,
};
use crate::sync_frames::current_results::{AccountCurrentCoverage, AccountCurrentView};
use crate::sync_frames::demand_sync::{
    AccountBaselineSegment, RealmDetailUnavailable, RealmInvalidation, RealmListChanges,
    RealmListPage,
};

pub const ACCOUNT_SUBSCRIBE_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const ACCOUNT_SUBSCRIBE_MAX_WIRE_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const ACCOUNT_SUBSCRIBE_MAX_ROUND_BYTES: usize = 16 * 1024 * 1024;
pub const ACCOUNT_SUBSCRIBE_MAX_ROUND_FRAMES: usize = 16;
pub const DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 5_000;
pub const MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 60_000;

fn protocol_error(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

fn validate_cursor(value: &str) -> Result<()> {
    let tail = value
        .strip_prefix("ak:cursor:")
        .ok_or_else(|| protocol_error("invalid account stream cursor prefix"))?;
    if tail.is_empty()
        || value.len() > 2048
        || !tail
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(protocol_error("invalid bounded account stream cursor"));
    }
    Ok(())
}

fn bounded_unique<T: Ord>(values: &[T], maximum: usize, field: &str) -> Result<()> {
    if values.len() > maximum || values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(protocol_error(format!(
            "{field} exceeds its bound or contains duplicates"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AccountFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_list: Option<RealmListRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_filter: Option<bool>,
}

impl SyncRequestBody {
    pub fn validate(&self) -> Result<()> {
        if let Some(after) = &self.after {
            validate_cursor(after)?;
        }
        if self.replace_filter == Some(true) && (self.after.is_none() || self.filter.is_none()) {
            return Err(protocol_error(
                "replace_filter requires after and an explicit filter",
            ));
        }
        if let Some(filter) = &self.filter {
            filter.validate()?;
        }
        if let Some(realm_list) = &self.realm_list {
            realm_list.validate()?;
        }
        Ok(())
    }
}

/// The Account subscribe filter,
/// `account-subscribe-frame.schema.json#/$defs/account_filter`.
///
/// Field declaration order is byte-for-byte the schema `properties` order.
/// `window_limit` is the per-visible-stream item ceiling of a stream window,
/// never a per-Realm budget. `stream_refs` optionally selects the window's
/// stream set; every entry must belong to a Realm named in `realm_ids`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountFilter {
    #[serde(
        default,
        deserialize_with = "present_member",
        skip_serializing_if = "Option::is_none"
    )]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(
        default,
        deserialize_with = "present_member",
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_refs: Option<Vec<CommitStreamRef>>,
    #[serde(
        default,
        deserialize_with = "present_member",
        skip_serializing_if = "Option::is_none"
    )]
    pub window_limit: Option<u32>,
    #[serde(
        default,
        deserialize_with = "present_member",
        skip_serializing_if = "Option::is_none"
    )]
    pub lazy_load_members: Option<bool>,
    #[serde(
        default,
        deserialize_with = "present_member",
        skip_serializing_if = "Option::is_none"
    )]
    pub include_redundant_members: Option<bool>,
}

/// A member that is present must carry a value of its type: `null` is not an
/// absent member, and the schema admits no `null` for any filter member.
fn present_member<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl AccountFilter {
    pub fn validate(&self) -> Result<()> {
        bounded_unique(
            self.realm_ids.as_deref().unwrap_or_default(),
            16,
            "filter.realm_ids",
        )?;
        if let Some(stream_refs) = &self.stream_refs {
            bounded_unique(stream_refs, 64, "filter.stream_refs")?;
            let realms = self.realm_ids.as_deref().unwrap_or_default();
            if stream_refs
                .iter()
                .any(|stream_ref| !realms.contains(stream_ref.realm_id()))
            {
                return Err(protocol_error(
                    "filter.stream_refs names a Realm absent from filter.realm_ids",
                ));
            }
        }
        if self.window_limit.is_some_and(|limit| limit > 100) {
            return Err(protocol_error("filter.window_limit must be <= 100"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmListRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl RealmListRequest {
    pub fn validate(&self) -> Result<()> {
        if let Some(after) = &self.after {
            validate_cursor(after.as_str())?;
        }
        if self.limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
            return Err(protocol_error("Realm list limit must be 1..=100"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeFrame {
    pub kind: AccountSubscribeFrameKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<AccountSubscribeRealms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_device: Option<RecipientDeliveryContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_lists: Option<AccountSubscribeDeviceListChanges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<AccountDataContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_draft_pending_intents: Option<AgentDraftPendingIntentContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<NotificationContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_list: Option<RealmListPage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_list_changes: Option<RealmListChanges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<AccountBaselineSegment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_invalidations: Option<Vec<RealmInvalidation>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AccountSubscribeFrameKind {
    Delta,
    CatchupComplete,
    Checkpoint,
    Heartbeat,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AccountStreamInterrupt {
    Dropped {
        cursor: String,
        reconnect_after_ms: Option<u64>,
    },
    ResyncRequired {
        reconnect_after_ms: Option<u64>,
    },
    Unauthorized,
}

impl AccountSubscribeFrame {
    pub const SCHEMA: &'static str = SchemaId::ACCOUNT_SUBSCRIBE_FRAME_V1;

    pub fn from_ndjson_line(line: &str) -> Result<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if line.len() > ACCOUNT_SUBSCRIBE_MAX_WIRE_FRAME_BYTES {
            return Err(protocol_error("account frame exceeds its wire byte limit"));
        }
        let frame: Self = canonical::from_canonical_json_str(trimmed)?;
        frame.validate()?;
        Ok(Some(frame))
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(cursor) = &self.cursor {
            validate_cursor(cursor)?;
        }
        if canonical::canonical_json_bytes(self)?.len() > ACCOUNT_SUBSCRIBE_MAX_FRAME_BYTES {
            return Err(protocol_error(
                "account frame exceeds its canonical byte limit",
            ));
        }
        if self.reconnect_after_ms == Some(0) {
            return Err(protocol_error("reconnect_after_ms must be positive"));
        }
        if let Some(realms) = &self.realms {
            realms.validate()?;
        }
        if let Some(devices) = &self.device_lists {
            devices.validate()?;
        }
        if let Some(account_data) = &self.account_data {
            account_data.validate()?;
        }
        if let Some(baseline) = &self.baseline {
            baseline.validate()?;
        }
        if let Some(pending_intents) = &self.agent_draft_pending_intents {
            pending_intents.validate()?;
            let channel =
                crate::sync_frames::demand_sync::AccountBaselineChannel::AgentDraftPendingIntents;
            match pending_intents {
                AgentDraftPendingIntentContainer::Delta { .. } => {
                    if self.baseline.as_ref().is_some_and(|baseline| {
                        baseline.channels.contains(&channel)
                            || baseline.completed_channels.contains(&channel)
                    }) {
                        return Err(protocol_error(
                            "pending-intent delta cannot be declared as a baseline channel",
                        ));
                    }
                }
                AgentDraftPendingIntentContainer::Baseline {
                    next_page_offset, ..
                } => {
                    let baseline = self.baseline.as_ref().ok_or_else(|| {
                        protocol_error(
                            "pending-intent baseline requires an account baseline segment",
                        )
                    })?;
                    if !baseline.channels.contains(&channel) {
                        return Err(protocol_error(
                            "pending-intent baseline must name its account baseline channel",
                        ));
                    }
                    if next_page_offset.is_some() && baseline.completed_channels.contains(&channel)
                    {
                        return Err(protocol_error(
                            "pending-intent baseline may complete only on its terminal page",
                        ));
                    }
                }
            }
        } else if self.baseline.as_ref().is_some_and(|baseline| {
            let channel =
                crate::sync_frames::demand_sync::AccountBaselineChannel::AgentDraftPendingIntents;
            baseline.channels.contains(&channel) || baseline.completed_channels.contains(&channel)
        }) {
            return Err(protocol_error(
                "pending-intent baseline channel requires its private container",
            ));
        }
        if self
            .notifications
            .as_ref()
            .is_some_and(|value| value.items.len() > 100)
        {
            return Err(protocol_error("account notifications exceed 100 items"));
        }
        let has_data = self.realms.is_some()
            || self.to_device.is_some()
            || self.device_lists.is_some()
            || self.account_data.is_some()
            || self.agent_draft_pending_intents.is_some()
            || self.notifications.is_some()
            || self.partial.is_some()
            || self.priority.is_some()
            || self.realm_list.is_some()
            || self.realm_list_changes.is_some()
            || self.baseline.is_some()
            || self.realm_invalidations.is_some();
        let valid = match self.kind {
            AccountSubscribeFrameKind::Delta => {
                self.cursor.is_some() && self.reconnect_after_ms.is_none()
            }
            AccountSubscribeFrameKind::CatchupComplete | AccountSubscribeFrameKind::Checkpoint => {
                self.cursor.is_some() && !has_data && self.reconnect_after_ms.is_none()
            }
            AccountSubscribeFrameKind::Dropped => self.cursor.is_some() && !has_data,
            AccountSubscribeFrameKind::Heartbeat | AccountSubscribeFrameKind::Unauthorized => {
                self.cursor.is_none() && !has_data && self.reconnect_after_ms.is_none()
            }
            AccountSubscribeFrameKind::ResyncRequired => self.cursor.is_none() && !has_data,
        };
        if !valid {
            return Err(protocol_error(
                "invalid fields for account subscribe frame kind",
            ));
        }
        Ok(())
    }

    pub fn requires_resubscribe(&self) -> bool {
        matches!(
            self.kind,
            AccountSubscribeFrameKind::Dropped | AccountSubscribeFrameKind::ResyncRequired
        )
    }

    pub fn reconnect_after_ms(&self) -> Option<u64> {
        self.reconnect_after_ms
    }

    pub fn interrupt(&self) -> Result<Option<AccountStreamInterrupt>> {
        Ok(match self.kind {
            AccountSubscribeFrameKind::Dropped => Some(AccountStreamInterrupt::Dropped {
                cursor: self
                    .cursor
                    .clone()
                    .ok_or_else(|| protocol_error("stream trace dropped_missing_cursor"))?,
                reconnect_after_ms: self.reconnect_after_ms,
            }),
            AccountSubscribeFrameKind::ResyncRequired => {
                Some(AccountStreamInterrupt::ResyncRequired {
                    reconnect_after_ms: self.reconnect_after_ms,
                })
            }
            AccountSubscribeFrameKind::Unauthorized => Some(AccountStreamInterrupt::Unauthorized),
            _ => None,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountSubscribeRealms {
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub entries: BTreeMap<String, RealmSyncEntry>,
}

impl AccountSubscribeRealms {
    fn validate(&self) -> Result<()> {
        if self.entries.len() > 16 {
            return Err(protocol_error("account frame exceeds 16 Realm details"));
        }
        for (realm, entry) in &self.entries {
            RealmId::new(realm.clone())?;
            entry.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<RealmStreamWindow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_limited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_snapshot_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_at_window_start: Option<StateAtWindowStart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<AccountCurrentView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<AccountSubscribeRealmSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_roster: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_notifications: Option<AccountSubscribeUnreadCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_states: Option<Vec<RealmSyncEventState>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<RealmDetailBaseline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<RealmDetailUnavailable>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_events: Option<Vec<CommittedEventView>>,
}

impl RealmSyncEntry {
    fn validate(&self) -> Result<()> {
        if let Some(streams) = &self.streams {
            if streams.len() > 64 {
                return Err(protocol_error("Realm detail exceeds 64 stream windows"));
            }
            let mut previous: Option<Vec<u8>> = None;
            let mut seen = BTreeSet::new();
            for stream in streams {
                stream.validate()?;
                let key = canonical::canonical_json_bytes(&stream.stream_ref)?;
                if !seen.insert(key.clone()) {
                    return Err(protocol_error("Realm detail repeats a stream window"));
                }
                if previous.as_ref().is_some_and(|earlier| *earlier >= key) {
                    return Err(protocol_error(
                        "Realm stream windows are not sorted by canonical stream_ref bytes",
                    ));
                }
                previous = Some(key);
            }
        }
        if let Some(cursor) = &self.window_snapshot_cursor {
            validate_cursor(cursor)?;
            if self.streams.is_none() {
                return Err(protocol_error(
                    "window_snapshot_cursor requires stream windows",
                ));
            }
        }
        if let Some(state_at_window_start) = &self.state_at_window_start {
            state_at_window_start.validate()?;
        }
        if let Some(current) = &self.current {
            current.validate()?;
        }
        if let Some(summary) = &self.summary {
            summary.validate()?;
        }
        if let Some(event_states) = &self.event_states {
            validate_event_states(event_states)?;
        }
        if let Some(baseline) = &self.baseline {
            baseline.validate()?;
        }
        if let Some(events) = &self.committed_events {
            if events.len() > 100 {
                return Err(protocol_error("Realm detail exceeds 100 committed Events"));
            }
            for event in events {
                event.validate_shape()?;
            }
        }
        // `unavailable` is exclusive with every projection member: a failure
        // and a partial answer for one Realm cannot both be true.
        if self.unavailable.is_some()
            && (self.streams.is_some()
                || self.streams_limited.is_some()
                || self.window_snapshot_cursor.is_some()
                || self.state_at_window_start.is_some()
                || self.current.is_some()
                || self.account_data.is_some()
                || self.summary.is_some()
                || self.member_roster.is_some()
                || self.unread_notifications.is_some()
                || self.event_states.is_some()
                || self.baseline.is_some()
                || self.committed_events.is_some())
        {
            return Err(protocol_error(
                "unavailable Realm detail cannot carry projection data",
            ));
        }
        Ok(())
    }
}

/// Protocol state of one reducer-input Event carried by a Realm detail entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmSyncEventStateKind {
    DataLocal,
    DataObserved,
    ControlPending,
    ControlCommitted,
    FailedPrecondition,
    FailedPlane,
    RejectedCommit,
    ForkQuarantine,
}

/// One `(event_id, event_state)` protocol-state view.
///
/// This is per-Event state, not ordering: ordinary current-value concurrency
/// is resolved by the fixed `(depth, EventId)` order, never by anything here.
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_sync_entry/properties/event_states/items`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSyncEventState {
    pub event_id: EventId,
    pub event_state: RealmSyncEventStateKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_state_reason_code: Option<String>,
}

fn validate_event_states(states: &[RealmSyncEventState]) -> Result<()> {
    if states.len() > 100 {
        return Err(protocol_error("Realm detail event_states exceed 100 rows"));
    }
    let mut seen = BTreeSet::new();
    for state in states {
        if !seen.insert(state.event_id.as_str()) {
            return Err(protocol_error("Realm detail event_states repeat an Event"));
        }
    }
    Ok(())
}

/// Per-Realm detail baseline carried by one [`RealmSyncEntry`].
///
/// `snapshot_cursor` identifies the frozen baseline generation and is repeated
/// identically in every segment of it; it is opaque, never an ordered token,
/// and never reused as the account `after` parameter. `cut_revision` is the
/// committed revision the cut was taken at. `complete` reports delivery of this
/// Realm's baseline only: it is independent of the account-level baseline and
/// proves neither authentication, decryption, nor any read permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `account-subscribe-frame.schema.json#/$defs/realm_detail_baseline`.
pub struct RealmDetailBaseline {
    pub snapshot_cursor: String,
    pub cut_revision: u64,
    pub coverage: AccountCurrentCoverage,
    pub complete: bool,
}

impl RealmDetailBaseline {
    /// The baseline's own invariants: a well-formed opaque cursor and coverage
    /// that answers each stream once.
    pub fn validate(&self) -> Result<()> {
        validate_cursor(&self.snapshot_cursor)?;
        self.coverage.validate()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventContainer {
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RecipientDeliveryContainer {
    #[serde(default)]
    pub deliveries: Vec<RecipientDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod open_container_tests {
    use serde_json::json;

    use super::{EventContainer, RecipientDeliveryContainer};

    #[test]
    fn account_subscribe_open_containers_accept_extensions_without_re_emitting_them() {
        let events: EventContainer = serde_json::from_value(json!({
            "events": [],
            "x_future_delivery_hint": {"enabled": true}
        }))
        .unwrap();
        assert!(events.events.is_empty());
        assert_eq!(serde_json::to_value(events).unwrap(), json!({"events": []}));

        let messages: RecipientDeliveryContainer = serde_json::from_value(json!({
            "deliveries": [],
            "limited": false,
            "x_future_queue_hint": 1
        }))
        .unwrap();
        assert!(messages.deliveries.is_empty());
        assert_eq!(
            serde_json::to_value(messages).unwrap(),
            json!({"deliveries": [], "limited": false})
        );

        assert!(serde_json::from_value::<EventContainer>(json!({"events": false})).is_err());
        assert!(
            serde_json::from_value::<RecipientDeliveryContainer>(json!({"deliveries": false}))
                .is_err()
        );
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSubscribeDeviceListChanges {
    #[serde(default)]
    pub changed_ids: Vec<ActorId>,
    #[serde(default)]
    pub left_ids: Vec<ActorId>,
}

impl AccountSubscribeDeviceListChanges {
    fn validate(&self) -> Result<()> {
        bounded_unique(&self.changed_ids, 100, "device_lists.changed_ids")?;
        bounded_unique(&self.left_ids, 100, "device_lists.left_ids")
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDataContainer {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub station_cas: Option<StationCasAccountDataContainer>,
}

impl AccountDataContainer {
    fn validate(&self) -> Result<()> {
        if self.events.len() > 100 {
            return Err(protocol_error("Account Data exceeds 100 Events"));
        }
        if let Some(station_cas) = &self.station_cas {
            station_cas.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationCasAccountDataContainer {
    #[serde(default)]
    pub upserts: Vec<AccountDataRow>,
    #[serde(default)]
    pub removals: Vec<StationCasAccountDataRemoval>,
}

impl StationCasAccountDataContainer {
    fn validate(&self) -> Result<()> {
        if self.upserts.len() > 100 || self.removals.len() > 100 {
            return Err(protocol_error("Station-CAS data exceeds 100 items"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationCasAccountDataRemoval {
    pub account_data_key: String,
    pub revision: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const AGENT_DRAFT_PENDING_INTENT_MAX_ITEMS: usize = 100;
const AGENT_DRAFT_PENDING_INTENT_MAX_UPSERT_BYTES: usize = 1024 * 1024;

/// Stable key of one controller-holder-private Agent draft pending row.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentKey {
    pub controller_account_id: AccountId,
    pub agent_id: DidCoreId,
    pub draft_id: String,
}

/// Exact schema discriminator retained by both live and terminal rows.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub enum AgentDraftPendingIntentSchema {
    #[default]
    #[serde(rename = "ak.schema.agent_draft_pending_intent.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub enum AgentDraftPendingIntentAvailableState {
    #[default]
    #[serde(rename = "available")]
    Available,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub enum AgentDraftPendingIntentConsumedState {
    #[default]
    #[serde(rename = "consumed")]
    Consumed,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub enum AgentDraftPendingIntentExpiredState {
    #[default]
    #[serde(rename = "expired")]
    Expired,
}

/// Metadata proving the unique revision-1 Account Data consumption.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentConsumption {
    pub account_data_set_event_id: EventId,
    pub account_data_key: String,
    pub accepted_revision: AgentDraftPendingIntentAcceptedRevision,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub consumed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AgentDraftPendingIntentAcceptedRevision;

impl Serialize for AgentDraftPendingIntentAcceptedRevision {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for AgentDraftPendingIntentAcceptedRevision {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let revision = u8::deserialize(deserializer)?;
        if revision == 1 {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "pending-intent accepted_revision must be exactly 1",
            ))
        }
    }
}

/// Live pending row. Ciphertext exists only in this `available` branch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentLive {
    pub schema: AgentDraftPendingIntentSchema,
    pub controller_account_id: AccountId,
    pub agent_id: DidCoreId,
    pub draft_id: String,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub content_digest: Hash,
    pub content_handoff: AgentDraftContentHandoff,
    pub canonical_event_digest: Hash,
    pub accepted_event_id: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub state: AgentDraftPendingIntentAvailableState,
}

/// Consumed terminal row. Its closed shape cannot carry ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentConsumed {
    pub schema: AgentDraftPendingIntentSchema,
    pub controller_account_id: AccountId,
    pub agent_id: DidCoreId,
    pub draft_id: String,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub content_digest: Hash,
    pub canonical_event_digest: Hash,
    pub accepted_event_id: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub state: AgentDraftPendingIntentConsumedState,
    pub consumption: AgentDraftPendingIntentConsumption,
}

/// Expired terminal row. Its closed shape cannot carry ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentExpired {
    pub schema: AgentDraftPendingIntentSchema,
    pub controller_account_id: AccountId,
    pub agent_id: DidCoreId,
    pub draft_id: String,
    pub proposed_action: String,
    pub target: AgentActionTarget,
    pub content_digest: Hash,
    pub canonical_event_digest: Hash,
    pub accepted_event_id: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub state: AgentDraftPendingIntentExpiredState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expired_at: DateTime<Utc>,
}

/// Closed terminal-redacted consumed | expired union.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentDraftPendingIntentTerminalRedacted {
    Consumed(AgentDraftPendingIntentConsumed),
    Expired(AgentDraftPendingIntentExpired),
}

/// Closed live | terminal-redacted pending-intent value.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentDraftPendingIntent {
    Live(AgentDraftPendingIntentLive),
    TerminalRedacted(AgentDraftPendingIntentTerminalRedacted),
}

/// Consumed removal tombstone retaining the exact terminal outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentConsumedRemoval {
    pub key: AgentDraftPendingIntentKey,
    pub accepted_event_id: EventId,
    pub canonical_event_digest: Hash,
    pub content_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub state: AgentDraftPendingIntentConsumedState,
    pub consumption: AgentDraftPendingIntentConsumption,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub removed_at: DateTime<Utc>,
}

/// Expired removal tombstone retaining the exact terminal outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentExpiredRemoval {
    pub key: AgentDraftPendingIntentKey,
    pub accepted_event_id: EventId,
    pub canonical_event_digest: Hash,
    pub content_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub state: AgentDraftPendingIntentExpiredState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expired_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub removed_at: DateTime<Utc>,
}

/// Closed consumed | expired removal union.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentDraftPendingIntentRemoval {
    Consumed(AgentDraftPendingIntentConsumedRemoval),
    Expired(AgentDraftPendingIntentExpiredRemoval),
}

/// One ordered upsert or removal on the private pending-intent projection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AgentDraftPendingIntentChange {
    Upsert(AgentDraftPendingIntent),
    Remove(AgentDraftPendingIntentRemoval),
}

/// Independent delta or frozen baseline page for pending intents.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentDraftPendingIntentContainer {
    Delta {
        projection_position: u64,
        items: Vec<AgentDraftPendingIntentChange>,
    },
    Baseline {
        snapshot_cut_position: u64,
        page_offset: u64,
        next_page_offset: Option<u64>,
        items: Vec<AgentDraftPendingIntentChange>,
    },
}

impl AgentDraftPendingIntentContainer {
    pub fn validate(&self) -> Result<()> {
        let (positions, items): (Vec<u64>, &[AgentDraftPendingIntentChange]) = match self {
            Self::Delta {
                projection_position,
                items,
            } => (vec![*projection_position], items),
            Self::Baseline {
                snapshot_cut_position,
                page_offset,
                next_page_offset,
                items,
            } => {
                let mut positions = vec![*snapshot_cut_position, *page_offset];
                positions.extend(*next_page_offset);
                (positions, items)
            }
        };
        if positions
            .into_iter()
            .any(|position| position > MAX_SAFE_JSON_INTEGER)
        {
            return Err(protocol_error(
                "pending-intent projection position exceeds the safe JSON integer ceiling",
            ));
        }
        if items.len() > AGENT_DRAFT_PENDING_INTENT_MAX_ITEMS {
            return Err(protocol_error(
                "pending-intent page exceeds 100 combined changes",
            ));
        }
        for item in items {
            match item {
                AgentDraftPendingIntentChange::Upsert(value) => {
                    if canonical::canonical_json_bytes(value)?.len()
                        > AGENT_DRAFT_PENDING_INTENT_MAX_UPSERT_BYTES
                    {
                        return Err(protocol_error(
                            "pending-intent upsert exceeds its canonical byte limit",
                        ));
                    }
                    value.validate()?;
                }
                AgentDraftPendingIntentChange::Remove(value) => value.validate()?,
            }
        }
        Ok(())
    }
}

impl AgentDraftPendingIntent {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Live(value) => {
                validate_agent_draft_pending_fields(
                    &value.draft_id,
                    &value.proposed_action,
                    &value.target,
                )?;
                validate_agent_draft_content_handoff(&value.content_handoff)
            }
            Self::TerminalRedacted(AgentDraftPendingIntentTerminalRedacted::Consumed(value)) => {
                validate_agent_draft_pending_fields(
                    &value.draft_id,
                    &value.proposed_action,
                    &value.target,
                )?;
                value.consumption.validate()
            }
            Self::TerminalRedacted(AgentDraftPendingIntentTerminalRedacted::Expired(value)) => {
                validate_agent_draft_pending_fields(
                    &value.draft_id,
                    &value.proposed_action,
                    &value.target,
                )
            }
        }
    }
}

impl AgentDraftPendingIntentConsumption {
    fn validate(&self) -> Result<()> {
        parse_agent_draft_account_data_key(&self.account_data_key).map(|_| ())
    }
}

impl AgentDraftPendingIntentRemoval {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Consumed(value) => {
                value.key.validate()?;
                value.consumption.validate()
            }
            Self::Expired(value) => value.key.validate(),
        }
    }
}

impl AgentDraftPendingIntentKey {
    fn validate(&self) -> Result<()> {
        validate_agent_draft_identifier(&self.draft_id)
    }
}

fn validate_agent_draft_identifier(draft_id: &str) -> Result<()> {
    if draft_id.is_empty() || draft_id.starts_with("ak:") {
        return Err(protocol_error(
            "pending-intent draft_id violates its identifier profile",
        ));
    }
    Ok(())
}

fn validate_agent_draft_pending_fields(
    draft_id: &str,
    proposed_action: &str,
    target: &AgentActionTarget,
) -> Result<()> {
    validate_agent_draft_identifier(draft_id)?;
    if proposed_action.is_empty() {
        return Err(protocol_error(
            "pending-intent proposed_action must be non-empty",
        ));
    }
    if target.realm_id.is_none()
        && target.object_ref.is_none()
        && target.operation_id.is_none()
        && target.account_data_key.is_none()
    {
        return Err(protocol_error(
            "pending-intent target must name at least one selector",
        ));
    }
    if !matches!(
        target.kind.as_str(),
        "realm" | "space" | "strand" | "message" | "object" | "service_operation" | "account_data"
    ) || target.operation_id.as_deref() == Some("")
        || target.account_data_key.as_deref() == Some("")
    {
        return Err(protocol_error(
            "pending-intent target violates its closed schema",
        ));
    }
    Ok(())
}

fn validate_agent_draft_content_handoff(value: &AgentDraftContentHandoff) -> Result<()> {
    if !(1..=32).contains(&value.recipients.len()) {
        return Err(protocol_error(
            "pending-intent content_handoff must have 1..=32 recipients",
        ));
    }
    let is_base64url = |text: &str, minimum: usize| {
        text.len() >= minimum
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    if value.recipients.iter().any(|recipient| {
        !is_base64url(&recipient.enc, 43) || !is_base64url(&recipient.ciphertext, 22)
    }) {
        return Err(protocol_error(
            "pending-intent content_handoff contains a non-canonical base64url member",
        ));
    }
    Ok(())
}

/// Closed action set for account notification projection deltas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeltaAction {
    Upsert,
    Remove,
}

/// Closed terminal reasons for an Agent runtime approval notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRuntimeApprovalRemovalReason {
    Approved,
    Expired,
    Renewed,
    Deactivated,
    Superseded,
}

/// Optional data carried by a remove delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalNotificationRemovalData {
    pub reason: AgentRuntimeApprovalRemovalReason,
}

/// Closed terminal reasons for an ordinary source-Event notification row.
///
/// Every value is server-observable. Inbox disposition (read / dismissed /
/// archived) is holder-private state and never removes a current row, so it has
/// no representation here — a Station that wanted to express "the user read it"
/// would have to invent a reason, and there is none to invent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrdinaryNotificationRemovalReason {
    SourceRemoved,
    AccessRevoked,
    Expired,
    Superseded,
}

/// Required data of an ordinary source-Event notification `remove` delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdinaryNotificationRemovalData {
    pub reason: OrdinaryNotificationRemovalReason,
}

/// Closed data branches for account notification deltas.
///
/// Serialization is untagged because the wire carries no discriminator of its
/// own; deserialization is *not*, and must not be. `expired` and `superseded`
/// belong to both removal vocabularies, so an untagged decoder would accept an
/// ordinary removal reason on an Agent approval row (and the reverse) whenever
/// the two vocabularies overlap. [`NotificationDelta`] therefore selects the
/// branch from the `id` form first and only then parses `data` into that
/// branch's type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum NotificationData {
    AgentRuntimeApproval(AgentRuntimeApprovalNotificationData),
    AgentRuntimeApprovalRemoval(AgentRuntimeApprovalNotificationRemovalData),
    OrdinaryProjection(Box<OrdinaryProjectionContent>),
    OrdinaryRemoval(OrdinaryNotificationRemovalData),
}

/// Strongly typed account notification projection delta.
///
/// One channel carries both notification branches, and the `id` form is the
/// only discriminator: `ak:notification:<uuidv7>` is an Agent runtime approval,
/// `ak:notification_projection:<token>` is an ordinary source-Event current
/// row. Both share the projector, the channel position and the per-frame
/// budget; there is no second notification list operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationDelta {
    pub id: NotificationIdentity,
    pub action: NotificationDeltaAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<NotificationData>,
}

impl NotificationDelta {
    pub fn try_new(
        id: NotificationIdentity,
        action: NotificationDeltaAction,
        data: Option<NotificationData>,
    ) -> Result<Self> {
        let delta = Self { id, action, data };
        delta.validate_shape()?;
        Ok(delta)
    }

    pub fn validate_shape(&self) -> Result<()> {
        match (&self.id, self.action, self.data.as_ref()) {
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Upsert,
                Some(NotificationData::AgentRuntimeApproval(_)),
            )
            | (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Remove,
                None | Some(NotificationData::AgentRuntimeApprovalRemoval(_)),
            ) => Ok(()),
            (
                NotificationIdentity::Projection(_),
                NotificationDeltaAction::Upsert,
                Some(NotificationData::OrdinaryProjection(content)),
            ) => content.validate(),
            (
                NotificationIdentity::Projection(_),
                NotificationDeltaAction::Remove,
                Some(NotificationData::OrdinaryRemoval(_)),
            ) => Ok(()),
            (NotificationIdentity::AgentApproval(_), NotificationDeltaAction::Upsert, _) => {
                Err(WireError::Protocol(
                    "notification upsert requires agent_runtime_approval data".to_owned(),
                ))
            }
            (NotificationIdentity::AgentApproval(_), NotificationDeltaAction::Remove, _) => {
                Err(WireError::Protocol(
                    "notification remove data must contain only a terminal reason".to_owned(),
                ))
            }
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Upsert, _) => {
                Err(WireError::Protocol(
                    "ordinary notification upsert requires ordinary projection content".to_owned(),
                ))
            }
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Remove, _) => {
                Err(WireError::Protocol(
                    "ordinary notification remove requires a server-observable reason".to_owned(),
                ))
            }
        }
    }

    pub fn agent_runtime_approval(&self) -> Option<&AgentRuntimeApprovalNotificationData> {
        match self.data.as_ref() {
            Some(NotificationData::AgentRuntimeApproval(data)) => Some(data),
            _ => None,
        }
    }

    pub fn agent_runtime_approval_removal_reason(
        &self,
    ) -> Option<AgentRuntimeApprovalRemovalReason> {
        match self.data.as_ref() {
            Some(NotificationData::AgentRuntimeApprovalRemoval(data)) => Some(data.reason),
            _ => None,
        }
    }

    pub fn ordinary_projection(&self) -> Option<&OrdinaryProjectionContent> {
        match self.data.as_ref() {
            Some(NotificationData::OrdinaryProjection(content)) => Some(content),
            _ => None,
        }
    }

    pub fn ordinary_removal_reason(&self) -> Option<OrdinaryNotificationRemovalReason> {
        match self.data.as_ref() {
            Some(NotificationData::OrdinaryRemoval(data)) => Some(data.reason),
            _ => None,
        }
    }

    /// Recompute the ordinary projection identity from the authenticated
    /// recipient's own AccountId and compare it with the delivered row id.
    ///
    /// A recipient MUST run this before displaying an ordinary current row: the
    /// id is the only thing binding the row to *this* account, and the row
    /// itself does not carry a recipient field to compare against. Branches
    /// with no recomputable identity (Agent approvals, and ordinary removals,
    /// which carry only a reason) return `Ok` without asserting anything.
    pub fn verify_recipient_binding(&self, recipient_account_id: &AccountId) -> Result<()> {
        self.validate_shape()?;
        match (&self.id, self.data.as_ref()) {
            (
                NotificationIdentity::Projection(id),
                Some(NotificationData::OrdinaryProjection(content)),
            ) => content.verify_id(recipient_account_id, id),
            _ => Ok(()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationDeltaWire {
    id: NotificationIdentity,
    action: NotificationDeltaAction,
    #[serde(default)]
    data: Option<Value>,
}

impl<'de> Deserialize<'de> for NotificationDelta {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = NotificationDeltaWire::deserialize(deserializer)?;
        let data = match (&wire.id, wire.action, wire.data) {
            (_, _, None) => None,
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Upsert,
                Some(raw),
            ) => Some(NotificationData::AgentRuntimeApproval(
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
            )),
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Remove,
                Some(raw),
            ) => Some(NotificationData::AgentRuntimeApprovalRemoval(
                serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
            )),
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Upsert, Some(raw)) => {
                Some(NotificationData::OrdinaryProjection(Box::new(
                    serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
                )))
            }
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Remove, Some(raw)) => {
                Some(NotificationData::OrdinaryRemoval(
                    serde_json::from_value(raw).map_err(serde::de::Error::custom)?,
                ))
            }
        };
        Self::try_new(wire.id, wire.action, data).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod notification_delta_tests {
    // `DidCoreId` only builds fixtures, so it belongs to the test module rather
    // than to the module's own imports.
    use arkret_wire::{DidCoreId, OrdinaryNotificationKind};
    use serde_json::json;

    use super::*;

    /// Identity KAT from `id-kind-registry.json`: this recipient, Realm, source
    /// Event and `message` kind derive exactly the projection id below.
    const KAT_REALM: &str = "ak:realm:AdF_8ICakbYdEH0Cnl-w5o1WFlnh5rXGWqY_-_G6yM7N";
    const KAT_EVENT: &str = "ak:event:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";
    const KAT_PROJECTION: &str =
        "ak:notification_projection:AdaNq4qN-xTAcv8kCT3P9mL5AsSzg0PFlSELggvhw2Pw";

    fn kat_recipient() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        )
    }

    fn approval_delta(action: &str) -> Value {
        json!({
            "id": "ak:notification:01964137-0000-7000-8000-000000000001",
            "action": action,
            "data": {
                "approval_request_id": "agent_runtime_approval:01964137-0000-7000-8000-000000000000",
                "agent_id": "ak:did_core:webvh:z6mkfixtureagent",
                "requested_at": "2026-07-13T10:00:00.000Z",
                "expires_at": "2026-07-13T10:15:00.000Z"
            }
        })
    }

    fn ordinary_delta(action: &str, data: Value) -> Value {
        json!({"id": KAT_PROJECTION, "action": action, "data": data})
    }

    fn ordinary_content() -> Value {
        json!({
            "realm_id": KAT_REALM,
            "source_event_id": KAT_EVENT,
            "notification_kind": "message",
            "priority": "normal",
            "created_at": "2026-09-10T10:00:00.000Z"
        })
    }

    #[test]
    fn notification_delta_accepts_upsert_and_rejects_retired_actions() {
        let delta: NotificationDelta = serde_json::from_value(approval_delta("upsert")).unwrap();
        assert_eq!(delta.action, NotificationDeltaAction::Upsert);
        assert!(serde_json::from_value::<NotificationDelta>(approval_delta("add")).is_err());
        assert!(serde_json::from_value::<NotificationDelta>(approval_delta("update")).is_err());
    }

    #[test]
    fn notification_delta_rejects_unknown_members() {
        let mut value = approval_delta("upsert");
        value["unknown_action"] = json!("add");
        assert!(serde_json::from_value::<NotificationDelta>(value).is_err());

        let mut retired_notification_kind = approval_delta("upsert");
        retired_notification_kind["notification_kind"] = json!("agent");
        assert!(serde_json::from_value::<NotificationDelta>(retired_notification_kind).is_err());

        let mut retired_data_kind = approval_delta("upsert");
        retired_data_kind["data"]["kind"] = json!("agent_runtime_approval");
        assert!(serde_json::from_value::<NotificationDelta>(retired_data_kind).is_err());
    }

    #[test]
    fn ordinary_current_row_round_trips_and_binds_its_recipient() {
        let delta: NotificationDelta =
            serde_json::from_value(ordinary_delta("upsert", ordinary_content())).unwrap();
        let content = delta.ordinary_projection().expect("ordinary branch");
        assert_eq!(content.notification_kind, OrdinaryNotificationKind::Message);
        assert!(delta.agent_runtime_approval().is_none());
        delta.verify_recipient_binding(&kat_recipient()).unwrap();

        let other_station = AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );
        assert!(delta.verify_recipient_binding(&other_station).is_err());
        assert_eq!(
            serde_json::to_value(&delta).unwrap(),
            ordinary_delta("upsert", ordinary_content())
        );
    }

    #[test]
    fn ordinary_row_refuses_inbox_state_and_identity_members() {
        for forbidden in ["id", "schema", "actor_id", "state"] {
            let mut content = ordinary_content();
            content[forbidden] = json!("unread");
            assert!(
                serde_json::from_value::<NotificationDelta>(ordinary_delta("upsert", content))
                    .is_err(),
                "{forbidden}"
            );
        }
        let mut agent_kind = ordinary_content();
        agent_kind["notification_kind"] = json!("agent");
        assert!(
            serde_json::from_value::<NotificationDelta>(ordinary_delta("upsert", agent_kind))
                .is_err()
        );
        let mut invite_kind = ordinary_content();
        invite_kind["notification_kind"] = json!("invite");
        assert!(
            serde_json::from_value::<NotificationDelta>(ordinary_delta("upsert", invite_kind))
                .is_err()
        );
    }

    #[test]
    fn removal_vocabularies_do_not_cross_branches() {
        let delta: NotificationDelta =
            serde_json::from_value(ordinary_delta("remove", json!({"reason": "expired"}))).unwrap();
        assert_eq!(
            delta.ordinary_removal_reason(),
            Some(OrdinaryNotificationRemovalReason::Expired)
        );
        assert!(delta.agent_runtime_approval_removal_reason().is_none());

        // `approved` is an Agent-only reason and `access_revoked` an ordinary
        // one; the shared `expired` / `superseded` values are exactly why the
        // branch cannot be chosen by trying both data shapes.
        assert!(
            serde_json::from_value::<NotificationDelta>(ordinary_delta(
                "remove",
                json!({"reason": "approved"})
            ))
            .is_err()
        );
        let mut agent_remove = approval_delta("remove");
        agent_remove["data"] = json!({"reason": "access_revoked"});
        assert!(serde_json::from_value::<NotificationDelta>(agent_remove).is_err());

        // An ordinary remove carries no optional data: the reason is required.
        let mut bare = ordinary_delta("remove", json!({}));
        bare.as_object_mut().unwrap().remove("data");
        assert!(serde_json::from_value::<NotificationDelta>(bare).is_err());
    }

    #[test]
    fn branch_data_cannot_be_delivered_under_the_other_id_form() {
        let mut approval_under_projection = approval_delta("upsert");
        approval_under_projection["id"] = json!(KAT_PROJECTION);
        assert!(serde_json::from_value::<NotificationDelta>(approval_under_projection).is_err());

        let mut ordinary_under_approval = ordinary_delta("upsert", ordinary_content());
        ordinary_under_approval["id"] =
            json!("ak:notification:01964137-0000-7000-8000-000000000001");
        assert!(serde_json::from_value::<NotificationDelta>(ordinary_under_approval).is_err());
    }
}

/// Dedicated notification container for account subscribe.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationContainer {
    pub items: Vec<NotificationDelta>,
}

#[derive(Clone, Debug, Default)]
pub struct AccountSyncRoundBudget {
    frame_count: usize,
    canonical_bytes: usize,
}

impl AccountSyncRoundBudget {
    pub fn observe(&mut self, canonical_bytes: usize) -> Result<()> {
        let total = self
            .canonical_bytes
            .checked_add(canonical_bytes)
            .ok_or_else(|| protocol_error("account round size overflow"))?;
        if self.frame_count >= ACCOUNT_SUBSCRIBE_MAX_ROUND_FRAMES
            || canonical_bytes > ACCOUNT_SUBSCRIBE_MAX_FRAME_BYTES
            || total > ACCOUNT_SUBSCRIBE_MAX_ROUND_BYTES
        {
            return Err(protocol_error("account sync round exceeds its budget"));
        }
        self.frame_count += 1;
        self.canonical_bytes = total;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum AccountSubscribeSnapshotResult {
    Batch(AccountSubscribeBatch),
    ReconnectAfter {
        reconnect_after_ms: u64,
        reconnect_cursor: Option<String>,
        reason: Option<String>,
        reset_cursor: bool,
    },
}

#[derive(Clone, Debug)]
pub struct AccountSubscribeBatch {
    pub frames: Vec<AccountSubscribeFrame>,
    pub cursor: String,
}

#[derive(Clone, Debug)]
pub struct AccountSubscribeReconnectAfter {
    pub reconnect_after_ms: u64,
    pub reconnect_cursor: Option<String>,
    pub reason: Option<String>,
    pub reset_cursor: bool,
}

impl std::fmt::Display for AccountSubscribeReconnectAfter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "account subscribe requested reconnect after {} ms",
            self.reconnect_after_ms
        )
    }
}

impl std::error::Error for AccountSubscribeReconnectAfter {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamTraceFrameKind {
    Data,
    Checkpoint,
    Heartbeat,
    CatchupComplete,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

impl StreamTraceFrameKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Checkpoint => "checkpoint",
            Self::Heartbeat => "heartbeat",
            Self::CatchupComplete => "catchup_complete",
            Self::Dropped => "dropped",
            Self::ResyncRequired => "resync_required",
            Self::Unauthorized => "unauthorized",
        }
    }

    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Dropped | Self::ResyncRequired | Self::Unauthorized
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StreamTraceError {
    #[error("stream frame `{kind}` requires a non-empty cursor")]
    MissingCursor { kind: &'static str },
    #[error("catchup_complete arrived before baseline data")]
    CatchupCompleteBeforeData,
    #[error("catchup_complete is forbidden when catchup=false")]
    UnexpectedCatchupComplete,
    #[error("stream frame arrived after terminal `{terminal}`")]
    FrameAfterTerminal { terminal: &'static str },
    #[error("stream trace was already rejected")]
    TraceAlreadyRejected,
    #[error("stream ended before catchup_complete")]
    CatchupIncomplete,
}

impl StreamTraceError {
    pub fn violation(&self) -> &'static str {
        match self {
            Self::MissingCursor { kind: "dropped" } => "dropped_missing_cursor",
            Self::MissingCursor { .. } => "cursor_required",
            Self::CatchupCompleteBeforeData => "catchup_complete_before_delta",
            Self::UnexpectedCatchupComplete => "unexpected_catchup_complete",
            Self::FrameAfterTerminal { .. } => "frame_after_terminal",
            Self::TraceAlreadyRejected => "trace_already_rejected",
            Self::CatchupIncomplete => "catchup_incomplete",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StreamTraceValidator {
    catchup: bool,
    baseline_data_seen: bool,
    catchup_complete_seen: bool,
    reconnect_cursor: Option<String>,
    terminal: Option<StreamTraceFrameKind>,
    rejected: bool,
}

impl StreamTraceValidator {
    pub fn new(catchup: bool, reconnect_cursor: Option<String>) -> Self {
        Self {
            catchup,
            baseline_data_seen: false,
            catchup_complete_seen: false,
            reconnect_cursor,
            terminal: None,
            rejected: false,
        }
    }

    pub fn push(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> std::result::Result<(), StreamTraceError> {
        if self.rejected {
            return Err(StreamTraceError::TraceAlreadyRejected);
        }
        if let Some(terminal) = self.terminal {
            self.rejected = true;
            return Err(StreamTraceError::FrameAfterTerminal {
                terminal: terminal.as_str(),
            });
        }
        let kind = match frame.kind {
            AccountSubscribeFrameKind::Delta => StreamTraceFrameKind::Data,
            AccountSubscribeFrameKind::Checkpoint => StreamTraceFrameKind::Checkpoint,
            AccountSubscribeFrameKind::Heartbeat => StreamTraceFrameKind::Heartbeat,
            AccountSubscribeFrameKind::CatchupComplete => StreamTraceFrameKind::CatchupComplete,
            AccountSubscribeFrameKind::Dropped => StreamTraceFrameKind::Dropped,
            AccountSubscribeFrameKind::ResyncRequired => StreamTraceFrameKind::ResyncRequired,
            AccountSubscribeFrameKind::Unauthorized => StreamTraceFrameKind::Unauthorized,
        };
        if matches!(
            kind,
            StreamTraceFrameKind::Data
                | StreamTraceFrameKind::Checkpoint
                | StreamTraceFrameKind::CatchupComplete
                | StreamTraceFrameKind::Dropped
        ) && frame.cursor.as_deref().is_none_or(str::is_empty)
        {
            self.rejected = true;
            return Err(StreamTraceError::MissingCursor {
                kind: kind.as_str(),
            });
        }
        if kind == StreamTraceFrameKind::CatchupComplete {
            if !self.catchup {
                self.rejected = true;
                return Err(StreamTraceError::UnexpectedCatchupComplete);
            }
            if !self.baseline_data_seen {
                self.rejected = true;
                return Err(StreamTraceError::CatchupCompleteBeforeData);
            }
            self.catchup_complete_seen = true;
        }
        if matches!(
            kind,
            StreamTraceFrameKind::Data | StreamTraceFrameKind::Checkpoint
        ) {
            self.baseline_data_seen = true;
        }
        match kind {
            StreamTraceFrameKind::Data
            | StreamTraceFrameKind::Checkpoint
            | StreamTraceFrameKind::CatchupComplete
            | StreamTraceFrameKind::Dropped => self.reconnect_cursor = frame.cursor.clone(),
            StreamTraceFrameKind::ResyncRequired => self.reconnect_cursor = None,
            _ => {}
        }
        if kind.terminal() {
            self.terminal = Some(kind);
        }
        Ok(())
    }

    pub fn finish(&mut self) -> std::result::Result<(), StreamTraceError> {
        if self.rejected {
            return Err(StreamTraceError::TraceAlreadyRejected);
        }
        if self.catchup && !self.catchup_complete_seen && self.terminal.is_none() {
            self.rejected = true;
            return Err(StreamTraceError::CatchupIncomplete);
        }
        Ok(())
    }

    pub fn reconnect_cursor(&self) -> Option<&str> {
        self.reconnect_cursor.as_deref()
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }
}
