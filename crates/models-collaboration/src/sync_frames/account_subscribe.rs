//! Account-aggregate subscription frames.
//!
//! The account cursor orders delivery of aggregate frames only. Durable Realm,
//! Circle, and Sidecar data remains in independent governance-authority commit
//! streams; each timeline item retains its own `CommitStreamRef` coordinate.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::account::AccountDataRow;
use arkret_wire::{
    ActorId, Cursor, Event, RealmId, Result, SchemaId, StrandId, StreamItem, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    pub filter: Option<SyncFilter>,
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

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_ids: Option<Vec<StrandId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline_limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lazy_load_members: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_event_kinds: Option<Vec<String>>,
}

impl SyncFilter {
    pub fn validate(&self) -> Result<()> {
        bounded_unique(
            self.realm_ids.as_deref().unwrap_or_default(),
            16,
            "filter.realm_ids",
        )?;
        bounded_unique(
            self.strand_ids.as_deref().unwrap_or_default(),
            32,
            "filter.strand_ids",
        )?;
        for (field, values) in [
            ("filter.event_kinds", &self.event_kinds),
            ("filter.not_event_kinds", &self.not_event_kinds),
        ] {
            bounded_unique(values.as_deref().unwrap_or_default(), 64, field)?;
        }
        if self.timeline_limit.is_some_and(|limit| limit > 100) {
            return Err(protocol_error("timeline_limit must be <= 100"));
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
    pub to_device: Option<DeviceMessageContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_lists: Option<AccountSubscribeDeviceListChanges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<AccountDataContainer>,
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
    Frontier,
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
            AccountSubscribeFrameKind::CatchupComplete | AccountSubscribeFrameKind::Frontier => {
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
    pub timeline: Option<RealmTimeline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline_baseline: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_at_window_start: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<EventContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_roster: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_notifications: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<Value>,
}

impl RealmSyncEntry {
    fn validate(&self) -> Result<()> {
        if let Some(timeline) = &self.timeline {
            timeline.validate()?;
        }
        if self.unavailable.is_some()
            && (self.timeline.is_some()
                || self.current.is_some()
                || self.account_data.is_some()
                || self.summary.is_some())
        {
            return Err(protocol_error(
                "unavailable Realm detail cannot carry projection data",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmTimeline {
    #[serde(default)]
    pub commits: Vec<StreamItem>,
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_only: Option<bool>,
}

impl RealmTimeline {
    fn validate(&self) -> Result<()> {
        if self.commits.len() > 100 {
            return Err(protocol_error("Realm timeline exceeds 100 commits"));
        }
        if let Some(cursor) = &self.prev_cursor {
            validate_cursor(cursor)?;
        }
        for item in &self.commits {
            item.commit.validate_shape()?;
            if item.commit.event_ref != item.event.event_id {
                return Err(protocol_error("timeline commit does not bind its Event"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventContainer {
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMessageContainer {
    #[serde(default)]
    pub messages: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeltaAction {
    Upsert,
    Remove,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationDelta {
    pub id: String,
    pub action: NotificationDeltaAction,
    pub data: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationContainer {
    #[serde(default)]
    pub items: Vec<NotificationDelta>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RealmListPage(pub Value);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RealmListChanges(pub Value);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountBaselineSegment(pub Value);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInvalidation {
    pub realm_id: RealmId,
    pub revision: u64,
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
    Frontier,
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
            Self::Frontier => "frontier",
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
            AccountSubscribeFrameKind::Frontier => StreamTraceFrameKind::Frontier,
            AccountSubscribeFrameKind::Heartbeat => StreamTraceFrameKind::Heartbeat,
            AccountSubscribeFrameKind::CatchupComplete => StreamTraceFrameKind::CatchupComplete,
            AccountSubscribeFrameKind::Dropped => StreamTraceFrameKind::Dropped,
            AccountSubscribeFrameKind::ResyncRequired => StreamTraceFrameKind::ResyncRequired,
            AccountSubscribeFrameKind::Unauthorized => StreamTraceFrameKind::Unauthorized,
        };
        if matches!(
            kind,
            StreamTraceFrameKind::Data
                | StreamTraceFrameKind::Frontier
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
            StreamTraceFrameKind::Data | StreamTraceFrameKind::Frontier
        ) {
            self.baseline_data_seen = true;
        }
        match kind {
            StreamTraceFrameKind::Data
            | StreamTraceFrameKind::Frontier
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
