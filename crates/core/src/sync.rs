//! Client sync protocol implementation.
//!
//! This module implements the Arkret v1 client sync protocol:
//! - Incremental sync with cursors
//! - Backfill handling
//! - Device message handling
//! - Filter and subscription support

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Cursor, DeviceId, Did, Error, Event, EventId, Hlc, RealmId, Result, canonical};

/// Query parameters for `ck.self.account.stream.subscribe`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncRequestBody {
    /// Exclusive stream cursor used to resume account-aggregate delivery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// Ask the server to replay account-aggregate deltas before live tail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
    /// Filter for selective sync
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<SyncFilter>,
    /// Realm subscriptions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriptions: Option<SubscriptionConfig>,
    /// Optional frontier that the server should wait to observe before replying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<WaitForFrontier>,
}

/// Sync result for a single Realm payload entry.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncRealm {
    /// Timeline events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<SyncTimeline>,
    /// State events
    #[serde(default)]
    pub state: Vec<Value>,
    /// Summary information
    #[serde(default)]
    pub summary: Value,
    /// Ephemeral events
    #[serde(default)]
    pub ephemeral: Vec<Value>,
    /// Unread counts
    #[serde(default)]
    pub unread: UnreadCounts,
    /// R3.1 — typed member roster projection (per
    /// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`).
    /// Entries are derived from effective `ck.member.state` plus the
    /// effective set of `ck.member.identity.update` references; raw
    /// handle / display fields MUST NOT be carried here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<crate::models::MemberRosterEntry>,
    /// R3.1 — SYNC-2: true when `members` is truncated and MUST NOT be
    /// treated as the complete Realm roster.
    #[serde(default, skip_serializing_if = "is_false_default")]
    pub members_limited: bool,
    /// R3.1 — SYNC-2: optional pagination cursor for continuing member
    /// roster retrieval. Mirrors
    /// `account-subscribe-frame.schema.json#/properties/members_next_cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members_next_cursor: Option<Cursor>,
}

fn is_false_default(v: &bool) -> bool {
    !*v
}

/// Timeline events with pagination.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncTimeline {
    /// Events in the timeline
    pub events: Vec<Value>,
    /// Limited flag (if true, history was limited)
    pub limited: bool,
    /// Older-direction cursor for backfill
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
}

/// Unread notification counts.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct UnreadCounts {
    /// Notification count
    #[serde(default)]
    pub notification_count: u64,
    /// Highlight count
    #[serde(default)]
    pub highlight_count: u64,
}

/// Device list changes.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceListChanges {
    /// Changed device lists
    #[serde(default)]
    pub changed: Vec<String>,
    /// Left users
    #[serde(default)]
    pub left: Vec<String>,
}

/// To-device message.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ToDeviceMessage {
    /// Message type
    #[serde(rename = "type")]
    pub message_type: String,
    /// Sender principal if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_principal_id: Option<Did>,
    /// Sender device if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<DeviceId>,
    /// Recipient principal if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    /// Recipient device if the server forwards a full `device-message` envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    /// Message send time if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<DateTime<Utc>>,
    /// Message expiry if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Message content
    pub content: Value,
    /// Device proof if carried by the upstream envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<Value>,
    /// Unsigned service metadata if carried by the upstream envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
}

/// Presence status — the closed v1 wire set from
/// `discovery/profiles-presence.md` §3.2. Receivers MUST treat any
/// other wire value as a schema violation and drop the update
/// (fail closed) instead of guessing a nearby state; use
/// [`PresenceStatus::parse_wire`] for that strict path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Idle,
    Dnd,
    Offline,
}

/// Presence event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PresenceEvent {
    /// User ID
    pub user_id: String,
    /// Presence status
    pub presence: PresenceStatus,
    /// Last active wire value: either an RFC 3339 UTC timestamp or a
    /// bucketed `<start>/<duration>` interval (profiles-presence.md
    /// §3.3). Validate with `presence::validate_last_active_at`
    /// before display — malformed values MUST be dropped, not
    /// repaired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<String>,
    /// Transient status message override carried by the broadcast
    /// (falls back to the durable profile `status_message` when
    /// absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// Currently active device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// Account data.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountData {
    /// Data type
    #[serde(rename = "type")]
    pub data_type: String,
    /// Data content
    pub content: Value,
}

/// Notification delta.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct NotificationDelta {
    /// Notification ID
    pub id: String,
    /// Notification type
    #[serde(rename = "type")]
    pub notification_type: String,
    /// Action (add/update/remove)
    pub action: String,
    /// Notification data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Sync filter for selective synchronization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncFilter {
    /// Realm IDs to sync.
    #[serde(default)]
    pub realms: Vec<RealmId>,
    /// Per-Realm timeline limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_limit: Option<u32>,
    /// Whether member state may be lazy-loaded
    #[serde(default)]
    pub lazy_load_members: bool,
    /// Whether redundant member state should be included
    #[serde(default)]
    pub include_redundant_members: bool,
    /// Event kind allow list
    #[serde(default)]
    pub event_types: Vec<String>,
    /// Event kind deny list
    #[serde(default)]
    pub not_event_types: Vec<String>,
    /// Forward-compatible service-specific filter extensions.
    #[serde(default, flatten)]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

/// Subscription configuration for realms.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SubscriptionConfig {
    /// Realm subscriptions.
    pub subscriptions: Vec<RealmSubscription>,
    /// Batch size for timeline
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    /// Timeline filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_filter: Option<Value>,
}

/// Realm subscription.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmSubscription {
    /// Realm ID.
    pub realm_id: RealmId,
    /// Timeline filter (lazy loading, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_filter: Option<TimelineFilter>,
    /// Required state
    #[serde(default)]
    pub required_state: Vec<String>,
}

/// Timeline filter options.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TimelineFilter {
    /// All events
    All,
    /// Only messages
    MessagesOnly,
    /// Custom filter
    Custom { filter: Value },
}

/// Backfill request for historical events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BackfillRequestBody {
    /// Realm ID to backfill.
    pub realm_id: RealmId,
    /// Starting point (cursor or event ID)
    pub from: BackfillFrom,
    /// Direction
    #[serde(default)]
    pub direction: BackfillDirection,
    /// Maximum events to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Backfill starting point.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackfillFrom {
    /// Start from a cursor
    Cursor { cursor: String },
    /// Start from an event ID
    EventId { event_id: EventId },
    /// Start from the beginning
    Beginning,
}

/// Backfill direction.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackfillDirection {
    /// Backward (newer to older)
    #[default]
    Backward,
    /// Forward (older to newer)
    Forward,
    /// Both directions
    Both,
}

/// Backfill response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BackfillOutcome {
    /// Events in reverse chronological order
    pub events: Vec<Value>,
    /// Count of total events available
    pub total_count: u64,
    /// Next cursor for continued backfill
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Reached beginning of history
    pub beginning_of_history: bool,
    /// Reached end of history
    pub end_of_history: bool,
}

/// Deterministic order key for timeline events.
///
/// Events sort by causal depth, HLC, actor ID, actor sequence and event ID. The
/// caller supplies causal depth because it depends on the known event graph.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct TimelineOrderKey {
    /// Transitive causal depth in the local event graph.
    pub causal_depth: u64,
    /// Hybrid logical clock for the event.
    pub hlc: Hlc,
    /// Event actor.
    pub actor_id: Did,
    /// Actor-local sequence.
    pub actor_seq: u64,
    /// Event ID tie-breaker.
    pub event_id: EventId,
}

impl TimelineOrderKey {
    /// Build an order key from an event and a caller-computed causal depth.
    pub fn from_event(event: &Event, causal_depth: u64) -> Self {
        Self {
            causal_depth,
            hlc: event.hlc.clone(),
            actor_id: event.actor_id.clone(),
            actor_seq: event.actor_seq,
            event_id: event.event_id.clone(),
        }
    }
}

/// Stream position for one Realm at a sync boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncStreamPosition {
    /// Realm covered by this position.
    pub realm_id: RealmId,
    /// Causal frontier event IDs.
    #[serde(default)]
    pub frontier: Vec<EventId>,
    /// Last deterministic timeline order key observed for this Realm.
    pub timeline_order: Hlc,
    /// State hash or Merkle root at this point.
    pub state_digest: String,
}

impl SyncStreamPosition {
    /// Return true when this position covers the required frontier.
    pub fn covers(&self, required: &Self) -> bool {
        if self.realm_id != required.realm_id || self.timeline_order < required.timeline_order {
            return false;
        }
        if !required.state_digest.is_empty() && self.state_digest != required.state_digest {
            return false;
        }

        let frontier: BTreeSet<_> = self.frontier.iter().collect();
        required
            .frontier
            .iter()
            .all(|event_id| frontier.contains(event_id))
    }
}

/// Digest the request filter and subscriptions for token binding.
pub fn sync_filter_digest(
    filter: Option<&SyncFilter>,
    subscriptions: Option<&SubscriptionConfig>,
) -> Result<String> {
    let mut binding = serde_json::Map::new();
    binding.insert("filter".to_owned(), normalized_sync_filter(filter));
    if let Some(subscriptions) = subscriptions {
        binding.insert(
            "subscriptions".to_owned(),
            normalized_subscription_config(subscriptions)?,
        );
    }
    canonical::canonical_sha256(&Value::Object(binding))
}

fn sorted_unique_strings<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    values
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_sync_filter(filter: Option<&SyncFilter>) -> Value {
    let Some(filter) = filter else {
        return serde_json::json!({});
    };
    let mut object = filter
        .extra
        .clone()
        .into_iter()
        .collect::<serde_json::Map<_, _>>();

    let realms = sorted_unique_strings(filter.realms.iter().map(RealmId::as_str));
    if !realms.is_empty() {
        object.insert("realms".to_owned(), serde_json::json!(realms));
    }
    if let Some(timeline_limit) = filter.timeline_limit {
        object.insert(
            "timeline_limit".to_owned(),
            serde_json::json!(timeline_limit),
        );
    }
    if filter.lazy_load_members {
        object.insert("lazy_load_members".to_owned(), Value::Bool(true));
    }
    if filter.include_redundant_members {
        object.insert("include_redundant_members".to_owned(), Value::Bool(true));
    }
    let event_types = sorted_unique_strings(filter.event_types.iter().map(String::as_str));
    if !event_types.is_empty() {
        object.insert("event_types".to_owned(), serde_json::json!(event_types));
    }
    let not_event_types = sorted_unique_strings(filter.not_event_types.iter().map(String::as_str));
    if !not_event_types.is_empty() {
        object.insert(
            "not_event_types".to_owned(),
            serde_json::json!(not_event_types),
        );
    }

    Value::Object(object)
}

fn normalized_subscription_config(subscriptions: &SubscriptionConfig) -> Result<Value> {
    let mut object = serde_json::Map::new();
    let mut subscription_entries = Vec::with_capacity(subscriptions.subscriptions.len());
    for subscription in &subscriptions.subscriptions {
        let value = normalized_realm_subscription(subscription);
        let canonical = canonical::canonical_json_bytes(&value)?;
        subscription_entries.push((canonical, value));
    }
    subscription_entries.sort_by(|left, right| left.0.cmp(&right.0));
    subscription_entries.dedup_by(|left, right| left.0 == right.0);
    let normalized_subscriptions = subscription_entries
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    if !normalized_subscriptions.is_empty() {
        object.insert(
            "subscriptions".to_owned(),
            Value::Array(normalized_subscriptions),
        );
    }
    if let Some(batch_size) = subscriptions.batch_size {
        object.insert("batch_size".to_owned(), serde_json::json!(batch_size));
    }
    if let Some(timeline_filter) = &subscriptions.timeline_filter {
        object.insert("timeline_filter".to_owned(), timeline_filter.clone());
    }
    Ok(Value::Object(object))
}

fn normalized_realm_subscription(subscription: &RealmSubscription) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "realm_id".to_owned(),
        Value::String(subscription.realm_id.as_str().to_owned()),
    );
    if let Some(timeline_filter) = &subscription.timeline_filter {
        object.insert(
            "timeline_filter".to_owned(),
            serde_json::to_value(timeline_filter).unwrap_or(Value::Null),
        );
    }
    let required_state =
        sorted_unique_strings(subscription.required_state.iter().map(String::as_str));
    if !required_state.is_empty() {
        object.insert(
            "required_state".to_owned(),
            serde_json::json!(required_state),
        );
    }
    Value::Object(object)
}

/// Sync token binding context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncTokenBinding {
    /// Opaque token received from the sync service.
    pub token: String,
    /// Principal this token belongs to.
    pub principal_id: Did,
    /// Device this token belongs to.
    pub device_id: DeviceId,
    /// Service that minted the token.
    pub service_id: Did,
    /// Canonical digest of filter and subscription shape.
    pub filter_digest: String,
    /// Stream positions captured by the token.
    #[serde(default)]
    pub positions: Vec<SyncStreamPosition>,
    /// Expiry time for the token.
    pub expires_at: DateTime<Utc>,
}

impl SyncTokenBinding {
    /// Create a binding for a concrete request context.
    #[allow(clippy::too_many_arguments)]
    pub fn for_request(
        token: String,
        principal_id: Did,
        device_id: DeviceId,
        service_id: Did,
        filter: Option<&SyncFilter>,
        subscriptions: Option<&SubscriptionConfig>,
        positions: Vec<SyncStreamPosition>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Ok(Self {
            token,
            principal_id,
            device_id,
            service_id,
            filter_digest: sync_filter_digest(filter, subscriptions)?,
            positions,
            expires_at,
        })
    }

    /// Validate that the token is being resumed by the same principal/device/service/filter.
    pub fn validate_context(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
        service_id: &Did,
        filter_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.expires_at <= now {
            return Err(Error::Protocol("sync token has expired".to_owned()));
        }
        if &self.principal_id != principal_id
            || &self.device_id != device_id
            || &self.service_id != service_id
            || self.filter_digest != filter_digest
        {
            return Err(Error::Protocol("sync token binding mismatch".to_owned()));
        }
        Ok(())
    }

    /// Whether the token has expired at `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// Whether a request starts from scratch or resumes an existing token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// No `after` token. The response should establish full local state.
    Initial,
    /// An `after` token is present. The response is an incremental delta.
    Incremental,
}

/// Client-visible sync semantics for one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncSemantics {
    /// Initial or incremental.
    pub mode: SyncMode,
    /// Token used for incremental account subscribe, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// Initial sync establishes state for the requested scope.
    pub expects_full_state: bool,
    /// Incremental sync requires the token binding context to match.
    pub requires_token_binding: bool,
}

impl SyncSemantics {
    /// Derive semantics from a request.
    pub fn from_request(request: &SyncRequestBody) -> Self {
        let mode = if request.after.is_some() {
            SyncMode::Incremental
        } else {
            SyncMode::Initial
        };
        Self {
            mode,
            after: request.after.clone(),
            expects_full_state: mode == SyncMode::Initial,
            requires_token_binding: mode == SyncMode::Incremental,
        }
    }
}

/// Realm membership bucket in sync responses and list projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MembershipBucket {
    /// Joined realms.
    Joined,
    /// Invited realms.
    Invited,
    /// realms where the user has knocked/requested access.
    Knocked,
    /// Left realms.
    Left,
}

/// A sync update assigned to one membership bucket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BucketedRealmUpdate {
    /// Bucket name.
    pub bucket: MembershipBucket,
    /// Updated Realm ID.
    pub realm_id: RealmId,
    /// Raw update payload.
    pub update: SyncRealm,
}

/// Reason a timeline gap exists locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SyncGapReason {
    /// Server returned `timeline.limited`.
    Limited,
    /// Sync token expired and local state must be reset or replayed.
    TokenExpired,
    /// Historical backfill is still pending.
    Backfill,
}

/// Backfill gap descriptor created from a limited timeline or token expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncGap {
    /// Realm containing the gap.
    pub realm_id: RealmId,
    /// Older edge event if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_id: Option<EventId>,
    /// Newer edge event if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_event_id: Option<EventId>,
    /// Backfill cursor supplied by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    /// Why the gap exists.
    pub reason: SyncGapReason,
}

/// Model for `timeline.limited` and the backfill work it creates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct LimitedTimelineState {
    /// Realm containing the limited timeline.
    pub realm_id: RealmId,
    /// Whether the timeline was limited.
    pub limited: bool,
    /// Older-direction cursor for historical pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    /// Gap to persist and backfill, if limited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap: Option<SyncGap>,
}

impl LimitedTimelineState {
    /// Build limited timeline state from a sync timeline section.
    pub fn from_timeline(realm_id: RealmId, timeline: &SyncTimeline) -> Self {
        let prev_event_id = timeline.events.first().and_then(event_id_from_value);
        let next_event_id = timeline.events.last().and_then(event_id_from_value);
        let gap = timeline.limited.then(|| SyncGap {
            realm_id: realm_id.clone(),
            prev_event_id,
            next_event_id,
            prev_cursor: timeline.prev_cursor.clone(),
            reason: SyncGapReason::Limited,
        });

        Self {
            realm_id,
            limited: timeline.limited,
            prev_cursor: timeline.prev_cursor.clone(),
            gap,
        }
    }

    /// Convert this limited section into a backfill request, if one is needed.
    pub fn backfill_request(&self, limit: u32) -> Option<BackfillRequestBody> {
        let gap = self.gap.as_ref()?;
        Some(BackfillRequestBody {
            realm_id: self.realm_id.clone(),
            from: gap
                .prev_cursor
                .as_ref()
                .map(|cursor| BackfillFrom::Cursor {
                    cursor: cursor.clone(),
                })
                .or_else(|| {
                    gap.prev_event_id
                        .as_ref()
                        .map(|event_id| BackfillFrom::EventId {
                            event_id: event_id.clone(),
                        })
                })
                .unwrap_or(BackfillFrom::Beginning),
            direction: BackfillDirection::Backward,
            limit: Some(limit),
        })
    }
}

/// `X-Arkret-Wait-For` frontier wait request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct WaitForFrontier {
    /// Required positions before the server should return.
    #[serde(default)]
    pub positions: Vec<SyncStreamPosition>,
    /// Maximum wait time in milliseconds.
    pub timeout_ms: u64,
}

impl WaitForFrontier {
    /// Return true when the current positions satisfy every requested frontier.
    pub fn is_satisfied_by(&self, current: &[SyncStreamPosition]) -> bool {
        self.positions
            .iter()
            .all(|required| current.iter().any(|position| position.covers(required)))
    }
}

/// To-device delivery acknowledgement state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ToDeviceAckStatus {
    /// Message was received by the client SDK.
    Received,
    /// Message was decrypted and handed to the consumer.
    Processed,
    /// Message failed permanently.
    Failed,
}

/// Acknowledgement for one to-device message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ToDeviceAck {
    /// Message ID from to-device content.
    pub message_id: String,
    /// Local device acknowledging the message.
    pub device_id: DeviceId,
    /// Acknowledgement status.
    pub status: ToDeviceAckStatus,
    /// Client acknowledgement time.
    pub acknowledged_at: DateTime<Utc>,
}

fn event_id_from_value(value: &Value) -> Option<EventId> {
    serde_json::from_value::<Event>(value.clone())
        .ok()
        .map(|event| event.event_id)
}

/// Project a `Vec<Value>` from the wire `SyncOutcome` into typed
/// entries (e.g. [`ToDeviceMessage`], [`AccountData`]); items that
/// fail to parse are dropped silently. Callers that need strict
/// validation should walk the wire `Vec<Value>` directly.
pub fn project_typed_vec<T: serde::de::DeserializeOwned>(items: Vec<Value>) -> Vec<T> {
    items
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect()
}

/// Project a single `Value` (the wire-shape `notifications` field —
/// the spec leaves it as an events-container `{"events": [...]}`)
/// into a typed `Vec<T>`. Accepts the spec's events-container shape
/// or a bare array. Items that fail to parse are dropped.
pub fn project_typed_vec_from_value<T: serde::de::DeserializeOwned>(value: Value) -> Vec<T> {
    match value {
        Value::Array(items) => project_typed_vec(items),
        Value::Object(mut map) => match map.remove("events") {
            Some(Value::Array(items)) => project_typed_vec(items),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Sync client for managing incremental synchronization.
pub struct SyncClient {
    /// Current sync token
    current_token: Option<String>,
    /// Device ID
    _device_id: String,
    /// Active subscriptions
    subscriptions: HashMap<RealmId, RealmSubscription>,
}

impl SyncClient {
    /// Create a new sync client.
    pub fn new(device_id: String) -> Self {
        Self {
            current_token: None,
            _device_id: device_id,
            subscriptions: HashMap::new(),
        }
    }

    /// Get the current sync token.
    pub fn current_token(&self) -> Option<&str> {
        self.current_token.as_deref()
    }

    /// Update the sync token from a response.
    pub fn update_token(&mut self, cursor: String) {
        self.current_token = Some(cursor);
    }

    /// Create a sync request with current token.
    ///
    /// Presence intent is never part of the subscribe request — the
    /// account subscribe surface is read-only (client-sync.md).
    /// Broadcast presence through `POST /_cokret/self/ephemeral`
    /// instead.
    pub fn create_request(&self) -> SyncRequestBody {
        SyncRequestBody {
            after: self.current_token.clone(),
            catchup: Some(true),
            filter: None,
            subscriptions: None,
            wait_for: None,
        }
    }

    /// Create a sync request with custom options.
    pub fn create_request_with_options(
        &self,
        catchup: Option<bool>,
        filter: Option<SyncFilter>,
        subscriptions: Option<SubscriptionConfig>,
    ) -> SyncRequestBody {
        SyncRequestBody {
            after: self.current_token.clone(),
            catchup,
            filter,
            subscriptions,
            wait_for: None,
        }
    }

    /// Process a sync response and extract updates. The response is
    /// the wire-shape [`crate::models::SyncOutcome`] — per-event
    /// classes ([`SyncRealm`], [`ToDeviceMessage`], [`AccountData`],
    /// …) are projected out of the loose `Value` shape on demand so
    /// the wire layer doesn't have to commit to the typed shape.
    pub fn process_response(&mut self, response: crate::models::SyncOutcome) -> SyncUpdates {
        // Update token
        self.current_token = Some(response.cursor);

        // Extract updates
        let mut realm_updates = Vec::new();
        let mut malformed_realms = Vec::new();
        for (raw_realm_id, raw_sync_realm) in response.realms {
            let Ok(realm_id) = RealmId::new(raw_realm_id.clone()) else {
                malformed_realms.push(raw_realm_id);
                continue;
            };
            let sync_realm: SyncRealm = serde_json::from_value(raw_sync_realm).unwrap_or_default();
            realm_updates.push(RealmUpdate {
                realm_id,
                timeline: sync_realm.timeline,
                state: sync_realm.state,
                summary: sync_realm.summary,
            });
        }

        SyncUpdates {
            realm_updates,
            malformed_realms,
            to_device: project_typed_vec(response.to_device),
            to_device_ack_token: response.to_device_ack_token,
            to_device_limited: response.to_device_limited,
            to_device_next_cursor: response.to_device_next_cursor,
            to_device_lost: response.to_device_lost.unwrap_or(false),
            device_lists: serde_json::from_value(response.device_lists).unwrap_or_default(),
            presence: project_typed_vec(response.presence),
            account_data: project_typed_vec(response.account_data),
            notifications: project_typed_vec_from_value(response.notifications),
            partial: response.partial,
        }
    }

    /// Subscribe to a Realm.
    pub fn subscribe(&mut self, subscription: RealmSubscription) {
        self.subscriptions
            .insert(subscription.realm_id.clone(), subscription);
    }

    /// Unsubscribe from a Realm.
    pub fn unsubscribe(&mut self, realm_id: &RealmId) {
        self.subscriptions.remove(realm_id);
    }

    /// Get active subscriptions.
    pub fn subscriptions(&self) -> Vec<&RealmSubscription> {
        self.subscriptions.values().collect()
    }

    /// Reset sync state (e.g., after reconnection).
    pub fn reset(&mut self) {
        self.current_token = None;
    }
}

impl Default for SyncClient {
    fn default() -> Self {
        Self::new("default".to_owned())
    }
}

/// Updates extracted from a sync response.
#[derive(Clone, Debug)]
pub struct SyncUpdates {
    /// Realm updates.
    pub realm_updates: Vec<RealmUpdate>,
    /// Realm keys in the response that were not valid `ck:realm:*` ids and
    /// were skipped (per-realm degradation instead of failing the whole
    /// batch, preserving at-least-once for the well-formed realms). A
    /// non-empty value indicates a misbehaving server.
    pub malformed_realms: Vec<String>,
    /// To-device messages
    pub to_device: Vec<ToDeviceMessage>,
    /// Opaque acknowledgement token for the delivered to-device batch.
    ///
    /// Issued by account subscribe when `to_device.messages[]` is non-empty
    /// and passed verbatim to `ck.self.device_messages.command.ack` after the
    /// client durably records the batch.
    pub to_device_ack_token: Option<String>,
    /// Whether the account-subscribe to-device batch was truncated.
    pub to_device_limited: bool,
    /// Continuation cursor for `ck.self.device_messages.query.list` when the
    /// account-subscribe to-device batch is limited.
    pub to_device_next_cursor: Option<String>,
    /// Whether the server reports an unacknowledged to-device queue gap.
    pub to_device_lost: bool,
    /// Device list changes
    pub device_lists: DeviceListChanges,
    /// Presence events
    pub presence: Vec<PresenceEvent>,
    /// Account data
    pub account_data: Vec<AccountData>,
    /// Notification deltas
    pub notifications: Vec<NotificationDelta>,
    /// Partial response flag
    pub partial: bool,
}

/// Update for a single Realm.
#[derive(Clone, Debug)]
pub struct RealmUpdate {
    pub realm_id: RealmId,
    pub timeline: Option<SyncTimeline>,
    pub state: Vec<Value>,
    pub summary: Value,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::RealmId;

    #[test]
    fn sync_request_serializes_correctly() {
        let request = SyncRequestBody {
            after: Some("token123".to_owned()),
            catchup: Some(true),
            filter: None,
            subscriptions: None,
            wait_for: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"after\":\"token123\""));
        assert!(json.contains("\"catchup\":true"));
    }

    #[test]
    fn sync_response_deserializes_correctly() {
        let json = r#"{
            "cursor": "token456",
            "realms": {
                "ak:realm:01904100-0000-7000-8000-9b64700c6ee8": {
                    "timeline": {
                        "events": [],
                        "limited": false
                    },
                    "state": [],
                    "summary": {},
                    "ephemeral": [],
                    "unread": {
                        "notification_count": 0,
                        "highlight_count": 0
                    }
                }
            },
            "to_device": [],
            "device_lists": {
                "changed": [],
                "left": []
            },
            "presence": [],
            "account_data": [],
            "notifications": [],
            "partial": false
        }"#;

        let response: crate::models::SyncOutcome = serde_json::from_str(json).unwrap();
        assert_eq!(response.cursor, "token456");
        assert_eq!(response.realms.len(), 1);
    }

    #[test]
    fn sync_client_manages_token() {
        let mut client = SyncClient::new("device1".to_owned());
        assert!(client.current_token().is_none());

        client.update_token("token123".to_owned());
        assert_eq!(client.current_token(), Some("token123"));

        let request = client.create_request();
        assert_eq!(request.after, Some("token123".to_owned()));
    }

    #[test]
    fn sync_client_processes_response() {
        let mut client = SyncClient::new("device1".to_owned());

        let response = crate::models::SyncOutcome {
            cursor: "token456".to_owned(),
            realms: BTreeMap::new(),
            left_realms: Vec::new(),
            to_device: Vec::new(),
            to_device_ack_token: Some("ack-token-1".to_owned()),
            to_device_limited: true,
            to_device_next_cursor: Some("device-cursor-2".to_owned()),
            to_device_lost: None,
            device_lists: Value::Null,
            account_data: Vec::new(),
            presence: Vec::new(),
            notifications: Value::Null,
            partial: false,
        };

        let updates = client.process_response(response);
        assert_eq!(client.current_token(), Some("token456"));
        assert_eq!(updates.to_device_ack_token.as_deref(), Some("ack-token-1"));
        assert!(updates.to_device_limited);
        assert_eq!(
            updates.to_device_next_cursor.as_deref(),
            Some("device-cursor-2")
        );
        assert!(!updates.to_device_lost);
    }

    #[test]
    fn backfill_request_serializes_correctly() {
        let request = BackfillRequestBody {
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            from: BackfillFrom::Beginning,
            direction: BackfillDirection::Backward,
            limit: Some(100),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"realm_id\""));
        assert!(json.contains("\"direction\":\"backward\""));
    }

    #[test]
    fn sync_semantics_distinguish_initial_and_incremental() {
        let mut request = SyncClient::new("device1".to_owned()).create_request();
        let initial = SyncSemantics::from_request(&request);

        assert_eq!(initial.mode, SyncMode::Initial);
        assert!(initial.expects_full_state);
        assert!(!initial.requires_token_binding);

        request.after = Some("token123".to_owned());
        let incremental = SyncSemantics::from_request(&request);

        assert_eq!(incremental.mode, SyncMode::Incremental);
        assert!(!incremental.expects_full_state);
        assert!(incremental.requires_token_binding);
    }

    #[test]
    fn token_binding_checks_principal_device_service_filter_and_expiry() {
        let principal = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap();
        let service = Did::new("did:webvh:z6mkfixture:sync.example").unwrap();
        let filter = SyncFilter {
            realms: vec![RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()],
            timeline_limit: Some(20),
            lazy_load_members: true,
            include_redundant_members: false,
            event_types: vec!["ak.message.create".to_owned()],
            not_event_types: Vec::new(),
            extra: BTreeMap::new(),
        };
        let filter_digest = sync_filter_digest(Some(&filter), None).unwrap();
        let binding = SyncTokenBinding::for_request(
            "token123".to_owned(),
            principal.clone(),
            device.clone(),
            service.clone(),
            Some(&filter),
            None,
            Vec::new(),
            Utc::now() + chrono::Duration::minutes(5),
        )
        .unwrap();

        binding
            .validate_context(&principal, &device, &service, &filter_digest, Utc::now())
            .unwrap();
        assert!(
            binding
                .validate_context(
                    &principal,
                    &device,
                    &service,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    Utc::now(),
                )
                .is_err()
        );
    }

    #[test]
    fn sync_filter_digest_normalizes_collection_fields() {
        let realm_a = RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000a1").unwrap();
        let realm_b = RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000b2").unwrap();
        let filter_a = SyncFilter {
            realms: vec![realm_b.clone(), realm_a.clone(), realm_a.clone()],
            timeline_limit: Some(20),
            lazy_load_members: true,
            include_redundant_members: false,
            event_types: vec![
                "ak.reaction.add".to_owned(),
                "ak.message.create".to_owned(),
                "ak.message.create".to_owned(),
            ],
            not_event_types: vec!["ak.audit.accessed".to_owned(), "ck.redaction".to_owned()],
            extra: BTreeMap::new(),
        };
        let filter_b = SyncFilter {
            realms: vec![realm_a.clone(), realm_b.clone()],
            timeline_limit: Some(20),
            lazy_load_members: true,
            include_redundant_members: false,
            event_types: vec!["ak.message.create".to_owned(), "ck.reaction.add".to_owned()],
            not_event_types: vec!["ak.redaction".to_owned(), "ck.audit.accessed".to_owned()],
            extra: BTreeMap::new(),
        };
        let subscriptions_a = SubscriptionConfig {
            subscriptions: vec![
                RealmSubscription {
                    realm_id: realm_b.clone(),
                    timeline_filter: Some(TimelineFilter::MessagesOnly),
                    required_state: vec!["m.room.name".to_owned(), "m.room.topic".to_owned()],
                },
                RealmSubscription {
                    realm_id: realm_a.clone(),
                    timeline_filter: None,
                    required_state: vec![
                        "ak.member.state".to_owned(),
                        "ak.realm.policy".to_owned(),
                    ],
                },
                RealmSubscription {
                    realm_id: realm_b.clone(),
                    timeline_filter: Some(TimelineFilter::MessagesOnly),
                    required_state: vec!["m.room.topic".to_owned(), "m.room.name".to_owned()],
                },
            ],
            batch_size: Some(20),
            timeline_filter: None,
        };
        let subscriptions_b = SubscriptionConfig {
            subscriptions: vec![
                RealmSubscription {
                    realm_id: realm_a,
                    timeline_filter: None,
                    required_state: vec![
                        "ak.realm.policy".to_owned(),
                        "ak.member.state".to_owned(),
                    ],
                },
                RealmSubscription {
                    realm_id: realm_b,
                    timeline_filter: Some(TimelineFilter::MessagesOnly),
                    required_state: vec!["m.room.topic".to_owned(), "m.room.name".to_owned()],
                },
            ],
            batch_size: Some(20),
            timeline_filter: None,
        };

        assert_eq!(
            sync_filter_digest(Some(&filter_a), Some(&subscriptions_a)).unwrap(),
            sync_filter_digest(Some(&filter_b), Some(&subscriptions_b)).unwrap()
        );

        let mut changed = filter_b;
        changed.event_types = vec!["ak.message.create".to_owned()];
        assert_ne!(
            sync_filter_digest(Some(&filter_a), Some(&subscriptions_a)).unwrap(),
            sync_filter_digest(Some(&changed), Some(&subscriptions_b)).unwrap()
        );
    }

    #[test]
    fn timeline_order_key_uses_causal_depth_then_hlc_actor_sequence_and_event() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let actor = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let mut newer_hlc = Event::new(
            "ak.message.create",
            realm_id.clone(),
            actor.clone(),
            2,
            Hlc::new("01970e589d22-0000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"newer"}),
        )
        .unwrap();
        newer_hlc.event_id = EventId::new("ak:event:01904100-0000-7000-8000-233457bf6148").unwrap();
        let mut deeper = Event::new(
            "ak.message.create",
            realm_id,
            actor,
            1,
            Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"deeper"}),
        )
        .unwrap();
        deeper.event_id = EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap();

        let mut keys = [
            TimelineOrderKey::from_event(&newer_hlc, 0),
            TimelineOrderKey::from_event(&deeper, 1),
        ];
        keys.sort();

        assert_eq!(keys[0].event_id, newer_hlc.event_id);
        assert_eq!(keys[1].event_id, deeper.event_id);
    }

    #[test]
    fn wait_for_frontier_requires_covering_positions() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let event_id = EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap();
        let required = SyncStreamPosition {
            realm_id: realm_id.clone(),
            frontier: vec![event_id.clone()],
            timeline_order: Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            state_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };
        let wait_for = WaitForFrontier {
            positions: vec![required],
            timeout_ms: 1500,
        };
        let current = SyncStreamPosition {
            realm_id,
            frontier: vec![event_id],
            timeline_order: Hlc::new("01970e589d22-0000-a13f9c2e").unwrap(),
            state_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };

        assert!(wait_for.is_satisfied_by(&[current]));
    }

    #[test]
    fn limited_timeline_creates_backfill_gap_and_request() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let event = Event::new(
            "ak.message.create",
            realm_id.clone(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"hello"}),
        )
        .unwrap();
        let timeline = SyncTimeline {
            events: vec![serde_json::to_value(event).unwrap()],
            limited: true,
            prev_cursor: Some("backfill-token".to_owned()),
        };

        let state = LimitedTimelineState::from_timeline(realm_id, &timeline);
        let request = state.backfill_request(25).unwrap();

        assert!(state.gap.is_some());
        assert!(matches!(request.from, BackfillFrom::Cursor { .. }));
        assert_eq!(request.limit, Some(25));
    }
}
