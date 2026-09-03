//! Client sync protocol implementation.
//!
//! This module implements the Arkret v1 client sync protocol:
//! - Incremental sync with cursors
//! - Backfill handling
//! - Device message handling
//! - Filter and subscription support

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{ActorId, DidCoreId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::internal_prelude::*;

/// Query parameters for `ak.self.account.stream.subscribe.v1`.
///
/// The read-your-writes barrier travels in the `X-Arkret-Wait-For` header, not
/// in this request; the closed shape keeps a stale `wait_for` member from being
/// accepted and then silently ignored.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
}

/// Sync filter for selective synchronization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncFilter {
    /// Realm IDs to sync.
    #[serde(default)]
    pub realm_ids: Vec<RealmId>,
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
    pub extra: BTreeMap<String, Value>,
}

/// Subscription configuration for realm_ids.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    /// Realm subscriptions.
    pub subscriptions: Vec<RealmSubscription>,
    /// Batch size for timeline
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_item_count: Option<u32>,
    /// Timeline filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_filter: Option<TimelineFilter>,
}

/// Realm subscription.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
pub struct BackfillOutcome {
    /// Events in reverse chronological order
    pub events: Vec<Event>,
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
pub struct TimelineOrderKey {
    /// Transitive causal depth in the local event graph.
    pub causal_depth: u64,
    /// Hybrid logical clock for the event.
    pub hlc: Option<Hlc>,
    /// Event actor.
    pub actor_id: ActorId,
    /// Actor-local sequence.
    pub actor_seq: u64,
    /// Event ID tie-breaker.
    pub event_id: EventId,
}

/// Stream position for one Realm at a sync boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    Ok(canonical::canonical_sha256(&Value::Object(binding))?)
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

    let realm_ids = sorted_unique_strings(filter.realm_ids.iter().map(RealmId::as_str));
    if !realm_ids.is_empty() {
        object.insert("realm_ids".to_owned(), serde_json::json!(realm_ids));
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
    if let Some(batch_item_count) = subscriptions.batch_item_count {
        object.insert(
            "batch_item_count".to_owned(),
            serde_json::json!(batch_item_count),
        );
    }
    if let Some(timeline_filter) = &subscriptions.timeline_filter {
        object.insert(
            "timeline_filter".to_owned(),
            serde_json::to_value(timeline_filter)?,
        );
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
pub struct SyncTokenBinding {
    /// Opaque token received from the sync service.
    pub token: String,
    /// Principal this token belongs to.
    pub principal_id: DidCoreId,
    /// Device this token belongs to.
    pub device_id: DeviceId,
    /// Service that minted the token.
    pub service_id: DidCoreId,
    /// Canonical digest of filter and subscription shape.
    pub filter_digest: String,
    /// Stream positions captured by the token.
    #[serde(default)]
    pub positions: Vec<SyncStreamPosition>,
    /// Expiry time for the token.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl SyncTokenBinding {
    /// Create a binding for a concrete request context.
    #[allow(clippy::too_many_arguments)]
    pub fn for_request(
        token: String,
        principal_id: DidCoreId,
        device_id: DeviceId,
        service_id: DidCoreId,
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
}

/// Whether a request starts from scratch or resumes an existing token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// No `after` token. The response should establish full local state.
    Initial,
    /// An `after` token is present. The response is an incremental delta.
    Incremental,
}

/// Client-visible sync semantics for one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Realm membership bucket in sync responses and list projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipBucket {
    /// Joined realm_ids.
    Joined,
    /// Invited realm_ids.
    Invited,
    /// realm_ids where the user has knocked/requested access.
    Knocked,
    /// Left realm_ids.
    Left,
}

/// Reason a timeline gap exists locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn from_timeline(realm_id: RealmId, timeline: &Timeline) -> Self {
        let prev_event_id = timeline.events.first().map(|event| event.event_id.clone());
        let next_event_id = timeline.events.last().map(|event| event.event_id.clone());
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
}

/// `X-Arkret-Wait-For` frontier wait request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitForFrontier {
    /// Required positions before the server should return.
    #[serde(default)]
    pub positions: Vec<SyncStreamPosition>,
    /// Maximum wait time in milliseconds.
    pub timeout_ms: u64,
}

/// To-device delivery acknowledgement state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct ToDeviceAck {
    /// Message ID from to-device content.
    pub device_message_id: String,
    /// Local device acknowledging the message.
    pub device_id: DeviceId,
    /// Acknowledgement status.
    pub status: ToDeviceAckStatus,
    /// Client acknowledgement time.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub acknowledged_at: DateTime<Utc>,
}

/// Updates extracted from a sync response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncUpdates {
    /// Realm updates.
    pub realm_updates: Vec<RealmUpdate>,
    /// Realm keys in the response that were not valid `ak:realm:*` ids and
    /// were skipped (per-realm degradation instead of failing the whole
    /// batch, preserving at-least-once for the well-formed realm_ids). A
    /// non-empty value indicates a misbehaving server.
    pub malformed_realm_ids: Vec<String>,
    /// To-device messages
    pub to_device: Vec<DeviceMessageEnvelope>,
    /// Opaque acknowledgement token for the delivered to-device batch.
    ///
    /// Issued by account subscribe when `to_device.messages[]` is non-empty
    /// and passed verbatim to `ak.self.device_messages.command.ack.v1` after the
    /// client durably records the batch.
    pub to_device_ack_token: Option<String>,
    /// Whether the account-subscribe to-device batch was truncated.
    pub to_device_limited: bool,
    /// Continuation cursor for `ak.self.device_messages.read.list.v1` when the
    /// account-subscribe to-device batch is limited.
    pub to_device_next_cursor: Option<String>,
    /// Whether the server reports an unacknowledged to-device queue gap.
    pub to_device_lost: bool,
    /// Device list changes
    pub device_lists: AccountSubscribeDeviceListChanges,
    /// Account data
    pub account_data: Vec<Event>,
    /// Cursor-covered Station-CAS Account Data baseline/deltas.
    #[serde(default)]
    pub station_cas_account_data:
        Vec<crate::sync_frames::account_subscribe::StationCasAccountDataContainer>,
    /// Notification deltas
    pub notifications: Vec<NotificationDelta>,
    /// Independently verifiable Agent signer evidence delivered by
    /// the account stream, never by Event federation.
    #[serde(default)]
    pub agent_signer_evidence: Vec<crate::agent_signer_evidence::AgentSignerEvidence>,
    /// Partial response flag
    pub partial: bool,
}

/// Update for a single Realm.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealmUpdate {
    pub realm_id: RealmId,
    pub entry: RealmSyncEntry,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_wire::{DidCoreId, project_did_to_core_id};

    use super::*;

    fn actor(value: &str) -> DidCoreId {
        let did = Did::new(value).unwrap();
        project_did_to_core_id(&did).unwrap()
    }

    #[test]
    fn sync_request_serializes_correctly() {
        let request = SyncRequestBody {
            after: Some("token123".to_owned()),
            catchup: Some(true),
            filter: None,
            subscriptions: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"after\":\"token123\""));
        assert!(json.contains("\"catchup\":true"));
    }

    #[test]
    fn backfill_request_serializes_correctly() {
        let request = BackfillRequestBody {
            realm_id: RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs")
                .unwrap(),
            from: BackfillFrom::Beginning,
            direction: BackfillDirection::Backward,
            limit: Some(100),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"realm_id\""));
        assert!(json.contains("\"direction\":\"backward\""));
    }

    #[test]
    fn sync_filter_digest_normalizes_collection_fields() {
        let realm_a =
            RealmId::new("ak:realm:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t").unwrap();
        let realm_b =
            RealmId::new("ak:realm:AUZVSPb9v-NuEN6dQgTA44vXJnQ1d-pxAvvfplV4zgOc").unwrap();
        let filter_a = SyncFilter {
            realm_ids: vec![realm_b.clone(), realm_a.clone(), realm_a.clone()],
            timeline_limit: Some(20),
            lazy_load_members: true,
            include_redundant_members: false,
            event_types: vec![
                "ak.reaction.add".to_owned(),
                "ak.message.create".to_owned(),
                "ak.message.create".to_owned(),
            ],
            not_event_types: vec!["ak.audit.accessed".to_owned(), "ak.redaction".to_owned()],
            extra: BTreeMap::new(),
        };
        let filter_b = SyncFilter {
            realm_ids: vec![realm_a.clone(), realm_b.clone()],
            timeline_limit: Some(20),
            lazy_load_members: true,
            include_redundant_members: false,
            event_types: vec!["ak.message.create".to_owned(), "ak.reaction.add".to_owned()],
            not_event_types: vec!["ak.redaction".to_owned(), "ak.audit.accessed".to_owned()],
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
            batch_item_count: Some(20),
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
            batch_item_count: Some(20),
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
        let realm_id =
            RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs").unwrap();
        let station = actor("did:webvh:z6mkfixture:principal.example");
        let actor = actor("did:webvh:z6mkfixture:alice.example");
        let mut newer_hlc = test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor.clone(),
            station.clone(),
            2,
            Hlc::new("01970e589d22-0000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"newer"}),
        )
        .unwrap();
        newer_hlc.event_id =
            EventId::new("ak:event:AYnTVVCNBa4iXXbFlwzE8SaOYDUUHuMdVacBm9hSHVPf").unwrap();
        let mut deeper = test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id },
            actor,
            station,
            1,
            Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            serde_json::json!({"body":"deeper"}),
        )
        .unwrap();
        deeper.event_id =
            EventId::new("ak:event:AXGvEEJkv6YPQvGdReHV-eLM-8ukvH7r9m8dCu3KWw36").unwrap();

        let mut keys = [
            TimelineOrderKey {
                causal_depth: 0,
                hlc: newer_hlc.hlc.clone(),
                actor_id: newer_hlc.actor_id.clone(),
                actor_seq: newer_hlc.actor_seq,
                event_id: newer_hlc.event_id.clone(),
            },
            TimelineOrderKey {
                causal_depth: 1,
                hlc: deeper.hlc.clone(),
                actor_id: deeper.actor_id.clone(),
                actor_seq: deeper.actor_seq,
                event_id: deeper.event_id.clone(),
            },
        ];
        keys.sort();

        assert_eq!(keys[0].event_id, newer_hlc.event_id);
        assert_eq!(keys[1].event_id, deeper.event_id);
    }
}
