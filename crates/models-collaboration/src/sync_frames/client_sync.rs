//! Client sync protocol implementation.
//!
//! This module implements the Arkret v1 client sync protocol:
//! - Incremental sync with cursors
//! - Backfill handling
//! - Device message handling
//! - Selective filters

use std::cmp::Ordering;
use std::collections::BTreeSet;

use arkret_wire::{ActorId, DidCoreId, Event, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::internal_prelude::*;

/// Closed account-subscribe query, shared with the WebSocket account operation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequestBody {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub after: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub catchup: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub filter: Option<SyncFilter>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub realm_list: Option<super::demand_sync::RealmListRequest>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub replace_filter: Option<bool>,
}

impl SyncRequestBody {
    pub fn validate(&self) -> Result<()> {
        if let Some(after) = &self.after {
            super::demand_sync::validate_demand_cursor(after)?;
        }
        if self.replace_filter == Some(true) && (self.after.is_none() || self.filter.is_none()) {
            return Err(WireError::Protocol(
                "replace_filter requires after and an explicit filter".to_owned(),
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

/// Explicit bounded detail interest. None and an empty Realm set select no details.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncFilter {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub strand_ids: Option<Vec<StrandId>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub timeline_limit: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub lazy_load_members: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub include_redundant_members: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub event_kinds: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub not_event_kinds: Option<Vec<String>>,
}

impl SyncFilter {
    pub fn validate(&self) -> Result<()> {
        use super::demand_sync::*;
        bounded_unique(
            self.realm_ids.as_deref().unwrap_or_default(),
            ACCOUNT_SYNC_MAX_REALMS,
            "filter.realm_ids",
        )?;
        bounded_unique(
            self.strand_ids.as_deref().unwrap_or_default(),
            ACCOUNT_SYNC_MAX_STRANDS,
            "filter.strand_ids",
        )?;
        for (field, items) in [
            ("event_kinds", &self.event_kinds),
            ("not_event_kinds", &self.not_event_kinds),
        ] {
            let items = items.as_deref().unwrap_or_default();
            bounded_unique(items, ACCOUNT_SYNC_MAX_KIND_FILTERS, field)?;
            for item in items {
                ProtocolKind::new(item.clone())
                    .map_err(|error| WireError::Protocol(error.to_owned()))?;
            }
        }
        if self.timeline_limit.is_some_and(|value| value > 100) {
            return Err(demand_error("filter.timeline_limit exceeds 100"));
        }
        if self
            .strand_ids
            .as_ref()
            .is_some_and(|items| !items.is_empty())
            && self.realm_ids.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(demand_error(
                "Strand detail interest requires selected Realms",
            ));
        }
        Ok(())
    }

    pub fn effective_timeline_limit(&self) -> u32 {
        self.timeline_limit
            .unwrap_or(super::demand_sync::ACCOUNT_SYNC_DEFAULT_TIMELINE_LIMIT)
    }

    pub fn effective_lazy_load_members(&self) -> bool {
        self.lazy_load_members.unwrap_or(true)
    }
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl Ord for TimelineOrderKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // `Option`'s derived order puts `None` first, but `conformance/
        // encoding.md` 7.3 makes an absent HLC sort **last**: it is greater
        // than any schema-valid HLC. Deriving `Ord` here would silently place
        // HLC-less Events at the head of every timeline window.
        fn hlc_rank(hlc: Option<&Hlc>) -> (u8, Option<&Hlc>) {
            match hlc {
                Some(hlc) => (0, Some(hlc)),
                None => (1, None),
            }
        }
        self.causal_depth
            .cmp(&other.causal_depth)
            .then_with(|| hlc_rank(self.hlc.as_ref()).cmp(&hlc_rank(other.hlc.as_ref())))
            .then_with(|| self.actor_id.cmp(&other.actor_id))
            .then_with(|| self.actor_seq.cmp(&other.actor_seq))
            .then_with(|| self.event_id.cmp(&other.event_id))
    }
}

impl PartialOrd for TimelineOrderKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Canonical timeline predecessor edges of one Event.
///
/// `conformance/encoding.md` 7.3 defines timeline `causal_depth` as the longest
/// path within the known causal closure along
/// `prev_refs` + `refs[role="after"]` + `causal_refs` + the payload-materialized
/// reply/reference edge. This is that edge set, and it is deliberately the only
/// place it is enumerated: a receiver that computes depth over a narrower set
/// produces a different order for the same Events.
///
/// `causal_refs` arrive as full wire digests. Any that name an active Event
/// digest suite are projected back to their Event id; the rest stay in
/// [`Self::unresolvable_digests`] and make the depth provisional, because an
/// edge the receiver cannot even name is an edge it cannot have closed over.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimelinePredecessors {
    pub event_ids: BTreeSet<EventId>,
    pub unresolvable_digests: BTreeSet<Hash>,
}

impl TimelinePredecessors {
    pub fn is_empty(&self) -> bool {
        self.event_ids.is_empty() && self.unresolvable_digests.is_empty()
    }
}

/// Payload field carrying the materialized reply edge of a message Event.
///
/// `models/content-types.md` 2: `ak.message.create` may carry `reply_to_id` as
/// an authoring convenience and the reducer projects it into a `replies_to`
/// relation. It is a complete Event id, so it participates in timeline depth
/// directly.
const TIMELINE_REPLY_EDGE_FIELD: &str = "reply_to_id";

pub fn timeline_predecessors(event: &Event) -> TimelinePredecessors {
    let mut predecessors = TimelinePredecessors::default();
    predecessors
        .event_ids
        .extend(event.prev_refs.iter().cloned());
    for reference in &event.refs {
        if reference.role == "after"
            && let Ok(event_id) = EventId::new(&reference.id)
        {
            predecessors.event_ids.insert(event_id);
        }
    }
    for digest in &event.causal_refs {
        match EventId::from_event_digest(digest) {
            Ok(event_id) => {
                predecessors.event_ids.insert(event_id);
            }
            Err(_) => {
                predecessors.unresolvable_digests.insert(digest.clone());
            }
        }
    }
    if let Some(reply_to) = event
        .payload
        .get(TIMELINE_REPLY_EDGE_FIELD)
        .and_then(Value::as_str)
        && let Ok(event_id) = EventId::new(reply_to)
    {
        predecessors.event_ids.insert(event_id);
    }
    predecessors
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

/// Digest the canonical account filter for token binding.
pub fn sync_filter_digest(filter: Option<&SyncFilter>) -> Result<String> {
    Ok(canonical::canonical_sha256(&normalized_sync_filter(
        filter,
    ))?)
}

pub fn normalized_sync_filter(filter: Option<&SyncFilter>) -> Value {
    let Some(filter) = filter else {
        return serde_json::json!({});
    };
    let mut value = serde_json::json!(filter);
    if let Some(object) = value.as_object_mut() {
        for field in ["realm_ids", "strand_ids", "event_kinds", "not_event_kinds"] {
            if let Some(Value::Array(items)) = object.get_mut(field) {
                items.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
                items.dedup();
            }
        }
    }
    value
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
    /// Canonical digest of the filter shape.
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
        positions: Vec<SyncStreamPosition>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Ok(Self {
            token,
            principal_id,
            device_id,
            service_id,
            filter_digest: sync_filter_digest(filter)?,
            positions,
            expires_at,
        })
    }
}

/// Whether a request starts from scratch or resumes an existing token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// No `after` token. Begins bounded per-channel baseline delivery.
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

            realm_list: None,
            replace_filter: None,
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
    fn sync_filter_preserves_empty_arrays_and_false_and_rejects_retired_names() {
        let wire = serde_json::json!({"realm_ids":[],"lazy_load_members":false});
        let filter: SyncFilter = serde_json::from_value(wire.clone()).unwrap();
        filter.validate().unwrap();
        assert_eq!(serde_json::to_value(&filter).unwrap(), wire);
        assert_eq!(normalized_sync_filter(Some(&filter)), wire);
        for old in [
            serde_json::json!({"realms":[]}),
            serde_json::json!({"custom":true}),
        ] {
            assert!(serde_json::from_value::<SyncFilter>(old).is_err());
        }
        assert_ne!(
            sync_filter_digest(Some(&filter)).unwrap(),
            sync_filter_digest(None).unwrap()
        );
    }

    #[test]
    fn sync_filter_digest_normalizes_collections_without_inserting_defaults() {
        let first: SyncFilter = serde_json::from_value(
            serde_json::json!({"event_kinds":["ak.reaction.add","ak.message.create"]}),
        )
        .unwrap();
        let second: SyncFilter = serde_json::from_value(
            serde_json::json!({"event_kinds":["ak.message.create","ak.reaction.add"]}),
        )
        .unwrap();
        assert_eq!(
            sync_filter_digest(Some(&first)).unwrap(),
            sync_filter_digest(Some(&second)).unwrap()
        );
        assert_eq!(
            sync_filter_digest(None).unwrap(),
            canonical::canonical_sha256(&serde_json::json!({})).unwrap()
        );
    }

    #[test]
    fn sync_filter_replacement_requires_a_resume_origin() {
        let request = SyncRequestBody {
            filter: Some(SyncFilter::default()),
            replace_filter: Some(true),
            ..Default::default()
        };
        assert!(request.validate().is_err());
        let request = SyncRequestBody {
            after: Some("ak:cursor:origin".to_owned()),
            ..request
        };
        request.validate().unwrap();
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

    #[test]
    fn timeline_predecessors_collect_every_canonical_edge_kind() {
        let realm_id =
            RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs").unwrap();
        let station = actor("did:webvh:z6mkfixture:principal.example");
        let producer = actor("did:webvh:z6mkfixture:alice.example");
        let reply_to = "ak:event:AXGvEEJkv6YPQvGdReHV-eLM-8ukvH7r9m8dCu3KWw36";
        let mut event = test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id },
            producer,
            station,
            2,
            Hlc::new("01970e589d22-0000-a13f9c2e").unwrap(),
            serde_json::json!({"body": "reply", "reply_to_id": reply_to}),
        )
        .unwrap();
        let prev = EventId::new("ak:event:AYnTVVCNBa4iXXbFlwzE8SaOYDUUHuMdVacBm9hSHVPf").unwrap();
        let after = EventId::new("ak:event:Acdo-DTSzgoY0Kjf-hvT52yy55O541hSJT4HQ50Z-P0p").unwrap();
        let causal = EventId::new("ak:event:ARoNVFTPC2MZwwVb9ic9nh5U7hzssLDzekdRvNaZQ-c7").unwrap();
        event.prev_refs = vec![prev.clone()];
        event.refs = vec![
            arkret_wire::EventRef::new(after.as_str(), "after"),
            // A non-`after` role is a semantic reference, not a timeline edge.
            arkret_wire::EventRef::new(
                "ak:event:AcZxEm5-56mhA6aajw4titG7O7lFxS6OUwHLDhdXvaEI",
                "authorized_by",
            ),
        ];
        event.causal_refs = vec![causal.event_digest()];

        let predecessors = timeline_predecessors(&event);
        assert_eq!(
            predecessors.event_ids,
            [prev, after, causal, EventId::new(reply_to).unwrap()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert!(predecessors.unresolvable_digests.is_empty());
    }

    #[test]
    fn a_genesis_event_has_no_timeline_predecessors() {
        let realm_id =
            RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs").unwrap();
        let station = actor("did:webvh:z6mkfixture:principal.example");
        let producer = actor("did:webvh:z6mkfixture:alice.example");
        let mut event = test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id },
            producer,
            station,
            1,
            Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            serde_json::json!({"body": "first"}),
        )
        .unwrap();
        event.prev_refs = vec![];
        assert!(timeline_predecessors(&event).is_empty());
    }

    #[test]
    fn an_absent_hlc_sorts_after_every_schema_valid_hlc() {
        let actor = ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:webvh:z6mkfixturealice".parse().unwrap(),
            "ak:did_core:webvh:z6mkfixturestation".parse().unwrap(),
        ));
        let key = |hlc: Option<&str>| TimelineOrderKey {
            causal_depth: 0,
            hlc: hlc.map(|hlc| Hlc::new(hlc).unwrap()),
            actor_id: actor.clone(),
            actor_seq: 1,
            event_id: EventId::new("ak:event:AXGvEEJkv6YPQvGdReHV-eLM-8ukvH7r9m8dCu3KWw36")
                .unwrap(),
        };
        // encoding.md 7.3 absent-last. The derived `Option` order would put the
        // absent key first and silently head every timeline window with it.
        let present = key(Some("01970e589d21-0000-a13f9c2e"));
        let absent = key(None);
        assert!(absent > present);
        let mut keys = [absent.clone(), present.clone()];
        keys.sort();
        assert_eq!(keys[0], present);
        assert_eq!(keys[1], absent);
        // A deeper causal depth still outranks the absent-HLC rule.
        let deeper = TimelineOrderKey {
            causal_depth: 1,
            ..key(Some("01970e589d21-0000-a13f9c2e"))
        };
        assert!(deeper > absent);
    }
}
