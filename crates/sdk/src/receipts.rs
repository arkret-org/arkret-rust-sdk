//! Read markers and read receipts.
//!
//! In addition to per-actor receipts and markers, this module hosts the
//! Space `ReadReceiptPolicy` typed model (component cell
//! `ck.component.space.read_receipt_policy.v1`) and the
//! `ReadReceiptPreferences` actor-private account-data model
//! (standard key `ck.read_receipt.preferences`). Together they implement
//! the disclosure / preference rules from spec
//! `discovery/read-receipts.md` §2.4-§2.5 and
//! `discovery/client-preferences.md` §3.6.
//!
//! Note: the `ck.flow.track.read_receipt_policy` cell was REMOVED in
//! cokret-spec revision `0a5ab85` (see
//! `cokret-spec/spec/v1/artifacts/registry/removed-event-kinds.json`).
//! Read receipts evaluate at the Space / child Space level only — create
//! a child Space if a discussion needs an independent boundary.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Did, EventId, FlowId, RealmId};

/// Read receipt visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVisibility {
    /// Visible to other members.
    Public,
    /// Private to this user/account.
    Private,
}

/// Read marker for one user in one space/thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarker {
    /// Space ID.
    pub space_id: RealmId,
    /// User DID.
    pub user_id: Did,
    /// Event ID considered read.
    pub event_id: EventId,
    /// Optional thread ID.
    pub thread_id: Option<String>,
    /// Update time.
    pub updated_at: DateTime<Utc>,
}

/// Read receipt event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceipt {
    /// Space ID.
    pub space_id: RealmId,
    /// User DID.
    pub user_id: Did,
    /// Event ID.
    pub event_id: EventId,
    /// Public or private receipt.
    pub visibility: ReceiptVisibility,
    /// Optional thread ID.
    pub thread_id: Option<String>,
    /// Receipt time.
    pub received_at: DateTime<Utc>,
}

/// Read receipt manager.
///
/// `dedup_window_ms` (default 1000 ms per `service-surface.md` §124)
/// controls the active de-duplication window. Calls to
/// [`Self::send_receipt`] within the window for the same
/// `(space_id, user_id, thread_id)` collapse into the existing receipt
/// instead of producing a new one.
#[derive(Clone, Debug)]
pub struct ReceiptManager {
    markers: BTreeMap<(RealmId, Did, Option<String>), ReadMarker>,
    receipts: BTreeMap<(RealmId, EventId, Option<String>), Vec<ReadReceipt>>,
    thread_index: BTreeSet<(RealmId, Option<String>)>,
    last_send_at: BTreeMap<(RealmId, Did, Option<String>), DateTime<Utc>>,
    dedup_window_ms: i64,
}

impl Default for ReceiptManager {
    fn default() -> Self {
        Self {
            markers: BTreeMap::new(),
            receipts: BTreeMap::new(),
            thread_index: BTreeSet::new(),
            last_send_at: BTreeMap::new(),
            dedup_window_ms: 1000,
        }
    }
}

impl ReceiptManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the active de-duplication window. Use a window of
    /// 0 ms to disable de-duplication entirely.
    pub fn with_dedup_window_ms(mut self, ms: i64) -> Self {
        self.dedup_window_ms = ms.max(0);
        self
    }

    /// Set a read marker.
    pub fn set_read_marker(
        &mut self,
        space_id: RealmId,
        user_id: Did,
        event_id: EventId,
        thread_id: Option<String>,
    ) -> ReadMarker {
        let marker = ReadMarker {
            space_id: space_id.clone(),
            user_id: user_id.clone(),
            event_id,
            thread_id: thread_id.clone(),
            updated_at: Utc::now(),
        };
        self.thread_index.insert((space_id.clone(), thread_id.clone()));
        self.markers.insert((space_id, user_id, thread_id), marker.clone());
        marker
    }

    /// Get a read marker.
    pub fn read_marker(
        &self,
        space_id: &RealmId,
        user_id: &Did,
        thread_id: Option<&str>,
    ) -> Option<&ReadMarker> {
        self.markers.get(&(space_id.clone(), user_id.clone(), thread_id.map(str::to_owned)))
    }

    /// Send/store a read receipt.
    ///
    /// Honors the active de-duplication window: when a receipt for the
    /// same `(space_id, user_id, thread_id)` was issued within the
    /// configured window, the new send is treated as a no-op and the
    /// existing latest receipt is returned. Set `dedup_window_ms = 0`
    /// to disable.
    pub fn send_receipt(
        &mut self,
        space_id: RealmId,
        user_id: Did,
        event_id: EventId,
        visibility: ReceiptVisibility,
        thread_id: Option<String>,
    ) -> ReadReceipt {
        let now = Utc::now();
        let dedup_key = (space_id.clone(), user_id.clone(), thread_id.clone());
        if self.dedup_window_ms > 0
            && let Some(prev) = self.last_send_at.get(&dedup_key)
            && now.signed_duration_since(*prev).num_milliseconds() < self.dedup_window_ms
            && let Some(latest) = self
                .receipts
                .get(&(space_id.clone(), event_id.clone(), thread_id.clone()))
                .and_then(|stack| stack.last())
        {
            return latest.clone();
        }
        let receipt = ReadReceipt {
            space_id: space_id.clone(),
            user_id,
            event_id: event_id.clone(),
            visibility,
            thread_id: thread_id.clone(),
            received_at: now,
        };
        self.thread_index.insert((space_id.clone(), thread_id.clone()));
        self.last_send_at.insert(dedup_key, now);
        self.receipts.entry((space_id, event_id, thread_id)).or_default().push(receipt.clone());
        receipt
    }

    /// Process a receipt received from sync.
    pub fn process_receipt(&mut self, receipt: ReadReceipt) {
        self.thread_index.insert((receipt.space_id.clone(), receipt.thread_id.clone()));
        self.receipts
            .entry((receipt.space_id.clone(), receipt.event_id.clone(), receipt.thread_id.clone()))
            .or_default()
            .push(receipt);
    }

    /// Receipts for one event/thread.
    pub fn receipts_for_event(
        &self,
        space_id: &RealmId,
        event_id: &EventId,
        thread_id: Option<&str>,
    ) -> Vec<&ReadReceipt> {
        self.receipts
            .get(&(space_id.clone(), event_id.clone(), thread_id.map(str::to_owned)))
            .map(|receipts| receipts.iter().collect())
            .unwrap_or_default()
    }

    /// Known thread positions for a space.
    pub fn thread_positions(&self, space_id: &RealmId) -> Vec<Option<String>> {
        self.thread_index
            .iter()
            .filter(|(candidate, _)| candidate == space_id)
            .map(|(_, thread_id)| thread_id.clone())
            .collect()
    }
}

// ─── Read Receipt disclosure policy (spec read-receipts.md §2.5) ────────

/// `disclosure` field of `ck.realm.read_receipt_policy`. Soft policy —
/// not cryptographically enforceable. Compliant clients honor `Required`
/// by sending and `Disabled` by suppressing; `Optional` defers to user
/// [`ReadReceiptPreferences`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadReceiptDisclosure {
    /// All compliant members SHOULD send `ck.receipt.read`. Client UI
    /// MUST lock the per-scope `send=false` toggle.
    Required,
    /// User preference decides. Default.
    #[default]
    Optional,
    /// Compliant clients MUST NOT generate; Sync Service MUST drop
    /// inbound `ck.receipt.read` for this scope.
    Disabled,
}

/// `visibility` field of `ReadReceiptPolicy`. Controls who Sync Service
/// fanouts `ck.receipt.read` to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadReceiptVisibility {
    /// All observers permitted by Space history visibility.
    Public,
    /// Space / child Space visible members. Default.
    #[default]
    Members,
    /// Only the original sender of the referenced event.
    Private,
}

/// Typed value of the read-receipt disclosure policy cell.
///
/// Carried only by the Space-level cell
/// `ck.component.space.read_receipt_policy.v1`. The Flow-track variant
/// (`ck.flow.track.read_receipt_policy`) was removed from spec
/// revision `0a5ab85`; create a child Space for an independent
/// disclosure boundary instead.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceiptPolicy {
    #[serde(default)]
    pub disclosure: ReadReceiptDisclosure,
    #[serde(default)]
    pub visibility: ReadReceiptVisibility,
}

// ─── Account-data preferences (client-preferences.md §3.6) ─────────────

/// One scope's worth of receipt-sending preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopePref {
    /// `None` = inherit (use the next layer up). `Some(true)` /
    /// `Some(false)` = explicit override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<bool>,
}

impl ScopePref {
    pub fn send(send: bool) -> Self {
        Self { send: Some(send) }
    }
}

/// Account-data value for `ck.read_receipt.preferences`.
///
/// Resolution order is (flow → space → default); the first non-`None`
/// `send` field wins.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceiptPreferences {
    #[serde(default)]
    pub default: ScopePref,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<RealmId, ScopePref>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flows: BTreeMap<FlowId, ScopePref>,
}

impl ReadReceiptPreferences {
    /// Standard account-data key.
    pub const ACCOUNT_DATA_KEY: &'static str = "ck.read_receipt.preferences";

    /// Effective `send` for a `(flow, space)` scope. If neither flow
    /// nor space declares an override, falls back to `default.send`,
    /// then to the protocol-wide default `true` (from spec §2.4 the
    /// global default sends receipts unless the user opts out).
    pub fn effective_send(&self, flow_id: Option<&FlowId>, space_id: Option<&RealmId>) -> bool {
        if let Some(fid) = flow_id
            && let Some(pref) = self.flows.get(fid)
            && let Some(send) = pref.send
        {
            return send;
        }
        if let Some(sid) = space_id
            && let Some(pref) = self.spaces.get(sid)
            && let Some(send) = pref.send
        {
            return send;
        }
        self.default.send.unwrap_or(true)
    }
}

/// Outcome of [`should_send_receipt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptDecision {
    /// User opted in (or default) AND policy is `Optional`/`Required`.
    Send,
    /// User opted out AND policy is `Optional` or absent.
    Skip,
    /// Space/Flow policy is `Required` — overrides any user preference.
    ForcedSend,
    /// Space/Flow policy is `Disabled` — overrides any user preference.
    ForcedSkip,
}

impl ReceiptDecision {
    /// `true` for [`Self::Send`] and [`Self::ForcedSend`].
    pub fn is_send(self) -> bool {
        matches!(self, Self::Send | Self::ForcedSend)
    }

    /// `true` when the decision is policy-locked and the UI MUST NOT
    /// allow the user to flip the per-scope toggle.
    pub fn is_locked(self) -> bool {
        matches!(self, Self::ForcedSend | Self::ForcedSkip)
    }
}

/// Compute whether to generate a `ck.receipt.read` for the given scope.
///
/// `policy` is the effective policy at the Space (or child Space)
/// boundary. Pass `None` to represent "no policy declared" (treated as
/// `ReadReceiptPolicy::default()` = `Optional` / `Members`).
pub fn should_send_receipt(
    prefs: &ReadReceiptPreferences,
    policy: Option<&ReadReceiptPolicy>,
    flow_id: Option<&FlowId>,
    space_id: Option<&RealmId>,
) -> ReceiptDecision {
    let disclosure = policy.map(|p| p.disclosure).unwrap_or_default();
    match disclosure {
        ReadReceiptDisclosure::Required => ReceiptDecision::ForcedSend,
        ReadReceiptDisclosure::Disabled => ReceiptDecision::ForcedSkip,
        ReadReceiptDisclosure::Optional => {
            if prefs.effective_send(flow_id, space_id) {
                ReceiptDecision::Send
            } else {
                ReceiptDecision::Skip
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn receipts_manage_markers_public_private_and_threads() {
        let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let event = EventId::new("ck:event:01904100-0000-7000-8000-834e21b98552").unwrap();
        let mut manager = ReceiptManager::new();

        manager.set_read_marker(
            space_id.clone(),
            alice.clone(),
            event.clone(),
            Some("t1".to_owned()),
        );
        assert!(manager.read_marker(&space_id, &alice, Some("t1")).is_some());

        manager.send_receipt(
            space_id.clone(),
            alice,
            event.clone(),
            ReceiptVisibility::Private,
            Some("t1".to_owned()),
        );
        manager.send_receipt(
            space_id.clone(),
            did("bob"),
            event.clone(),
            ReceiptVisibility::Public,
            Some("t1".to_owned()),
        );

        assert_eq!(manager.receipts_for_event(&space_id, &event, Some("t1")).len(), 2);
        assert_eq!(manager.thread_positions(&space_id), vec![Some("t1".to_owned())]);
    }

    fn space() -> RealmId {
        RealmId::new("ck:space:01904100-0000-7000-8000-906bb8c30a80").unwrap()
    }

    fn flow() -> FlowId {
        FlowId::new("ck:flow:01904100-0000-7000-8000-c1fe7e18f6fe").unwrap()
    }

    #[test]
    fn prefs_default_send_when_unset_is_true() {
        let prefs = ReadReceiptPreferences::default();
        assert!(prefs.effective_send(None, None));
    }

    #[test]
    fn prefs_explicit_default_overrides_protocol_default() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(false);
        assert!(!prefs.effective_send(None, None));
    }

    #[test]
    fn prefs_resolution_flow_overrides_space_overrides_default() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        prefs.spaces.insert(space(), ScopePref::send(false));
        prefs.flows.insert(flow(), ScopePref::send(true));

        // flow overrides space
        assert!(prefs.effective_send(Some(&flow()), Some(&space())));
        // space overrides default when no flow override
        assert!(!prefs.effective_send(None, Some(&space())));
        // default applies when nothing else matches
        let other_space = RealmId::new("ck:space:01904100-0000-7000-8000-de7b2d3c4472").unwrap();
        assert!(prefs.effective_send(None, Some(&other_space)));
    }

    #[test]
    fn should_send_required_forces_send_overrides_user() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(false);
        let policy =
            ReadReceiptPolicy { disclosure: ReadReceiptDisclosure::Required, ..Default::default() };
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::ForcedSend);
        assert!(decision.is_send());
        assert!(decision.is_locked());
    }

    #[test]
    fn should_send_disabled_forces_skip_overrides_user() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        let policy =
            ReadReceiptPolicy { disclosure: ReadReceiptDisclosure::Disabled, ..Default::default() };
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::ForcedSkip);
        assert!(!decision.is_send());
        assert!(decision.is_locked());
    }

    #[test]
    fn should_send_optional_defers_to_user_pref() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        let policy = ReadReceiptPolicy::default();
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::Send);
        assert!(!decision.is_locked());

        prefs.default.send = Some(false);
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::Skip);
    }

    #[test]
    fn should_send_no_policy_treats_as_optional() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        let decision = should_send_receipt(&prefs, None, None, None);
        assert_eq!(decision, ReceiptDecision::Send);
    }

    #[test]
    fn prefs_serde_roundtrip() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        prefs.spaces.insert(space(), ScopePref::send(false));
        let json = serde_json::to_string(&prefs).unwrap();
        // Empty `flows` map MUST be omitted by `skip_serializing_if`.
        assert!(!json.contains("\"flows\""));
        let back: ReadReceiptPreferences = serde_json::from_str(&json).unwrap();
        assert_eq!(back, prefs);
    }
}
