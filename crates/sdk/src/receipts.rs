//! Read markers and read receipts.
//!
//! In addition to per-actor receipts and markers, this module hosts the
//! Space / Flow `ReadReceiptPolicy` typed model (component cells
//! `cx.component.space.read_receipt_policy.v1` /
//! `cx.component.flow.track.read_receipt_policy.v1`) and the
//! `ReadReceiptPreferences` actor-private account-data model
//! (standard key `cx.read_receipt.preferences`). Together they implement
//! the disclosure / preference rules from spec
//! `discovery/read-receipts.md` §2.4-§2.5 and
//! `discovery/client-preferences.md` §3.6.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Did, EventId, FlowId, SpaceId};

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
    pub space_id: SpaceId,
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
    pub space_id: SpaceId,
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
    markers: BTreeMap<(SpaceId, Did, Option<String>), ReadMarker>,
    receipts: BTreeMap<(SpaceId, EventId, Option<String>), Vec<ReadReceipt>>,
    thread_index: BTreeSet<(SpaceId, Option<String>)>,
    last_send_at: BTreeMap<(SpaceId, Did, Option<String>), DateTime<Utc>>,
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
        space_id: SpaceId,
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
        space_id: &SpaceId,
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
        space_id: SpaceId,
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
        space_id: &SpaceId,
        event_id: &EventId,
        thread_id: Option<&str>,
    ) -> Vec<&ReadReceipt> {
        self.receipts
            .get(&(space_id.clone(), event_id.clone(), thread_id.map(str::to_owned)))
            .map(|receipts| receipts.iter().collect())
            .unwrap_or_default()
    }

    /// Known thread positions for a space.
    pub fn thread_positions(&self, space_id: &SpaceId) -> Vec<Option<String>> {
        self.thread_index
            .iter()
            .filter(|(candidate, _)| candidate == space_id)
            .map(|(_, thread_id)| thread_id.clone())
            .collect()
    }
}

// ─── Read Receipt disclosure policy (spec read-receipts.md §2.5) ────────

/// `disclosure` field of `cx.space.read_receipt_policy` /
/// `cx.flow.track.read_receipt_policy`. Soft policy — not cryptographically
/// enforceable. Compliant clients honor `Required` by sending and `Disabled`
/// by suppressing; `Optional` defers to user [`ReadReceiptPreferences`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadReceiptDisclosure {
    /// All compliant members SHOULD send `cx.receipt.read`. Client UI
    /// MUST lock the per-scope `send=false` toggle.
    Required,
    /// User preference decides. Default.
    Optional,
    /// Compliant clients MUST NOT generate; Sync Service MUST drop
    /// inbound `cx.receipt.read` for this scope.
    Disabled,
}

impl Default for ReadReceiptDisclosure {
    fn default() -> Self {
        Self::Optional
    }
}

/// `visibility` field of `ReadReceiptPolicy`. Controls who Sync Service
/// fanouts `cx.receipt.read` to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadReceiptVisibility {
    /// All observers permitted by Space history visibility.
    Public,
    /// Discussion branch members only. Default.
    Members,
    /// Only the original sender of the referenced event.
    Private,
}

impl Default for ReadReceiptVisibility {
    fn default() -> Self {
        Self::Members
    }
}

/// Typed value of the read-receipt disclosure policy cell. Same shape at
/// both Space and Flow-branch level; the cell id determines scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceiptPolicy {
    #[serde(default)]
    pub disclosure: ReadReceiptDisclosure,
    #[serde(default)]
    pub visibility: ReadReceiptVisibility,
    /// When `true`, a Flow-branch override MAY loosen the parent Space
    /// declaration. Default `true`. Tightening is always allowed.
    #[serde(default = "ReadReceiptPolicy::default_scope_overrides_allowed")]
    pub scope_overrides_allowed: bool,
}

impl ReadReceiptPolicy {
    fn default_scope_overrides_allowed() -> bool {
        true
    }

    /// Compose a Flow-track override on top of a parent Space policy.
    ///
    /// Returns the effective policy for the track, enforcing the
    /// "Track tightens but does not loosen" rule from spec §2.5. When
    /// the override would loosen and `scope_overrides_allowed=false`,
    /// the parent's value is preserved for that field.
    pub fn compose_track(parent: &Self, track: &Self) -> Self {
        Self {
            disclosure: tighten_disclosure(
                parent.disclosure,
                track.disclosure,
                parent.scope_overrides_allowed,
            ),
            visibility: tighten_visibility(
                parent.visibility,
                track.visibility,
                parent.scope_overrides_allowed,
            ),
            scope_overrides_allowed: parent.scope_overrides_allowed,
        }
    }
}

impl Default for ReadReceiptPolicy {
    fn default() -> Self {
        Self {
            disclosure: ReadReceiptDisclosure::default(),
            visibility: ReadReceiptVisibility::default(),
            scope_overrides_allowed: Self::default_scope_overrides_allowed(),
        }
    }
}

/// Strictness order for `disclosure`: `Required > Optional > Disabled`
/// is NOT a total order on a single axis (`Required` forces send,
/// `Disabled` forbids send, `Optional` defers). For the track override
/// we treat any move *toward* a stricter answer (`Optional`→`Required`
/// is a tightening because it removes the user's right to opt out;
/// `Optional`→`Disabled` is also a tightening because it forbids what
/// was previously optional). Loosening (`Required`→`Optional`,
/// `Disabled`→`Optional`, or `Required`↔`Disabled`) requires
/// `scope_overrides_allowed=true`.
fn tighten_disclosure(
    parent: ReadReceiptDisclosure,
    track: ReadReceiptDisclosure,
    overrides_allowed: bool,
) -> ReadReceiptDisclosure {
    use ReadReceiptDisclosure::*;
    let is_tighter = matches!(
        (parent, track),
        (Optional, Required) | (Optional, Disabled)
    );
    if is_tighter || overrides_allowed {
        track
    } else {
        parent
    }
}

/// `Public > Members > Private` (more disclosure → less strict).
/// Track may always tighten by reducing the audience.
fn tighten_visibility(
    parent: ReadReceiptVisibility,
    track: ReadReceiptVisibility,
    overrides_allowed: bool,
) -> ReadReceiptVisibility {
    use ReadReceiptVisibility::*;
    let parent_rank = match parent {
        Public => 2,
        Members => 1,
        Private => 0,
    };
    let track_rank = match track {
        Public => 2,
        Members => 1,
        Private => 0,
    };
    if track_rank <= parent_rank || overrides_allowed {
        track
    } else {
        parent
    }
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

/// Account-data value for `cx.read_receipt.preferences`.
///
/// Resolution order is (flow → space → default); the first non-`None`
/// `send` field wins.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceiptPreferences {
    #[serde(default)]
    pub default: ScopePref,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<SpaceId, ScopePref>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flows: BTreeMap<FlowId, ScopePref>,
}

impl ReadReceiptPreferences {
    /// Standard account-data key.
    pub const ACCOUNT_DATA_KEY: &'static str = "cx.read_receipt.preferences";

    /// Effective `send` for a `(flow, space)` scope. If neither flow
    /// nor space declares an override, falls back to `default.send`,
    /// then to the protocol-wide default `true` (from spec §2.4 the
    /// global default sends receipts unless the user opts out).
    pub fn effective_send(&self, flow_id: Option<&FlowId>, space_id: Option<&SpaceId>) -> bool {
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

/// Compute whether to generate a `cx.receipt.read` for the given scope.
///
/// `policy` is the effective policy at the scope (already composed via
/// [`ReadReceiptPolicy::compose_track`] for tracks). Pass `None` to
/// represent "no policy declared" (treated as
/// `ReadReceiptPolicy::default()` = `Optional` / `Members`).
pub fn should_send_receipt(
    prefs: &ReadReceiptPreferences,
    policy: Option<&ReadReceiptPolicy>,
    flow_id: Option<&FlowId>,
    space_id: Option<&SpaceId>,
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
        let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap();
        let alice = did("alice");
        let event = EventId::new("cx:event:01").unwrap();
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

    fn space() -> SpaceId {
        SpaceId::new("cx:space:01JS0SP00000000000000RR000").unwrap()
    }

    fn flow() -> FlowId {
        FlowId::new("cx:flow:01JS1FL00000000000000RR000").unwrap()
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
        let other_space = SpaceId::new("cx:space:01JS0SP00000000000000XX000").unwrap();
        assert!(prefs.effective_send(None, Some(&other_space)));
    }

    #[test]
    fn should_send_required_forces_send_overrides_user() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(false);
        let policy = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Required,
            ..Default::default()
        };
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::ForcedSend);
        assert!(decision.is_send());
        assert!(decision.is_locked());
    }

    #[test]
    fn should_send_disabled_forces_skip_overrides_user() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        let policy = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Disabled,
            ..Default::default()
        };
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
    fn compose_track_tightens_disclosure_without_overrides_allowed() {
        // Parent Optional → track Required is a tightening (forces send),
        // allowed even without scope_overrides_allowed.
        let parent = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Optional,
            visibility: ReadReceiptVisibility::Members,
            scope_overrides_allowed: false,
        };
        let track = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Required,
            visibility: ReadReceiptVisibility::Private,
            scope_overrides_allowed: false,
        };
        let composed = ReadReceiptPolicy::compose_track(&parent, &track);
        assert_eq!(composed.disclosure, ReadReceiptDisclosure::Required);
        // Members → Private is also tighter (Private < Members < Public).
        assert_eq!(composed.visibility, ReadReceiptVisibility::Private);
    }

    #[test]
    fn compose_track_blocks_loosening_when_overrides_disallowed() {
        // Parent Required → track Optional is loosening; blocked.
        let parent = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Required,
            visibility: ReadReceiptVisibility::Private,
            scope_overrides_allowed: false,
        };
        let track = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Optional,
            visibility: ReadReceiptVisibility::Public,
            scope_overrides_allowed: false,
        };
        let composed = ReadReceiptPolicy::compose_track(&parent, &track);
        assert_eq!(composed.disclosure, ReadReceiptDisclosure::Required);
        assert_eq!(composed.visibility, ReadReceiptVisibility::Private);
    }

    #[test]
    fn compose_track_allows_loosening_when_overrides_allowed() {
        let parent = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Required,
            visibility: ReadReceiptVisibility::Private,
            scope_overrides_allowed: true,
        };
        let track = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Optional,
            visibility: ReadReceiptVisibility::Public,
            scope_overrides_allowed: true,
        };
        let composed = ReadReceiptPolicy::compose_track(&parent, &track);
        assert_eq!(composed.disclosure, ReadReceiptDisclosure::Optional);
        assert_eq!(composed.visibility, ReadReceiptVisibility::Public);
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
