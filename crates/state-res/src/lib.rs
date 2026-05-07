//! Deterministic Contrix state resolution primitives.
//!
//! The reducer in this crate focuses on protocol state events: stable ordering,
//! state-key extraction, conflict recording, frontier maintenance and snapshot
//! hashing. Product projections can build richer materialized views on top.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use contrix_core::{
    DeviceId, Did, EntityId, Error, Event, EventId, Hlc, Result, SpaceId, canonical,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedStateEvent {
    pub kind: String,
    /// State slot subject derived from the event's typed payload per the
    /// schema registry's `state_subject_field`. Empty string for singleton
    /// state events whose slot key is `(space_id, kind)` only. Spec Phase 1
    /// (2026-05-07) removed the envelope `state_key` field entirely; this
    /// is now reducer-internal subject, not a wire field.
    pub subject: String,
    pub source_event_id: EventId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: Hlc,
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub key: String,
    pub winner_event_id: EventId,
    pub loser_event_id: EventId,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateResolutionSnapshot {
    pub space_id: SpaceId,
    pub space_version: String,
    pub frontier: Vec<EventId>,
    pub resolved_state: BTreeMap<String, ResolvedStateEvent>,
    pub state_hash: String,
    pub created_at: DateTime<Utc>,
}

impl StateResolutionSnapshot {
    pub fn verify(&self) -> Result<()> {
        let expected =
            state_hash(&self.space_id, &self.space_version, &self.frontier, &self.resolved_state)?;
        if expected == self.state_hash {
            Ok(())
        } else {
            Err(Error::Protocol("state resolution snapshot hash mismatch".to_owned()))
        }
    }

    pub fn delta_from(&self, previous: &StateResolutionSnapshot) -> Result<StateResolutionDelta> {
        self.verify()?;
        previous.verify()?;
        if self.space_id != previous.space_id {
            return Err(Error::Protocol("state snapshot delta space mismatch".to_owned()));
        }
        let changed = self
            .resolved_state
            .iter()
            .filter(|(key, value)| previous.resolved_state.get(*key) != Some(*value))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let removed = previous
            .resolved_state
            .keys()
            .filter(|key| !self.resolved_state.contains_key(*key))
            .cloned()
            .collect();
        Ok(StateResolutionDelta {
            space_id: self.space_id.clone(),
            from_state_hash: previous.state_hash.clone(),
            to_state_hash: self.state_hash.clone(),
            frontier: self.frontier.clone(),
            changed,
            removed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateResolutionDelta {
    pub space_id: SpaceId,
    pub from_state_hash: String,
    pub to_state_hash: String,
    pub frontier: Vec<EventId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub changed: BTreeMap<String, ResolvedStateEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
}

impl StateResolutionDelta {
    pub fn verify_transition(
        &self,
        previous: &StateResolutionSnapshot,
        next: &StateResolutionSnapshot,
    ) -> Result<()> {
        if self.from_state_hash != previous.state_hash || self.to_state_hash != next.state_hash {
            return Err(Error::Protocol("state delta hash boundary mismatch".to_owned()));
        }
        let expected = next.delta_from(previous)?;
        if &expected == self {
            Ok(())
        } else {
            Err(Error::Protocol("state delta does not match snapshot transition".to_owned()))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshotProof {
    pub space_id: SpaceId,
    pub space_version: String,
    pub state_hash: String,
    pub frontier_hash: String,
    pub state_event_count: usize,
    pub frontier_count: usize,
    pub conflict_count: usize,
}

impl StateSnapshotProof {
    pub fn from_snapshot(
        snapshot: &StateResolutionSnapshot,
        conflict_count: usize,
    ) -> Result<Self> {
        snapshot.verify()?;
        Ok(Self {
            space_id: snapshot.space_id.clone(),
            space_version: snapshot.space_version.clone(),
            state_hash: snapshot.state_hash.clone(),
            frontier_hash: canonical::canonical_sha256(&snapshot.frontier)?,
            state_event_count: snapshot.resolved_state.len(),
            frontier_count: snapshot.frontier.len(),
            conflict_count,
        })
    }

    pub fn verify_snapshot(&self, snapshot: &StateResolutionSnapshot) -> Result<()> {
        snapshot.verify()?;
        let frontier_hash = canonical::canonical_sha256(&snapshot.frontier)?;
        if self.space_id == snapshot.space_id
            && self.space_version == snapshot.space_version
            && self.state_hash == snapshot.state_hash
            && self.frontier_hash == frontier_hash
            && self.state_event_count == snapshot.resolved_state.len()
            && self.frontier_count == snapshot.frontier.len()
        {
            Ok(())
        } else {
            Err(Error::Protocol("state snapshot proof mismatch".to_owned()))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictGraph {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub nodes: BTreeSet<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<ConflictEdge>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictEdge {
    pub key: String,
    pub winner_event_id: EventId,
    pub loser_event_id: EventId,
    pub reason: String,
}

impl ConflictGraph {
    pub fn from_conflicts(conflicts: &[ConflictRecord]) -> Self {
        let mut nodes = BTreeSet::new();
        let edges = conflicts
            .iter()
            .map(|conflict| {
                nodes.insert(conflict.winner_event_id.clone());
                nodes.insert(conflict.loser_event_id.clone());
                ConflictEdge {
                    key: conflict.key.clone(),
                    winner_event_id: conflict.winner_event_id.clone(),
                    loser_event_id: conflict.loser_event_id.clone(),
                    reason: conflict.reason.clone(),
                }
            })
            .collect();
        Self { nodes, edges }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateAuthority {
    Creator,
    Admin,
    Member,
    Device,
    Server,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAuthContext {
    pub creator: Did,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub admins: BTreeSet<Did>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub members: BTreeSet<Did>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub server_dids: BTreeSet<Did>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_owners: BTreeMap<DeviceId, Did>,
}

impl StateAuthContext {
    pub fn granted_authorities(&self, event: &Event) -> BTreeSet<StateAuthority> {
        let mut granted = BTreeSet::new();
        if event.actor_id == self.creator {
            granted.insert(StateAuthority::Creator);
            granted.insert(StateAuthority::Admin);
            granted.insert(StateAuthority::Member);
        }
        if self.admins.contains(&event.actor_id) {
            granted.insert(StateAuthority::Admin);
            granted.insert(StateAuthority::Member);
        }
        if self.members.contains(&event.actor_id) {
            granted.insert(StateAuthority::Member);
        }
        if self.server_dids.contains(&event.actor_id) {
            granted.insert(StateAuthority::Server);
        }
        if let Some(device_id) = optional_field::<DeviceId>(&event.content, "device_id")
            && self.device_owners.get(&device_id) == Some(&event.actor_id)
        {
            granted.insert(StateAuthority::Device);
        }
        granted
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAuthDecision {
    pub allowed: bool,
    pub required: StateAuthority,
    pub granted: BTreeSet<StateAuthority>,
    pub reason: String,
}

pub fn evaluate_state_auth(event: &Event, context: &StateAuthContext) -> StateAuthDecision {
    let required = required_authority_for_event(event);
    let granted = context.granted_authorities(event);
    let allowed = authority_satisfies(required, &granted);
    let reason = if allowed {
        format!("event '{}' satisfies required {:?} authority", event.kind, required)
    } else {
        format!("event '{}' is missing required {:?} authority", event.kind, required)
    };
    StateAuthDecision { allowed, required, granted, reason }
}

pub fn required_authority_for_event(event: &Event) -> StateAuthority {
    match event.kind.as_str() {
        "cx.space.create" => StateAuthority::Creator,
        "cx.federation.state" | "cx.federation.backfill" => StateAuthority::Server,
        "cx.read.marker" | "cx.state.read_marker" => StateAuthority::Device,
        "cx.state.membership" | "cx.member.state" => required_membership_authority(event),
        "cx.state.power_levels"
        | "cx.state.capabilities"
        | "cx.state.policy"
        | "cx.space.policy"
        | "cx.policy.set"
        | "cx.space.archive"
        | "cx.space.freeze"
        | "cx.space.destroy" => StateAuthority::Admin,
        _ if is_state_event(event) => StateAuthority::Member,
        _ => StateAuthority::Member,
    }
}

fn required_membership_authority(event: &Event) -> StateAuthority {
    let target = optional_field::<String>(&event.content, "principal_id")
        .or_else(|| optional_field::<String>(&event.content, "member_id"))
        .or_else(|| optional_field::<String>(&event.content, "user_id"));
    let membership = optional_field::<String>(&event.content, "membership")
        .or_else(|| optional_field::<String>(&event.content, "state"));
    if target.as_deref() == Some(event.actor_id.as_str())
        && matches!(membership.as_deref(), Some("join" | "leave" | "knock"))
    {
        StateAuthority::Member
    } else {
        StateAuthority::Admin
    }
}

fn authority_satisfies(required: StateAuthority, granted: &BTreeSet<StateAuthority>) -> bool {
    match required {
        StateAuthority::Creator => granted.contains(&StateAuthority::Creator),
        StateAuthority::Admin => {
            granted.contains(&StateAuthority::Creator) || granted.contains(&StateAuthority::Admin)
        }
        StateAuthority::Member => {
            granted.contains(&StateAuthority::Creator)
                || granted.contains(&StateAuthority::Admin)
                || granted.contains(&StateAuthority::Member)
        }
        StateAuthority::Device => granted.contains(&StateAuthority::Device),
        StateAuthority::Server => granted.contains(&StateAuthority::Server),
    }
}

#[derive(Clone, Debug)]
pub struct StateReducer {
    pub space_id: SpaceId,
    pub space_version: String,
    pub resolved_state: BTreeMap<String, ResolvedStateEvent>,
    pub conflict_records: Vec<ConflictRecord>,
    pub frontier: Vec<EventId>,
    processed_events: BTreeMap<EventId, Event>,
}

impl StateReducer {
    pub fn new(space_id: SpaceId, space_version: impl Into<String>) -> Self {
        Self {
            space_id,
            space_version: space_version.into(),
            resolved_state: BTreeMap::new(),
            conflict_records: Vec::new(),
            frontier: Vec::new(),
            processed_events: BTreeMap::new(),
        }
    }

    pub fn apply_events(&mut self, events: &[Event]) -> Result<()> {
        let mut event_index = self.processed_events.clone();
        for event in events {
            event_index.insert(event.event_id.clone(), event.clone());
        }

        let mut sorted_events: Vec<&Event> = events.iter().collect();
        sorted_events.sort_by(|a, b| {
            causal_depth_from_index(a, &event_index)
                .cmp(&causal_depth_from_index(b, &event_index))
                .then_with(|| a.hlc.cmp(&b.hlc))
                .then_with(|| a.actor_id.as_str().cmp(b.actor_id.as_str()))
                .then_with(|| a.actor_seq.cmp(&b.actor_seq))
                .then_with(|| a.event_id.as_str().cmp(b.event_id.as_str()))
        });

        for event in sorted_events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        if self.processed_events.contains_key(&event.event_id) {
            return Ok(());
        }
        if event.space_id != self.space_id {
            return Err(Error::Protocol(format!(
                "event space '{}' does not match reducer space '{}'",
                event.space_id, self.space_id
            )));
        }
        for prev_ref in &event.prev_refs {
            if !self.processed_events.contains_key(prev_ref) {
                return Err(Error::Protocol(format!("missing causal dependency: {}", prev_ref)));
            }
        }

        if let Some(candidate) = candidate_from_event(event)? {
            self.reduce_candidate(candidate);
        }
        self.processed_events.insert(event.event_id.clone(), event.clone());
        self.update_frontier(event);
        Ok(())
    }

    pub fn snapshot(&self) -> Result<StateResolutionSnapshot> {
        let state_hash =
            state_hash(&self.space_id, &self.space_version, &self.frontier, &self.resolved_state)?;
        Ok(StateResolutionSnapshot {
            space_id: self.space_id.clone(),
            space_version: self.space_version.clone(),
            frontier: self.frontier.clone(),
            resolved_state: self.resolved_state.clone(),
            state_hash,
            created_at: Utc::now(),
        })
    }

    pub fn snapshot_proof(&self) -> Result<StateSnapshotProof> {
        StateSnapshotProof::from_snapshot(&self.snapshot()?, self.conflict_records.len())
    }

    pub fn conflict_graph(&self) -> ConflictGraph {
        ConflictGraph::from_conflicts(&self.conflict_records)
    }

    fn reduce_candidate(&mut self, candidate: ResolvedStateEvent) {
        let map_key = state_slot_key(&candidate.kind, &candidate.subject);
        match self.resolved_state.get(&map_key) {
            Some(existing) if !candidate_wins(existing, &candidate) => {
                self.conflict_records.push(ConflictRecord {
                    key: map_key,
                    winner_event_id: existing.source_event_id.clone(),
                    loser_event_id: candidate.source_event_id,
                    reason: "existing state wins deterministic reducer order".to_owned(),
                });
            }
            Some(existing) => {
                let loser_event_id = existing.source_event_id.clone();
                self.conflict_records.push(ConflictRecord {
                    key: map_key.clone(),
                    winner_event_id: candidate.source_event_id.clone(),
                    loser_event_id,
                    reason: "candidate state wins deterministic reducer order".to_owned(),
                });
                self.resolved_state.insert(map_key, candidate);
            }
            None => {
                self.resolved_state.insert(map_key, candidate);
            }
        }
    }

    fn update_frontier(&mut self, event: &Event) {
        let prev_refs: BTreeSet<EventId> = event.prev_refs.iter().cloned().collect();
        self.frontier.retain(|frontier_event| !prev_refs.contains(frontier_event));
        if !self.frontier.contains(&event.event_id) {
            self.frontier.push(event.event_id.clone());
        }
        self.frontier.sort();
    }
}

pub fn candidate_from_event(event: &Event) -> Result<Option<ResolvedStateEvent>> {
    if !is_state_event(event) {
        return Ok(None);
    }
    let subject = subject_for_event(event)?;
    Ok(Some(ResolvedStateEvent {
        kind: event.kind.clone(),
        subject,
        source_event_id: event.event_id.clone(),
        actor_id: event.actor_id.clone(),
        actor_seq: event.actor_seq,
        hlc: event.hlc.clone(),
        content: event.content.clone(),
    }))
}

pub fn is_state_event(event: &Event) -> bool {
    event.kind.starts_with("cx.state.")
        || matches!(
            event.kind.as_str(),
            // membership
            "cx.member.state"
                | "cx.flow.branch.member"
                | "cx.flow.branch.history_visibility"
                | "cx.flow.branch.policy_components"
            // capability (grant/revoke share slot via grant_id; delegate/derived have own slot)
                | "cx.capability.grant"
                | "cx.capability.delegate"
                | "cx.capability.revoke"
                | "cx.capability.derived"
            // policy
                | "cx.policy.set"
                | "cx.policy.rule"
            // invite
                | "cx.invite.create"
                | "cx.invite.cancel"
                | "cx.invite.accept"
            // read marker
                | "cx.read.marker"
            // space lifecycle / structure
                | "cx.space.create"
                | "cx.space.update"
                | "cx.space.organization"
                | "cx.space.upgrade"
                | "cx.space.child"
                | "cx.space.parent"
            // per-facet space policy state events (Phase 1: replaced cx.space.policy.set)
                | "cx.space.policy"
                | "cx.space.join_rule"
                | "cx.space.history_visibility"
                | "cx.space.discovery"
                | "cx.space.policy_server"
                | "cx.space.policy_components"
                | "cx.space.history_sharing_policy"
                | "cx.space.asset_privacy_policy"
                | "cx.space.moderation_policy"
                | "cx.space.plaintext_visible_services"
                | "cx.space.media_service"
                | "cx.space.schema"
                | "cx.space.inheritance_policy"
            // per-facet space lifecycle (Phase 1: replaced cx.space.lifecycle.set)
                | "cx.space.archive"
                | "cx.space.freeze"
                | "cx.space.tombstone"
                | "cx.space.destroy"
            // hub-writer (Phase 4)
                | "cx.space.host"
                | "cx.space.host.transfer"
            // consent (Phase 5)
                | "cx.consent.grant"
                | "cx.consent.revoke"
            // device / session / account state
                | "cx.device.authorized"
                | "cx.device.revoked"
                | "cx.device.list_update"
                | "cx.session.grant"
                | "cx.account.status"
            // profile state (create/update share slot via payload.object.id / payload.target_ref)
                | "cx.profile.create"
                | "cx.profile.update"
            // mimi room binding
                | "cx.mimi.room_binding"
            // view state
                | "cx.view.create"
                | "cx.view.update"
                | "cx.view.reconcile"
            // flow lifecycle / structure
                | "cx.flow.create"
                | "cx.flow.update"
                | "cx.flow.archive"
                | "cx.flow.restore"
                | "cx.flow.link_surface"
                | "cx.flow.unlink_surface"
                | "cx.flow.set_primary_surface"
        )
}

/// Derive the state slot subject for an event according to the schema
/// registry's `state_subject_field` rules (spec Phase 1 §4.3).
///
/// Returns the empty string for singleton state events whose slot key is
/// `(space_id, kind)` only. Returns a non-empty subject string for
/// per_subject events; composite subjects are joined via `|` (an in-memory
/// canonical form — wire form is the base64url(sha256(canonical_json([...])))
/// derived by [`contrix_core::canonical::encode_state_subject`]).
///
/// **No fallback to `payload.state_key`**: spec Phase 1 removed the envelope
/// `state_key` field entirely, and writers MUST NOT carry it through payload
/// either. Older events that still ship a `payload.state_key` field are
/// rejected here as `Protocol("legacy state_key field on event payload — \
/// spec Phase 1 requires typed subject fields")`.
pub fn subject_for_event(event: &Event) -> Result<String> {
    if optional_field::<String>(&event.content, "state_key").is_some() {
        return Err(Error::Protocol(
            "legacy state_key field on event payload — spec Phase 1 requires typed subject fields"
                .to_owned(),
        ));
    }

    match event.kind.as_str() {
        // ── per_subject by payload.actor_id ────────────────────────────
        "cx.member.state" | "cx.state.membership" => {
            optional_field::<String>(&event.content, "actor_id")
                .or_else(|| optional_field::<String>(&event.content, "principal_id"))
                .or_else(|| optional_field::<String>(&event.content, "member_id"))
                .or_else(|| optional_field::<String>(&event.content, "user_id"))
                .ok_or_else(|| Error::Protocol("member state requires payload.actor_id".to_owned()))
        }
        // ── flow.branch.member: composite (flow_id, branch, actor_id) ─
        "cx.flow.branch.member" => composite_subject(event, &["flow_id", "branch", "actor_id"]),
        "cx.flow.branch.history_visibility" | "cx.flow.branch.policy_components" => {
            composite_subject(event, &["flow_id", "branch"])
        }
        // ── per_subject by payload.grant_id (revoke shares grant slot) ─
        "cx.capability.grant"
        | "cx.capability.delegate"
        | "cx.capability.revoke"
        | "cx.capability.derived" => optional_field::<String>(&event.content, "grant_id")
            .or_else(|| optional_field::<String>(&event.content, "capability_id"))
            .or_else(|| optional_field::<String>(&event.content, "target_capability_id"))
            .or_else(|| optional_field::<String>(&event.content, "id"))
            .ok_or_else(|| Error::Protocol("capability event requires payload.grant_id".to_owned())),
        // ── policy ────────────────────────────────────────────────────
        "cx.policy.set" | "cx.state.policy" => Ok(optional_field::<String>(
            &event.content,
            "policy_id",
        )
        .unwrap_or_else(|| "space_policy".to_owned())),
        "cx.policy.rule" => optional_field::<String>(&event.content, "rule_id")
            .ok_or_else(|| Error::Protocol("policy rule requires payload.rule_id".to_owned())),
        // ── invite ────────────────────────────────────────────────────
        "cx.invite.create" | "cx.invite.cancel" | "cx.invite.accept" => {
            optional_field::<String>(&event.content, "invite_id")
                .or_else(|| optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("invite event requires payload.invite_id".to_owned()))
        }
        // ── flow surface ──────────────────────────────────────────────
        "cx.flow.link_surface" | "cx.flow.unlink_surface" | "cx.flow.set_primary_surface" => {
            optional_field::<String>(&event.content, "relation_id")
                .or_else(|| {
                    let flow_id = optional_field::<String>(&event.content, "flow_id")
                        .map(|value| canonicalize_flow_ref(&value))
                        .or_else(|| {
                            optional_field::<String>(&event.content, "id")
                                .map(|value| canonicalize_flow_ref(&value))
                        })?;
                    let surface_ref = optional_field::<String>(&event.content, "surface_ref")?;
                    let surface_role = optional_field::<String>(&event.content, "surface_role")
                        .unwrap_or_else(|| "*".to_owned());
                    Some(format!("{flow_id}|{surface_ref}|{surface_role}"))
                })
                .ok_or_else(|| {
                    Error::Protocol("flow surface event requires a state key".to_owned())
                })
        }
        "cx.flow.create" | "cx.flow.update" | "cx.flow.archive" | "cx.flow.restore" => {
            optional_field::<String>(&event.content, "flow_id")
                .map(|value| canonicalize_flow_ref(&value))
                .or_else(|| {
                    optional_field::<String>(&event.content, "id")
                        .map(|value| canonicalize_flow_ref(&value))
                })
                .ok_or_else(|| Error::Protocol("flow event requires a state key".to_owned()))
        }
        "cx.read.marker" | "cx.state.read_marker" => {
            optional_field::<String>(&event.content, "scope")
                .or_else(|| optional_field::<String>(&event.content, "target_ref"))
                .ok_or_else(|| Error::Protocol("read marker requires a state key".to_owned()))
        }
        // ── space child / parent: per_subject by other-space id ───────
        "cx.space.child" => optional_field::<String>(&event.content, "child_space_id")
            .ok_or_else(|| Error::Protocol("cx.space.child requires payload.child_space_id".to_owned())),
        "cx.space.parent" => optional_field::<String>(&event.content, "parent_space_id")
            .ok_or_else(|| Error::Protocol("cx.space.parent requires payload.parent_space_id".to_owned())),
        // ── space inheritance: per_subject by parent_space_id ─────────
        "cx.space.inheritance_policy" => optional_field::<String>(&event.content, "parent_space_id")
            .ok_or_else(|| {
                Error::Protocol(
                    "cx.space.inheritance_policy requires payload.parent_space_id".to_owned(),
                )
            }),
        // ── space upgrade: per_subject by target_reducer_profile ──────
        "cx.space.upgrade" => optional_field::<String>(&event.content, "target_reducer_profile")
            .ok_or_else(|| {
                Error::Protocol(
                    "cx.space.upgrade requires payload.target_reducer_profile".to_owned(),
                )
            }),
        // ── consent: per_subject by consent_id (revoke shares slot) ───
        "cx.consent.grant" | "cx.consent.revoke" => {
            optional_field::<String>(&event.content, "consent_id").ok_or_else(|| {
                Error::Protocol("consent event requires payload.consent_id".to_owned())
            })
        }
        // ── host transfer: per_subject by transfer_id ─────────────────
        "cx.space.host.transfer" => optional_field::<String>(&event.content, "transfer_id")
            .ok_or_else(|| {
                Error::Protocol(
                    "cx.space.host.transfer requires payload.transfer_id".to_owned(),
                )
            }),
        // ── mimi room binding: per_subject by mimi_room_uri ───────────
        "cx.mimi.room_binding" => optional_field::<String>(&event.content, "mimi_room_uri")
            .ok_or_else(|| {
                Error::Protocol(
                    "cx.mimi.room_binding requires payload.mimi_room_uri".to_owned(),
                )
            }),
        // ── profile create/update: per_subject by actor_profile id ────
        "cx.profile.create" => {
            // payload.object.id is the canonical subject for create
            event
                .content
                .get("object")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::Protocol(
                        "cx.profile.create requires payload.object.id".to_owned(),
                    )
                })
        }
        "cx.profile.update" => optional_field::<String>(&event.content, "target_ref").ok_or_else(
            || Error::Protocol("cx.profile.update requires payload.target_ref".to_owned()),
        ),
        // ── device authorized/revoked: composite (principal_id, device_id) ─
        "cx.device.authorized" | "cx.device.revoked" => {
            composite_subject(event, &["principal_id", "device_id"])
        }
        "cx.device.list_update" | "cx.account.status" => {
            optional_field::<String>(&event.content, "principal_id").ok_or_else(|| {
                Error::Protocol(
                    "device list / account status requires payload.principal_id".to_owned(),
                )
            })
        }
        "cx.session.grant" => optional_field::<String>(&event.content, "grant_id")
            .ok_or_else(|| Error::Protocol("cx.session.grant requires payload.grant_id".to_owned())),
        // ── view state ────────────────────────────────────────────────
        "cx.view.create" | "cx.view.update" | "cx.view.reconcile" => {
            optional_field::<String>(&event.content, "view_id")
                .or_else(|| {
                    event
                        .content
                        .get("object")
                        .and_then(|v| v.get("id"))
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                })
                .ok_or_else(|| Error::Protocol("view event requires payload.view_id".to_owned()))
        }
        // ── singleton: slot keyed by (space_id, kind) only ────────────
        "cx.space.create"
        | "cx.space.update"
        | "cx.space.organization"
        | "cx.space.policy"
        | "cx.space.join_rule"
        | "cx.space.history_visibility"
        | "cx.space.discovery"
        | "cx.space.policy_server"
        | "cx.space.policy_components"
        | "cx.space.history_sharing_policy"
        | "cx.space.asset_privacy_policy"
        | "cx.space.moderation_policy"
        | "cx.space.plaintext_visible_services"
        | "cx.space.media_service"
        | "cx.space.schema"
        | "cx.space.archive"
        | "cx.space.freeze"
        | "cx.space.tombstone"
        | "cx.space.destroy"
        | "cx.space.host"
        | "cx.state.power_levels"
        | "cx.state.capabilities"
        | "cx.state.tags"
        | "cx.state.pinned_events"
        | "cx.state.topic"
        | "cx.state.name"
        | "cx.state.avatar"
        | "cx.state.notification_settings" => Ok(event.space_id.as_str().to_owned()),
        _ if event.kind.starts_with("cx.state.") => Ok(event.space_id.as_str().to_owned()),
        _ => Ok(String::new()),
    }
}

/// Combine multiple payload string fields into a composite subject (e.g.
/// `(flow_id, branch, actor_id)`). The wire-canonical form is
/// base64url(sha256(canonical_json([components]))) per spec encoding §9.5;
/// the reducer-internal form uses `|` separation since reducers operate on
/// the typed values, not the wire hash.
fn composite_subject(event: &Event, fields: &[&str]) -> Result<String> {
    let mut parts = Vec::with_capacity(fields.len());
    for field in fields {
        let value = optional_field::<String>(&event.content, field).ok_or_else(|| {
            Error::Protocol(format!(
                "{} requires payload.{}",
                event.kind.as_str(),
                field
            ))
        })?;
        parts.push(value);
    }
    Ok(parts.join("|"))
}

/// Compose the canonical reducer state slot key for an `(kind, subject)`
/// pair. Multiple kinds that operate on the same logical state slot
/// (paired kinds with `component_slot_alias_of` declared in the schema
/// registry) collapse to the same family prefix, so the reducer treats
/// `cx.capability.grant` / `cx.capability.revoke` etc. as one slot.
///
/// Spec Phase 1 (2026-05-07) renamed `state_key` to `subject` everywhere;
/// this function is the canonical name. Singleton state slots take the
/// empty subject and produce keys like `"cx.space.media_service|"`.
pub fn state_slot_key(kind: &str, subject: &str) -> String {
    let family = match kind {
        // capability grant + revoke share state slot via payload.grant_id
        "cx.capability.grant" | "cx.capability.revoke" => "cx.capability.grant",
        "cx.capability.delegate" => "cx.capability.delegate",
        "cx.capability.derived" => "cx.capability.derived",
        // invite slot keyed by invite_id
        "cx.invite.create" | "cx.invite.cancel" | "cx.invite.accept" => "cx.invite",
        // legacy aggregate (Phase 1 removed): keep alias only for the old
        // single-Space `cx.policy.set` typed payload, not the per-facet kinds.
        "cx.policy.set" | "cx.state.policy" => "cx.policy",
        // profile create/update share state slot
        "cx.profile.create" | "cx.profile.update" => "cx.profile",
        // device authorized/revoked share state slot via composite (principal,device)
        "cx.device.authorized" | "cx.device.revoked" => "cx.device.authorized",
        // consent grant/revoke share state slot via consent_id
        "cx.consent.grant" | "cx.consent.revoke" => "cx.consent.grant",
        other => other,
    };
    format!("{family}|{subject}")
}

pub fn candidate_wins(existing: &ResolvedStateEvent, candidate: &ResolvedStateEvent) -> bool {
    if is_membership_kind(&candidate.kind) && is_membership_kind(&existing.kind) {
        let existing_rank = membership_rank(&existing.content);
        let candidate_rank = membership_rank(&candidate.content);
        if existing_rank != candidate_rank {
            return candidate_rank > existing_rank;
        }
    }

    candidate
        .hlc
        .cmp(&existing.hlc)
        .then_with(|| candidate.actor_id.as_str().cmp(existing.actor_id.as_str()))
        .then_with(|| candidate.actor_seq.cmp(&existing.actor_seq))
        .then_with(|| candidate.source_event_id.as_str().cmp(existing.source_event_id.as_str()))
        .is_gt()
}

pub fn state_hash(
    space_id: &SpaceId,
    space_version: &str,
    frontier: &[EventId],
    resolved_state: &BTreeMap<String, ResolvedStateEvent>,
) -> Result<String> {
    canonical::canonical_sha256(&json!({
        "space_id": space_id,
        "space_version": space_version,
        "frontier": frontier,
        "resolved_state": resolved_state,
    }))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoardProjection {
    pub board_id: EntityId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub lists: BTreeMap<EntityId, BoardListProjection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cards: BTreeMap<String, BoardFlowPosition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflict_records: Vec<ConflictRecord>,
}

impl BoardProjection {
    pub fn new(board_id: EntityId) -> Self {
        Self {
            board_id,
            lists: BTreeMap::new(),
            cards: BTreeMap::new(),
            conflict_records: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoardListProjection {
    pub list_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub rank: String,
    pub source_event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoardFlowPosition {
    pub board_id: EntityId,
    pub flow_id: String,
    pub list_id: EntityId,
    pub rank: String,
    pub source_event_id: EventId,
    pub actor_seq: u64,
    pub hlc: Hlc,
}

#[derive(Clone, Debug)]
pub struct BoardReducer {
    projection: BoardProjection,
}

impl BoardReducer {
    pub fn new(board_id: EntityId) -> Self {
        Self { projection: BoardProjection::new(board_id) }
    }

    pub fn apply_events(&mut self, events: &[Event]) -> Result<()> {
        let mut sorted = events.iter().collect::<Vec<_>>();
        sorted.sort_by(|left, right| {
            left.hlc
                .cmp(&right.hlc)
                .then_with(|| left.actor_id.as_str().cmp(right.actor_id.as_str()))
                .then_with(|| left.actor_seq.cmp(&right.actor_seq))
                .then_with(|| left.event_id.as_str().cmp(right.event_id.as_str()))
        });
        for event in sorted {
            self.apply_event(event)?;
        }
        Ok(())
    }

    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        if !event_targets_board(event, &self.projection.board_id) {
            return Ok(());
        }
        match event.kind.as_str() {
            "cx.list.create" | "cx.list.reorder" => self.apply_list_event(event),
            "cx.flow.create" => self.apply_flow_position(event, false),
            "cx.flow.move" => self.apply_flow_move(event),
            "cx.flow.reorder" => self.apply_flow_reorder(event),
            "cx.relation.create" | "cx.relation.contains" => {
                if optional_field::<String>(&event.content, "relation_kind").as_deref()
                    == Some("contains")
                    || event.kind == "cx.relation.contains"
                {
                    self.apply_flow_position(event, false)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    pub fn finish(self) -> BoardProjection {
        self.projection
    }

    pub fn projection(&self) -> &BoardProjection {
        &self.projection
    }

    fn apply_list_event(&mut self, event: &Event) -> Result<()> {
        let list_id = required_entity_field(&event.content, "list_id")?;
        let rank = optional_field::<String>(&event.content, "rank")
            .unwrap_or_else(|| format!("r:{:016x}", self.projection.lists.len() as u64 + 1));
        let title = optional_field::<String>(&event.content, "title");
        self.projection.lists.insert(
            list_id.clone(),
            BoardListProjection { list_id, title, rank, source_event_id: event.event_id.clone() },
        );
        Ok(())
    }

    fn apply_flow_move(&mut self, event: &Event) -> Result<()> {
        let flow_id = required_flow_id(&event.content)?;
        let from_list_id = required_entity_field(&event.content, "from_list_id")?;
        let to_list_id = required_entity_field(&event.content, "to_list_id")?;
        let rank = optional_field::<String>(&event.content, "rank")
            .unwrap_or_else(|| format!("r:{:016x}", self.projection.cards.len() as u64 + 1));
        match self.projection.cards.get(&flow_id) {
            Some(current) if current.list_id != from_list_id => {
                self.projection.conflict_records.push(ConflictRecord {
                    key: format!("board_flow|{}|{}", self.projection.board_id, flow_id),
                    winner_event_id: current.source_event_id.clone(),
                    loser_event_id: event.event_id.clone(),
                    reason: "cx.flow.move CAS from_list_id mismatch".to_owned(),
                });
                Ok(())
            }
            Some(_) => {
                self.projection.cards.insert(
                    flow_id.clone(),
                    BoardFlowPosition {
                        board_id: self.projection.board_id.clone(),
                        flow_id: flow_id.clone(),
                        list_id: to_list_id,
                        rank,
                        source_event_id: event.event_id.clone(),
                        actor_seq: event.actor_seq,
                        hlc: event.hlc.clone(),
                    },
                );
                Ok(())
            }
            None => {
                self.projection.conflict_records.push(ConflictRecord {
                    key: format!("board_flow|{}|{}", self.projection.board_id, flow_id),
                    winner_event_id: event.event_id.clone(),
                    loser_event_id: event.event_id.clone(),
                    reason: "cx.flow.move requires an existing flow position".to_owned(),
                });
                Ok(())
            }
        }
    }

    fn apply_flow_reorder(&mut self, event: &Event) -> Result<()> {
        let flow_id = required_flow_id(&event.content)?;
        let list_id = required_entity_field(&event.content, "list_id")?;
        let rank = optional_field::<String>(&event.content, "rank")
            .ok_or_else(|| Error::Protocol("cx.flow.reorder requires rank".to_owned()))?;
        match self.projection.cards.get_mut(&flow_id) {
            Some(current) if current.list_id == list_id => {
                current.rank = rank;
                current.source_event_id = event.event_id.clone();
                current.actor_seq = event.actor_seq;
                current.hlc = event.hlc.clone();
                Ok(())
            }
            Some(current) => {
                self.projection.conflict_records.push(ConflictRecord {
                    key: format!("board_flow|{}|{}", self.projection.board_id, flow_id),
                    winner_event_id: current.source_event_id.clone(),
                    loser_event_id: event.event_id.clone(),
                    reason: "cx.flow.reorder cannot move a flow across lists".to_owned(),
                });
                Ok(())
            }
            None => self.apply_flow_position(event, false),
        }
    }

    fn apply_flow_position(&mut self, event: &Event, force: bool) -> Result<()> {
        let flow_id = required_flow_id(&event.content)?;
        let list_id = required_entity_field(&event.content, "list_id")
            .or_else(|_| required_entity_field(&event.content, "container_id"))?;
        let rank = optional_field::<String>(&event.content, "rank")
            .unwrap_or_else(|| format!("r:{:016x}", self.projection.cards.len() as u64 + 1));
        let candidate = BoardFlowPosition {
            board_id: self.projection.board_id.clone(),
            flow_id: flow_id.clone(),
            list_id,
            rank,
            source_event_id: event.event_id.clone(),
            actor_seq: event.actor_seq,
            hlc: event.hlc.clone(),
        };
        match self.projection.cards.get(&flow_id) {
            Some(existing)
                if !force
                    && existing.list_id != candidate.list_id
                    && !board_position_wins(existing, &candidate) =>
            {
                self.projection.conflict_records.push(ConflictRecord {
                    key: format!("board_flow|{}|{}", self.projection.board_id, flow_id),
                    winner_event_id: existing.source_event_id.clone(),
                    loser_event_id: candidate.source_event_id,
                    reason: "duplicate active board flow position loser".to_owned(),
                });
            }
            Some(existing) if !force && existing.list_id != candidate.list_id => {
                let loser_event_id = existing.source_event_id.clone();
                self.projection.conflict_records.push(ConflictRecord {
                    key: format!("board_flow|{}|{}", self.projection.board_id, flow_id.clone()),
                    winner_event_id: candidate.source_event_id.clone(),
                    loser_event_id,
                    reason: "duplicate active board flow position loser".to_owned(),
                });
                self.projection.cards.insert(flow_id, candidate);
            }
            _ => {
                self.projection.cards.insert(flow_id, candidate);
            }
        }
        Ok(())
    }
}

pub fn reduce_board_projection(board_id: EntityId, events: &[Event]) -> Result<BoardProjection> {
    let mut reducer = BoardReducer::new(board_id);
    reducer.apply_events(events)?;
    Ok(reducer.finish())
}

fn event_targets_board(event: &Event, board_id: &EntityId) -> bool {
    optional_field::<EntityId>(&event.content, "board_id").as_ref() == Some(board_id)
        || optional_field::<EntityId>(&event.content, "scope_container_id").as_ref()
            == Some(board_id)
}

fn required_entity_field(content: &Value, field: &str) -> Result<EntityId> {
    optional_field::<EntityId>(content, field)
        .ok_or_else(|| Error::Protocol(format!("board reducer requires {field}")))
}

fn required_flow_id(content: &Value) -> Result<String> {
    optional_field::<String>(content, "flow_id")
        .map(|value| canonicalize_flow_ref(&value))
        .ok_or_else(|| Error::Protocol("board reducer requires flow_id".to_owned()))
}

fn canonicalize_flow_ref(value: &str) -> String {
    value.to_owned()
}

fn board_position_wins(existing: &BoardFlowPosition, candidate: &BoardFlowPosition) -> bool {
    candidate
        .hlc
        .cmp(&existing.hlc)
        .then_with(|| candidate.actor_seq.cmp(&existing.actor_seq))
        .then_with(|| candidate.source_event_id.as_str().cmp(existing.source_event_id.as_str()))
        .is_gt()
}

fn is_membership_kind(kind: &str) -> bool {
    matches!(kind, "cx.member.state" | "cx.state.membership")
}

fn membership_rank(content: &Value) -> i32 {
    content
        .get("membership")
        .or_else(|| content.get("state"))
        .and_then(Value::as_str)
        .map(|membership| match membership {
            "ban" => 5,
            "join" => 4,
            "invite" => 3,
            "knock" => 2,
            "leave" => 1,
            _ => 0,
        })
        .unwrap_or(0)
}

fn optional_field<T>(content: &Value, field: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    content.as_object()?.get(field).and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn causal_depth_from_index(event: &Event, index: &BTreeMap<EventId, Event>) -> usize {
    fn walk(
        event_id: &EventId,
        index: &BTreeMap<EventId, Event>,
        visiting: &mut BTreeSet<EventId>,
    ) -> usize {
        if !visiting.insert(event_id.clone()) {
            return 0;
        }
        let depth = index
            .get(event_id)
            .map(|event| {
                event
                    .prev_refs
                    .iter()
                    .map(|prev_ref| 1 + walk(prev_ref, index, visiting))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        visiting.remove(event_id);
        depth
    }

    event
        .prev_refs
        .iter()
        .map(|prev_ref| 1 + walk(prev_ref, index, &mut BTreeSet::new()))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, actor: &str, seq: u64, hlc: &str, content: Value) -> Event {
        Event::new(
            kind,
            SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            Did::new(format!("did:web:{actor}.example")).unwrap(),
            seq,
            Hlc::new(hlc).unwrap(),
            content,
        )
        .unwrap()
    }

    #[test]
    fn resolves_membership_conflicts_deterministically() {
        let mut reducer =
            StateReducer::new(SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(), "1");
        let join = event(
            "cx.member.state",
            "alice",
            1,
            "01970e589d21-00000001-a13f9c2e",
            json!({"principal_id": "did:web:bob.example", "membership": "join"}),
        );
        let ban = event(
            "cx.member.state",
            "admin",
            1,
            "01970e589d21-00000000-a13f9c2e",
            json!({"principal_id": "did:web:bob.example", "membership": "ban"}),
        );

        reducer.apply_events(&[join, ban]).unwrap();

        let resolved = reducer.resolved_state.get("cx.member.state|did:web:bob.example").unwrap();
        assert_eq!(resolved.content["membership"], "ban");
        assert_eq!(reducer.conflict_records.len(), 1);
    }

    #[test]
    fn rejects_missing_causal_dependency() {
        let mut reducer =
            StateReducer::new(SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(), "1");
        let mut state = event(
            "cx.state.topic",
            "alice",
            1,
            "01970e589d21-00000001-a13f9c2e",
            json!({"topic": "one"}),
        );
        state.prev_refs.push(EventId::new("cx:event:missing").unwrap());

        assert!(reducer.apply_event(&state).is_err());
    }

    #[test]
    fn snapshot_hash_verifies_and_detects_tamper() {
        let mut reducer =
            StateReducer::new(SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(), "1");
        reducer
            .apply_event(&event(
                "cx.state.topic",
                "alice",
                1,
                "01970e589d21-00000001-a13f9c2e",
                json!({"topic": "one"}),
            ))
            .unwrap();

        let mut snapshot = reducer.snapshot().unwrap();
        snapshot.verify().unwrap();
        snapshot.space_version = "2".to_owned();
        assert!(snapshot.verify().is_err());
    }

    #[test]
    fn snapshot_delta_proof_and_conflict_graph_validate() {
        let mut reducer =
            StateReducer::new(SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(), "1");
        reducer
            .apply_event(&event(
                "cx.state.topic",
                "alice",
                1,
                "01970e589d21-00000001-a13f9c2e",
                json!({"topic": "one"}),
            ))
            .unwrap();
        let first = reducer.snapshot().unwrap();
        reducer
            .apply_event(&event(
                "cx.state.topic",
                "bob",
                1,
                "01970e589d22-00000001-a13f9c2e",
                json!({"topic": "two"}),
            ))
            .unwrap();
        let second = reducer.snapshot().unwrap();

        let delta = second.delta_from(&first).unwrap();
        assert!(delta.changed.contains_key("cx.state.topic|cx:space:01JS0SP000000000000000000"));
        delta.verify_transition(&first, &second).unwrap();

        let proof = reducer.snapshot_proof().unwrap();
        proof.verify_snapshot(&second).unwrap();
        assert_eq!(proof.conflict_count, 1);

        let graph = reducer.conflict_graph();
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn state_auth_rules_fail_closed_by_authority() {
        let alice = Did::new("did:web:alice.example").unwrap();
        let admin = Did::new("did:web:admin.example").unwrap();
        let member = Did::new("did:web:member.example").unwrap();
        let context = StateAuthContext {
            creator: alice.clone(),
            admins: BTreeSet::from([admin.clone()]),
            members: BTreeSet::from([alice, admin, member.clone()]),
            server_dids: BTreeSet::new(),
            device_owners: BTreeMap::from([(DeviceId::new("dev_member").unwrap(), member)]),
        };

        let policy = event(
            "cx.state.policy",
            "admin",
            1,
            "01970e589d21-00000001-a13f9c2e",
            json!({"policy_id": "default"}),
        );
        assert!(evaluate_state_auth(&policy, &context).allowed);

        let forged_marker = event(
            "cx.read.marker",
            "admin",
            1,
            "01970e589d21-00000002-a13f9c2e",
            json!({"scope": "timeline", "device_id": "dev_member"}),
        );
        assert!(!evaluate_state_auth(&forged_marker, &context).allowed);

        let own_marker = event(
            "cx.read.marker",
            "member",
            1,
            "01970e589d21-00000003-a13f9c2e",
            json!({"scope": "timeline", "device_id": "dev_member"}),
        );
        assert!(evaluate_state_auth(&own_marker, &context).allowed);

        let member_ban = event(
            "cx.member.state",
            "member",
            1,
            "01970e589d21-00000004-a13f9c2e",
            json!({"principal_id": "did:web:bob.example", "membership": "ban"}),
        );
        let decision = evaluate_state_auth(&member_ban, &context);
        assert!(!decision.allowed);
        assert_eq!(decision.required, StateAuthority::Admin);
    }

    #[test]
    fn board_reducer_enforces_unique_position_move_cas_and_reorder_scope() {
        let board_id = EntityId::new("cx:entity:board").unwrap();
        let todo = EntityId::new("cx:entity:todo").unwrap();
        let doing = EntityId::new("cx:entity:doing").unwrap();
        let flow_id = EntityId::new("cx:entity:flow").unwrap();
        let flow_id = flow_id.to_string();
        let create = event(
            "cx.flow.create",
            "alice",
            1,
            "01970e589d21-00000001-a13f9c2e",
            json!({
                "board_id": board_id,
                "flow_id": flow_id,
                "list_id": todo,
                "rank": "r:4000000000000000"
            }),
        );
        let bad_move = event(
            "cx.flow.move",
            "alice",
            2,
            "01970e589d21-00000002-a13f9c2e",
            json!({
                "board_id": board_id,
                "flow_id": flow_id,
                "from_list_id": doing,
                "to_list_id": doing,
                "rank": "r:5000000000000000"
            }),
        );
        let good_move = event(
            "cx.flow.move",
            "alice",
            3,
            "01970e589d21-00000003-a13f9c2e",
            json!({
                "board_id": board_id,
                "flow_id": flow_id,
                "from_list_id": todo,
                "to_list_id": doing,
                "rank": "r:6000000000000000"
            }),
        );
        let bad_reorder = event(
            "cx.flow.reorder",
            "alice",
            4,
            "01970e589d21-00000004-a13f9c2e",
            json!({
                "board_id": board_id,
                "flow_id": flow_id,
                "list_id": todo,
                "rank": "r:7000000000000000"
            }),
        );

        let projection =
            reduce_board_projection(board_id, &[create, bad_move, good_move, bad_reorder]).unwrap();
        assert_eq!(projection.cards.get(&flow_id).unwrap().list_id, doing);
        assert_eq!(projection.conflict_records.len(), 2);
        assert!(projection.conflict_records.iter().any(|record| record.reason.contains("CAS")));
        assert!(
            projection.conflict_records.iter().any(|record| record.reason.contains("cannot move"))
        );
    }

    #[test]
    fn board_reducer_records_duplicate_position_loser() {
        let board_id = EntityId::new("cx:entity:board").unwrap();
        let todo = EntityId::new("cx:entity:todo").unwrap();
        let doing = EntityId::new("cx:entity:doing").unwrap();
        let flow_id = EntityId::new("cx:entity:flow").unwrap();
        let first = event(
            "cx.relation.contains",
            "alice",
            1,
            "01970e589d21-00000001-a13f9c2e",
            json!({
                "board_id": board_id,
                "relation_kind": "contains",
                "flow_id": flow_id,
                "list_id": todo
            }),
        );
        let duplicate = event(
            "cx.relation.contains",
            "bob",
            1,
            "01970e589d21-00000002-a13f9c2e",
            json!({
                "board_id": board_id,
                "relation_kind": "contains",
                "flow_id": flow_id,
                "list_id": doing
            }),
        );

        let projection = reduce_board_projection(board_id, &[first, duplicate]).unwrap();
        assert_eq!(projection.cards.get(&flow_id.to_string()).unwrap().list_id, doing);
        assert_eq!(
            projection.conflict_records[0].reason,
            "duplicate active board flow position loser"
        );
    }
}
