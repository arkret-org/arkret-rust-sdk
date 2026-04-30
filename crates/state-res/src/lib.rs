//! Deterministic Contrix state resolution primitives.
//!
//! The reducer in this crate focuses on protocol state events: stable ordering,
//! state-key extraction, conflict recording, frontier maintenance and snapshot
//! hashing. Product projections can build richer materialized views on top.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use contrix_core::{Did, Error, Event, EventId, Hlc, Result, SpaceId, canonical};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedStateEvent {
    pub kind: String,
    pub state_key: String,
    pub source_event_id: EventId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: Hlc,
    pub content: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub key: String,
    pub winner_event_id: EventId,
    pub loser_event_id: EventId,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

    fn reduce_candidate(&mut self, candidate: ResolvedStateEvent) {
        let map_key = state_map_key(&candidate.kind, &candidate.state_key);
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
    let state_key = state_key_for_event(event)?;
    Ok(Some(ResolvedStateEvent {
        kind: event.kind.clone(),
        state_key,
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
            "cx.member.state"
                | "cx.capability.grant"
                | "cx.capability.delegate"
                | "cx.capability.revoke"
                | "cx.space.policy"
                | "cx.policy.set"
                | "cx.invite.create"
                | "cx.invite.cancel"
                | "cx.invite.accept"
                | "cx.read.marker"
                | "cx.space.create"
                | "cx.space.update"
                | "cx.space.organization"
                | "cx.space.child"
                | "cx.space.parent"
                | "cx.space.inheritance_policy"
                | "cx.space.join_rule"
                | "cx.space.history_visibility"
                | "cx.space.discovery"
                | "cx.space.archive"
                | "cx.space.freeze"
                | "cx.space.destroy"
        )
}

pub fn state_key_for_event(event: &Event) -> Result<String> {
    if let Some(state_key) = optional_field::<String>(&event.content, "state_key") {
        return Ok(state_key);
    }

    match event.kind.as_str() {
        "cx.member.state" | "cx.state.membership" => {
            optional_field::<String>(&event.content, "principal_id")
                .or_else(|| optional_field::<String>(&event.content, "member_id"))
                .or_else(|| optional_field::<String>(&event.content, "user_id"))
                .ok_or_else(|| Error::Protocol("member state requires a state key".to_owned()))
        }
        "cx.capability.revoke" => optional_field::<String>(&event.content, "target_capability_id")
            .or_else(|| optional_field::<String>(&event.content, "id"))
            .ok_or_else(|| Error::Protocol("capability revoke requires a state key".to_owned())),
        "cx.capability.grant" | "cx.capability.delegate" => {
            optional_field::<String>(&event.content, "capability_id")
                .or_else(|| optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("capability event requires a state key".to_owned()))
        }
        "cx.space.policy" | "cx.policy.set" | "cx.state.policy" => {
            Ok(optional_field::<String>(&event.content, "policy_id")
                .unwrap_or_else(|| "space_policy".to_owned()))
        }
        "cx.invite.create" | "cx.invite.cancel" | "cx.invite.accept" => {
            optional_field::<String>(&event.content, "invite_id")
                .or_else(|| optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("invite event requires a state key".to_owned()))
        }
        "cx.read.marker" | "cx.state.read_marker" => {
            optional_field::<String>(&event.content, "scope")
                .or_else(|| optional_field::<String>(&event.content, "target_ref"))
                .ok_or_else(|| Error::Protocol("read marker requires a state key".to_owned()))
        }
        "cx.space.create"
        | "cx.space.update"
        | "cx.space.organization"
        | "cx.space.child"
        | "cx.space.parent"
        | "cx.space.inheritance_policy"
        | "cx.space.join_rule"
        | "cx.space.history_visibility"
        | "cx.space.discovery"
        | "cx.space.archive"
        | "cx.space.freeze"
        | "cx.space.destroy"
        | "cx.state.power_levels"
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

pub fn state_map_key(kind: &str, state_key: &str) -> String {
    let family = match kind {
        "cx.capability.grant" | "cx.capability.delegate" | "cx.capability.revoke" => {
            "cx.capability"
        }
        "cx.invite.create" | "cx.invite.cancel" | "cx.invite.accept" => "cx.invite",
        "cx.space.policy" | "cx.policy.set" | "cx.state.policy" => "cx.policy",
        other => other,
    };
    format!("{family}|{state_key}")
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
}
