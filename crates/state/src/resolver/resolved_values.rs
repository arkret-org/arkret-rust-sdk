//! Value types and field helpers the Realm reducer produces.
//!
//! These are reducer outputs, not protocol wire objects: `ResolvedMessage` and
//! `ResolvedReaction` are what the resolver hands a UI after joining the
//! message and reaction Events it has accepted.

use std::collections::BTreeMap;

use arkret_wire::ActorId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EventId, Result, WireError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedMessage {
    pub message_id: String,
    pub source_event_id: EventId,
    pub latest_event_id: EventId,
    pub created_by: ActorId,
    pub latest_actor_id: ActorId,
    pub latest_actor_seq: u64,
    pub latest_hlc: Option<crate::Hlc>,
    pub content: Value,
    pub revision_event_ids: Vec<EventId>,
    pub redacted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedReaction {
    pub message_id: String,
    pub actor_id: ActorId,
    pub reaction_key: String,
    pub source_event_id: EventId,
    pub actor_seq: u64,
    pub hlc: Option<crate::Hlc>,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub key: String,
    pub winner_event_id: EventId,
    pub loser_event_id: EventId,
    pub reason: String,
}

pub(super) fn membership_rank(content: &Value) -> u8 {
    match content.get("membership").and_then(Value::as_str) {
        Some("ban") => 4,
        Some("leave") => 3,
        Some("invite") => 2,
        Some("join") => 1,
        _ => 0,
    }
}

pub(super) fn object_state_from_str(state: &str) -> Result<crate::ObjectState> {
    // C47 (spec e10b6ad): `deleted` is no longer a valid lifecycle state for
    // Strand / Morph; the only terminal state is `redacted`.
    match state {
        "active" => Ok(crate::ObjectState::Active),
        "archived" => Ok(crate::ObjectState::Archived),
        "redacted" => Ok(crate::ObjectState::Redacted),
        _ => Err(WireError::Protocol(format!("invalid state: {}", state))),
    }
}

pub(super) fn space_state_from_str(state: &str) -> Result<crate::models::SpaceState> {
    match state {
        "active" => Ok(crate::models::SpaceState::Active),
        "archived" => Ok(crate::models::SpaceState::Archived),
        "tombstoned" => Ok(crate::models::SpaceState::Tombstoned),
        _ => Err(WireError::Protocol(format!(
            "invalid space state: {}",
            state
        ))),
    }
}

pub(super) fn patch_string(patch: &Option<BTreeMap<String, Value>>, field: &str) -> Option<String> {
    patch.as_ref()?.get(field)?.as_str().map(ToOwned::to_owned)
}

pub(super) fn patch_fields(
    patch: &Option<BTreeMap<String, Value>>,
) -> Option<BTreeMap<String, Value>> {
    serde_json::from_value(patch.as_ref()?.get("fields")?.clone()).ok()
}

pub(super) fn patch_state(
    patch: &Option<BTreeMap<String, Value>>,
) -> Option<Result<crate::ObjectState>> {
    patch_string(patch, "state").map(|state| object_state_from_str(&state))
}

pub(super) fn canonicalize_strand_ref(value: &str) -> String {
    value.to_owned()
}
