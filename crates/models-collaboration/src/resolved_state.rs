//! Resolved-projection data shapes shared across the state runtime and the
//! authorization layer.
//!
//! [`ResolvedStateEvent`] is the reducer's per-cell projection of a generic
//! state event (`kind|subject` keyed): the latest-writer-wins content plus
//! the causal metadata used to break ties. It is pure data with no behavior;
//! the mutable Move/Seal reducer that produces it lives in `arkret-state`,
//! and `arkret-policy` reads it to mint capability grants. Both edges
//! (state -> models-collaboration, policy -> models-collaboration) are
//! allowed, keeping policy free of any dependency on the state runtime.

use arkret_identifiers::Hlc;
use arkret_wire::{Did, EventId, EventKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A generic resolved state event, keyed by `kind|subject` in the reducer
/// projection. Carries the winning event's typed content and the causal
/// tie-break metadata (HLC, actor id / seq, source event id).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedStateEvent {
    pub kind: EventKind,
    /// Cell subject derived from the event's typed payload per the spec
    /// event-kind-registry's `cell_subject`. Empty string for singleton
    /// kinds.
    pub subject: String,
    pub source_event_id: EventId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: Option<Hlc>,
    pub content: Value,
}
