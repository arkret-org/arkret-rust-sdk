//! Runtime implementations of the five Arkret v1 state models.
//!
//! Ordinary data uses `causal_register`, `or_set`, `counter`, or
//! `ordered_log`. Safety state uses `sequenced_state` and is resolved only in
//! the unique confirmed Realm order. Domain transitions and CAS predicates are
//! validators layered over those models; they are not state models.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Bottom, EventId, Hash, LatticeOp, ProjectionEffect};

pub mod causal_register;
pub mod counter;
pub mod domain_transition;
pub mod or_set;
pub mod ordered_log;
pub mod sequenced_state;
mod traits;

pub use arkret_wire::CausalHead;
pub use causal_register::{CausalRegister, CausalRegisterState, causal_heads};
pub use counter::Counter;
pub use domain_transition::{
    DomainTransitionRule, MEMBERSHIP_INITIAL_STATE, membership_transition_heads_into,
};
pub use or_set::OrSet;
pub use ordered_log::OrderedLog;
pub use sequenced_state::SequencedState;
pub use traits::{OpError, StateModel, StateModelKind};

/// One authenticated reducer write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateWrite {
    pub event_id: EventId,
    pub op: LatticeOp,
    /// Exact causal-register heads observed by this signed write.
    pub supersedes: Vec<EventId>,
}

pub trait IntoStateEventId {
    fn into_state_event_id(self) -> EventId;
}

impl IntoStateEventId for EventId {
    fn into_state_event_id(self) -> EventId {
        self
    }
}

impl IntoStateEventId for Hash {
    fn into_state_event_id(self) -> EventId {
        EventId::from_event_digest(&self).expect("validated Event digest must form an EventId")
    }
}

impl StateWrite {
    pub fn new(event_id: impl IntoStateEventId, op: LatticeOp) -> Self {
        Self {
            event_id: event_id.into_state_event_id(),
            op,
            supersedes: Vec::new(),
        }
    }

    pub fn superseding<E, I>(event_id: E, op: LatticeOp, supersedes: I) -> Self
    where
        E: IntoStateEventId,
        I: IntoIterator,
        I::Item: IntoStateEventId,
    {
        Self {
            event_id: event_id.into_state_event_id(),
            op,
            supersedes: supersedes
                .into_iter()
                .map(IntoStateEventId::into_state_event_id)
                .collect(),
        }
    }

    pub fn from_projection(event_id: impl IntoStateEventId, effect: &ProjectionEffect) -> Self {
        Self::new(event_id, effect.op.clone())
    }

    pub fn with_supersedes<I>(mut self, supersedes: I) -> Self
    where
        I: IntoIterator,
        I::Item: IntoStateEventId,
    {
        self.supersedes = supersedes
            .into_iter()
            .map(IntoStateEventId::into_state_event_id)
            .collect();
        self
    }
}

/// Materialized safety state. A written `null` remains distinct from absence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequencedStateValue {
    pub revision_event_id: EventId,
    pub value: Value,
}

/// Result of resolving one registered cell.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolvedCellState {
    /// Full causal coverage and active heads for a causal register.
    Causal(CausalRegisterState),
    /// Last successful write in the confirmed safety order.
    Sequenced(SequencedStateValue),
    /// Joined value for OR-set, counter, and ordered-log state.
    Value(Value),
    /// Unresolved ordinary causal-register heads.
    Bottom(Bottom),
}

impl ResolvedCellState {
    /// Return a usable single value without discarding causal identities.
    pub fn settled_value(&self) -> Option<&Value> {
        match self {
            Self::Sequenced(state) => Some(&state.value),
            Self::Value(value) => Some(value),
            Self::Causal(state) => {
                let first = state.heads.first()?;
                state
                    .heads
                    .iter()
                    .all(|head| head.value == first.value)
                    .then_some(&first.value)
            }
            Self::Bottom(_) => None,
        }
    }

    pub fn into_value(self) -> Option<Value> {
        match self {
            Self::Sequenced(state) => Some(state.value),
            Self::Value(value) => Some(value),
            Self::Causal(state) => {
                let first = state.heads.first()?.value.clone();
                state
                    .heads
                    .iter()
                    .all(|head| head.value == first)
                    .then_some(first)
            }
            Self::Bottom(_) => None,
        }
    }

    pub fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom(_))
    }
}

pub(crate) fn covered_event_ids(writes: &[StateWrite]) -> BTreeSet<EventId> {
    writes.iter().map(|write| write.event_id.clone()).collect()
}
