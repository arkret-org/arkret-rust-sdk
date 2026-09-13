//! Runtime implementations of the five Arkret v1 state models.
//!
//! Ordinary data uses `causal_register`, `or_set`, `counter`, or
//! `ordered_log`. Safety state uses `sequenced_state` and is resolved only in
//! the unique confirmed Realm order. Domain transitions and CAS predicates are
//! validators layered over those models; they are not state models.

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
pub use causal_register::{
    CausalRegister, CausalRegisterState, CausalWinner, causal_register_state,
};
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
    /// Exact same-Cell causal-register predecessors observed by this signed write.
    pub supersedes: Vec<EventId>,
    /// Receiver-derived immutable depth cache. Producers never supply this.
    pub fixed_depth: Option<u64>,
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
            fixed_depth: None,
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
            fixed_depth: None,
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

    pub fn with_fixed_depth(mut self, depth: u64) -> Self {
        self.fixed_depth = Some(depth);
        self
    }
}

/// Materialized safety state. A written `null` remains distinct from absence.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequencedStateValue {
    pub revision_event_id: EventId,
    pub value: Value,
}

/// Result of resolving one registered cell.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolvedCellState {
    /// Full causal coverage and deterministic current winner for a causal register.
    Causal(CausalRegisterState),
    /// Last successful write in the confirmed safety order.
    Sequenced(SequencedStateValue),
    /// Joined value for OR-set, counter, and ordered-log state.
    Value(Value),
    /// A registered cross-cell domain invariant has no usable projection.
    Bottom(Bottom),
}

impl ResolvedCellState {
    /// Return a usable single value without discarding causal identities.
    pub fn settled_value(&self) -> Option<&Value> {
        match self {
            Self::Sequenced(state) => Some(&state.value),
            Self::Value(value) => Some(value),
            Self::Causal(state) => Some(&state.winner.value),
            Self::Bottom(_) => None,
        }
    }

    pub fn into_value(self) -> Option<Value> {
        match self {
            Self::Sequenced(state) => Some(state.value),
            Self::Value(value) => Some(value),
            Self::Causal(state) => Some(state.winner.value),
            Self::Bottom(_) => None,
        }
    }

    pub fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom(_))
    }
}

/// Convert a materialized reducer state into the canonical protocol snapshot
/// used by Seal command result digests and Realm snapshots.
pub fn canonical_cell_state(
    model: StateModelKind,
    state: &ResolvedCellState,
) -> Result<arkret_wire::CanonicalCellState, crate::WireError> {
    use arkret_wire::{CanonicalCausalState, CanonicalCausalWinner, CanonicalCellState};

    let canonical = match (model, state) {
        (StateModelKind::CausalRegister, ResolvedCellState::Causal(state)) => {
            let mut covered_event_ids = state.covered_event_ids.iter().cloned().collect::<Vec<_>>();
            covered_event_ids.sort_by(|left, right| left.token_bytes().cmp(&right.token_bytes()));
            CanonicalCellState::CausalRegister(CanonicalCausalState {
                covered_event_ids,
                winner: CanonicalCausalWinner {
                    event_id: state.winner.event_id.clone(),
                    depth: state.winner.depth,
                    value: state.winner.value.clone(),
                },
            })
        }
        (StateModelKind::SequencedState, ResolvedCellState::Sequenced(state)) => {
            CanonicalCellState::SequencedState(arkret_wire::CanonicalSequencedState {
                revision_event_id: state.revision_event_id.clone(),
                value: state.value.clone(),
            })
        }
        (
            StateModelKind::OrSet | StateModelKind::OrderedLog | StateModelKind::Counter,
            ResolvedCellState::Value(value),
        ) => CanonicalCellState::from_state_object(
            model.as_wire(),
            serde_json::json!({ "value": value }),
        )?,
        (_, ResolvedCellState::Bottom(_)) => {
            return Err(crate::WireError::Protocol(
                "a domain Bottom has no canonical committed Cell state".to_owned(),
            ));
        }
        _ => {
            return Err(crate::WireError::Protocol(format!(
                "materialized state does not match registered model {}",
                model.as_wire_str()
            )));
        }
    };
    canonical.validate()?;
    Ok(canonical)
}
