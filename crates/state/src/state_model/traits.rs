//! Runtime contract for the five closed Arkret v1 state models.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{ResolvedCellState, StateWrite};
use crate::{CellRef, LatticeOp};

/// Closed set of state models registered by the protocol.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateModelKind {
    CausalRegister,
    SequencedState,
    OrSet,
    Counter,
    OrderedLog,
}

impl StateModelKind {
    pub const fn as_wire(self) -> arkret_wire::EventCellStateModel {
        match self {
            Self::CausalRegister => arkret_wire::EventCellStateModel::CausalRegister,
            Self::SequencedState => arkret_wire::EventCellStateModel::SequencedState,
            Self::OrSet => arkret_wire::EventCellStateModel::OrSet,
            Self::Counter => arkret_wire::EventCellStateModel::Counter,
            Self::OrderedLog => arkret_wire::EventCellStateModel::OrderedLog,
        }
    }

    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::CausalRegister => "causal_register",
            Self::SequencedState => "sequenced_state",
            Self::OrSet => "or_set",
            Self::Counter => "counter",
            Self::OrderedLog => "ordered_log",
        }
    }

    /// Active Event kinds with at least one write using this state model.
    pub fn event_kinds(self) -> Vec<&'static str> {
        let target = self.as_wire();
        arkret_wire::EVENT_KIND_DESCRIPTORS
            .iter()
            .filter(|descriptor| {
                descriptor
                    .cell_writes
                    .iter()
                    .any(|write| write.state_model == Some(target))
            })
            .map(|descriptor| descriptor.kind)
            .collect()
    }
}

/// Shape error raised before a write enters a reducer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OpError {
    #[error("state operation type {got} is not allowed for {expected_kind}")]
    UnsupportedOpType {
        got: String,
        expected_kind: &'static str,
    },

    #[error("state operation for {kind} requires field {field}")]
    MissingField {
        kind: &'static str,
        field: &'static str,
    },

    #[error("state operation for {kind} field {field} has invalid value: {reason}")]
    InvalidValue {
        kind: &'static str,
        field: &'static str,
        reason: String,
    },

    #[error("state operation for {kind} cannot be represented: {reason}")]
    Unrepresentable { kind: &'static str, reason: String },
}

/// Pure reducer for one registered state model.
///
/// Ordinary models are order independent. `sequenced_state` is called only
/// with the unique confirmed safety order and deliberately does not expose a
/// pairwise join operation.
pub trait StateModel: Send + Sync {
    fn kind(&self) -> StateModelKind;

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError>;

    fn resolve(&self, cell: &CellRef, writes: &[StateWrite]) -> Result<ResolvedCellState, OpError>;

    fn requires_confirmed_order(&self) -> bool {
        self.kind() == StateModelKind::SequencedState
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_model_set_matches_the_registry() {
        let kinds = [
            StateModelKind::CausalRegister,
            StateModelKind::SequencedState,
            StateModelKind::OrSet,
            StateModelKind::Counter,
            StateModelKind::OrderedLog,
        ];
        assert_eq!(
            kinds.map(StateModelKind::as_wire_str),
            [
                "causal_register",
                "sequenced_state",
                "or_set",
                "counter",
                "ordered_log",
            ]
        );
        for kind in kinds {
            assert!(
                kind.event_kinds()
                    .iter()
                    .all(|event| event.starts_with("ak."))
            );
        }
    }
}
