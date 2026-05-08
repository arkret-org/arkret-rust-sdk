//! Lattice trait + closed kind enum.

use contrix_core::CellRef;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AnchoredOp, CellState};

/// Closed set of normative Lattice kinds.
///
/// Per spec §5.4 profiles MUST NOT introduce new variants here without a
/// schema profile bump. Receivers MUST fail closed on unrecognized kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LatticeKind {
    OrSet,
    MvRegister,
    CasRegister,
    Fsm,
    Counter,
    OrderedLog,
}

impl LatticeKind {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::OrSet => "or-set",
            Self::MvRegister => "mv-register",
            Self::CasRegister => "cas-register",
            Self::Fsm => "fsm",
            Self::Counter => "counter",
            Self::OrderedLog => "ordered-log",
        }
    }
}

/// Op-validation error from [`Lattice::validate_op`].
///
/// Distinct from `Bottom`: this fires on individual op parse / shape
/// problems, BEFORE the op enters a join. Move-level rejection due to a
/// `validate_op` failure surfaces as a `schema_violation` at the Move
/// verifier and never reaches the lattice runtime.
#[derive(Clone, Debug, Error)]
pub enum OpError {
    #[error("lattice op type {got} is not allowed for {expected_kind}")]
    UnsupportedOpType { got: String, expected_kind: &'static str },

    #[error("lattice op for {kind} requires field {field}")]
    MissingField { kind: &'static str, field: &'static str },

    #[error("lattice op for {kind} field {field} has invalid value: {reason}")]
    InvalidValue { kind: &'static str, field: &'static str, reason: String },
}

/// Per-cell Lattice trait.
///
/// Implementations are stateless — `join` takes the full anchored op list
/// each call and returns the deterministic resolved state. This matches
/// the spec model where state is a pure function of (Anchor view,
/// frontier, cell schema) and the runtime caches it for performance.
///
/// `cell` is passed so multi-cell-aware diagnostics (multi-cell Move
/// failures, anchorer cell ⊥) can populate `Bottom.cells`.
pub trait Lattice {
    fn kind(&self) -> LatticeKind;

    /// Validate that `op` has the right shape for this Lattice.
    ///
    /// Run before the op enters Anchor frontier — failure produces a
    /// Move-level `schema_violation` rather than a cell-level Bottom.
    fn validate_op(&self, op: &contrix_core::LatticeOp) -> Result<(), OpError>;

    /// Deterministic join of `anchored_ops` to a `CellState`.
    ///
    /// The order of `anchored_ops` is the deterministic per-Anchor-view
    /// order (e.g. by `(Anchor.hlc, Move.id)`). Implementations MUST be
    /// associative and commutative w.r.t. this order so receivers
    /// converge.
    fn join(&self, cell: &CellRef, anchored_ops: &[AnchoredOp]) -> CellState;
}
