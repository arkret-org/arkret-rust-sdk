//! Per-cell Lattice trait and 6 core implementations.
//!
//! Per spec `event-auth-state-resolution.md` §5, every cell declares one
//! Lattice type from a closed set of 6 normative algebras. Each Lattice
//! implementation defines:
//!
//! - `Op` — the wire-level operation shape it accepts (a subset of [`crate::LatticeOp`] with its
//!   required fields populated);
//! - `Value` — the resolved value type after `join()`;
//! - `validate_op` — schema-level validity of a single op against this Lattice's rules;
//! - `join` — deterministic merge of an ordered list of sealed ops to produce either `Value` or
//!   `Bottom`.
//!
//! The 6 normative Lattice types:
//!
//! | type | purpose | bottom default |
//! | --- | --- | --- |
//! | `or-set` | OR-set: tagged add/remove with deterministic remove-after-add | reject |
//! | `mv-register` | multi-value register: concurrent `set` exposes all heads | expose |
//! | `cas-register` | CAS register: concurrent `set` produces ⊥ conflict | reject |
//! | `fsm` | finite-state machine: enforces declared transitions | reject |
//! | `counter` | PN-counter: `inc` / `dec` summed deterministically | reject |
//! | `ordered-log` | per-issuer-seq deduped append log | reject |
//!
//! New Lattice types MUST go through a spec profile bump and a new
//! [`LatticeKind`] variant — receivers MUST fail closed on unknown kinds.
//! See spec §5.4.
//!
//! This module is intentionally pure. State store, network, notary
//! orchestration, and the apply-Seal algorithm live elsewhere
//! (`crate::state`, server runtime).

pub mod cas_register;
pub mod counter;
pub mod fsm;
pub mod mv_register;
pub mod or_set;
pub mod ordered_log;
mod traits;

pub use cas_register::CasRegister;
pub use counter::Counter;
pub use fsm::Fsm;
pub use mv_register::MvRegister;
pub use or_set::OrSet;
pub use ordered_log::OrderedLog;
use serde_json::Value;
pub use traits::{Lattice, LatticeKind, OpError};

use crate::{Bottom, BottomKind, CellRef, LatticeOp, MoveId};

/// A single sealed op input to [`Lattice::join`].
///
/// Each SealedOp carries the underlying [`LatticeOp`] plus the Move id
/// it came from (used to populate `Bottom::move_ids` on conflict).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedOp {
    pub move_id: MoveId,
    pub op: LatticeOp,
}

impl SealedOp {
    pub fn new(move_id: MoveId, op: LatticeOp) -> Self {
        Self { move_id, op }
    }
}

/// Resolved cell state. Either a concrete value or a [`Bottom`] diagnostic.
#[derive(Clone, Debug, PartialEq)]
pub enum CellState {
    Value(Value),
    Bottom(Bottom),
}

impl CellState {
    pub fn into_bottom(self) -> Option<Bottom> {
        match self {
            Self::Bottom(b) => Some(b),
            _ => None,
        }
    }

    pub fn into_value(self) -> Option<Value> {
        match self {
            Self::Value(v) => Some(v),
            _ => None,
        }
    }

    pub fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom(_))
    }

    pub fn make_bottom(kind: BottomKind, cells: Vec<CellRef>) -> Self {
        Self::Bottom(Bottom::new(kind, cells))
    }
}
