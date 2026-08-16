//! Lattice trait + closed kind enum.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{CellState, SealedOp};
use crate::{CellRef, LatticeOp};

/// Closed set of normative Lattice kinds.
///
/// Per spec §5.4 profiles MUST NOT introduce new variants here without a
/// schema profile bump. Receivers MUST fail closed on unrecognized kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
            Self::OrSet => "or_set",
            Self::MvRegister => "mv_register",
            Self::CasRegister => "cas_register",
            Self::Fsm => "fsm",
            Self::Counter => "counter",
            Self::OrderedLog => "ordered_log",
        }
    }

    /// Active spec Event kinds with at least one cell write using this lattice.
    /// A single Event may legitimately occur in more than one returned set
    /// because the registry permits one Event to write multiple cell families.
    pub fn event_kinds(self) -> Vec<&'static str> {
        let target = match self {
            Self::OrSet => Some(arkret_wire::EventCellLattice::OrSet),
            Self::MvRegister => Some(arkret_wire::EventCellLattice::MvRegister),
            Self::CasRegister => Some(arkret_wire::EventCellLattice::CasRegister),
            Self::Fsm => Some(arkret_wire::EventCellLattice::Fsm),
            Self::OrderedLog => Some(arkret_wire::EventCellLattice::OrderedLog),
            Self::Counter => None,
        };
        let Some(target) = target else {
            return Vec::new();
        };
        arkret_wire::EVENT_KIND_DESCRIPTORS
            .iter()
            .filter(|descriptor| {
                descriptor
                    .cell_writes
                    .iter()
                    .any(|write| write.lattice == Some(target))
            })
            .map(|descriptor| descriptor.kind)
            .collect()
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
    UnsupportedOpType {
        got: String,
        expected_kind: &'static str,
    },

    #[error("lattice op for {kind} requires field {field}")]
    MissingField {
        kind: &'static str,
        field: &'static str,
    },

    #[error("lattice op for {kind} field {field} has invalid value: {reason}")]
    InvalidValue {
        kind: &'static str,
        field: &'static str,
        reason: String,
    },
}

/// Per-cell Lattice trait.
///
/// Implementations are stateless — `join` takes the full sealed op list
/// each call and returns the deterministic resolved state. This matches
/// the spec model where state is a pure function of (Seal view,
/// frontier, cell schema) and the runtime caches it for performance.
///
/// `cell` is passed so multi-cell-aware diagnostics (multi-cell Move
/// failures, notary cell ⊥) can populate `Bottom.cells`.
pub trait Lattice {
    fn kind(&self) -> LatticeKind;

    /// Validate that `op` has the right shape for this Lattice.
    ///
    /// Run before the op enters Seal frontier — failure produces a
    /// Move-level `schema_violation` rather than a cell-level Bottom.
    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError>;

    /// Deterministic join of `sealed_ops` to a `CellState`.
    ///
    /// The order of `sealed_ops` is the deterministic per-Seal-view
    /// order (e.g. by `(Seal.hlc, Move.id)`). Implementations MUST be
    /// associative and commutative w.r.t. this order so receivers
    /// converge.
    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState;

    /// The value this lattice reports for a cell no write has reached yet.
    ///
    /// `join` starts from it, so a producer's derived `from` must too — an
    /// absent `fsm` cell that derived `from = null` could never match the
    /// registered initial state, and every first transition would join to
    /// Bottom. Lattices with no such notion return `None`.
    fn initial_state(&self) -> Option<serde_json::Value> {
        None
    }
}

#[cfg(test)]
mod kind_tests {
    use super::*;

    #[test]
    fn declared_event_kinds_are_canonical() {
        for kind in [
            LatticeKind::OrSet,
            LatticeKind::MvRegister,
            LatticeKind::CasRegister,
            LatticeKind::Fsm,
            LatticeKind::Counter,
            LatticeKind::OrderedLog,
        ] {
            for ek in kind.event_kinds() {
                assert!(
                    ek.starts_with("ak."),
                    "lattice kind {kind:?} event kind {ek} must start with 'ak.'"
                );
            }
        }
    }

    #[test]
    fn applet_binding_create_declares_both_registry_cell_lattices() {
        let create = arkret_wire::event_kind_str::AUDIT_APPLET_BINDING_CREATE;
        assert!(LatticeKind::CasRegister.event_kinds().contains(&create));
        assert!(LatticeKind::Fsm.event_kinds().contains(&create));
        assert!(
            LatticeKind::Fsm
                .event_kinds()
                .contains(&arkret_wire::event_kind_str::AUDIT_APPLET_BINDING_STATE)
        );
    }

    #[test]
    fn or_set_handles_consent_and_capability() {
        let kinds = LatticeKind::OrSet.event_kinds();
        assert!(kinds.contains(&"ak.consent.grant"));
        assert!(kinds.contains(&"ak.consent.revoke"));
        assert!(kinds.contains(&"ak.capability.grant"));
        assert!(kinds.contains(&"ak.capability.revoke"));
    }

    #[test]
    fn cas_register_handles_mls_commit_and_creates() {
        let kinds = LatticeKind::CasRegister.event_kinds();
        assert!(kinds.contains(&"ak.realm.policy"));
        assert!(kinds.contains(&"ak.strand.move"));
        assert!(kinds.contains(&"ak.space.parent"));
    }

    #[test]
    fn ordered_log_handles_registry_ordered_cells() {
        let kinds = LatticeKind::OrderedLog.event_kinds();
        assert!(kinds.contains(&"ak.space.create"));
        assert!(kinds.contains(&"ak.policy.rule"));
        assert!(kinds.contains(&"ak.account.status"));
    }

    #[test]
    fn fsm_handles_member_state() {
        assert!(LatticeKind::Fsm.event_kinds().contains(&"ak.member.state"));
    }
}
