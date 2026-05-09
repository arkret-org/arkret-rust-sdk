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

    /// Per-kind declaration of the `cx.<...>` event-kind IDs each lattice
    /// type handles.
    ///
    /// The list is the canonical contract used by [`LatticeRegistry`] →
    /// `ProjectionState::apply` to route incoming events to the correct
    /// lattice without consulting the cell registry. Soland's full
    /// `lattice_first=true` projection switch depends on this contract.
    ///
    /// Notes:
    ///
    /// - The list is exhaustive within v1: any event-kind not appearing
    ///   here MUST NOT enter a per-cell Lattice; the runtime fails closed
    ///   on unknown kinds (spec §5.4).
    /// - Multiple kinds may map to the same lattice (`cx.consent.grant` /
    ///   `cx.consent.revoke` both flow through `or-set`).
    /// - `cx.flow.move` is consumed by `fsm` (membership/state transitions
    ///   on flow ranks), while flow CRUD shape changes go through
    ///   `cas-register`.
    pub fn event_kinds(self) -> &'static [&'static str] {
        match self {
            Self::OrSet => &[
                // capability grant/revoke — or-set on capability cells.
                "cx.capability.grant",
                "cx.capability.revoke",
                // consent grant/revoke — or-set on consent cells (spec §3).
                "cx.consent.grant",
                "cx.consent.revoke",
                // covered_frontier — governance Anchor frontier as or-set
                // tags on the MLS group's covered_frontier cell (spec §10).
                "cx.mls.covered_frontier.add",
            ],
            Self::MvRegister => &[
                // soft display state surfaces concurrent values (multi-value
                // last-writer-wins style read after deduplicate).
                "cx.space.update",
                "cx.flow.update",
                "cx.entity.update",
                "cx.task.update",
            ],
            Self::CasRegister => &[
                // create-and-set primitives where racing writes must fail
                // closed (cas-register, bottom=reject).
                "cx.space.create",
                "cx.flow.create",
                "cx.flow.archive",
                "cx.flow.restore",
                "cx.entity.create",
                "cx.entity.delete",
                "cx.entity.restore",
                "cx.entity.redact",
                "cx.task.create",
                "cx.view.create",
                "cx.view.update",
                "cx.view.reconcile",
                // anchorer cell + space policy CAS updates.
                "cx.space.anchorer.set",
                "cx.space.policy.set",
                // MLS commit Move targets — mls_epoch + key_schedule are
                // both cas-register (one schedule per epoch). Spec §10.
                "cx.mls.commit",
            ],
            Self::Fsm => &[
                // membership state transitions (invited → join → leave/ban).
                "cx.member.state",
                // flow rank reorder + parent moves are FSM-style (declared
                // edges only) on the flow position cell.
                "cx.flow.move",
                "cx.flow.reorder",
                "cx.flow.convert",
                "cx.flow.link_surface",
                "cx.flow.unlink_surface",
                "cx.flow.set_primary_surface",
            ],
            Self::Counter => &[
                // PN-counter — audit + quota counters.
                "cx.metric.counter.inc",
                "cx.metric.counter.dec",
            ],
            Self::OrderedLog => &[
                // append-only chat / audit log — per-issuer-seq deduped.
                "cx.message.create",
                "cx.audit.append",
                "cx.audit.ryw_receipt",
            ],
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

#[cfg(test)]
mod kind_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_kind_declares_at_least_one_event_kind() {
        for kind in [
            LatticeKind::OrSet,
            LatticeKind::MvRegister,
            LatticeKind::CasRegister,
            LatticeKind::Fsm,
            LatticeKind::Counter,
            LatticeKind::OrderedLog,
        ] {
            assert!(
                !kind.event_kinds().is_empty(),
                "lattice kind {kind:?} declares no event kinds"
            );
            for ek in kind.event_kinds() {
                assert!(
                    ek.starts_with("cx."),
                    "lattice kind {kind:?} event kind {ek} must start with 'cx.'"
                );
            }
        }
    }

    #[test]
    fn event_kinds_have_no_cross_kind_overlap() {
        // Every cx.<...> event kind MUST belong to exactly one lattice kind
        // so the LatticeRegistry route is unambiguous.
        let mut seen: BTreeSet<&'static str> = BTreeSet::new();
        for kind in [
            LatticeKind::OrSet,
            LatticeKind::MvRegister,
            LatticeKind::CasRegister,
            LatticeKind::Fsm,
            LatticeKind::Counter,
            LatticeKind::OrderedLog,
        ] {
            for ek in kind.event_kinds() {
                assert!(seen.insert(ek), "event kind {ek} appears in more than one LatticeKind");
            }
        }
    }

    #[test]
    fn or_set_handles_consent_and_capability() {
        let kinds = LatticeKind::OrSet.event_kinds();
        assert!(kinds.contains(&"cx.consent.grant"));
        assert!(kinds.contains(&"cx.consent.revoke"));
        assert!(kinds.contains(&"cx.capability.grant"));
        assert!(kinds.contains(&"cx.capability.revoke"));
    }

    #[test]
    fn cas_register_handles_mls_commit_and_creates() {
        let kinds = LatticeKind::CasRegister.event_kinds();
        assert!(kinds.contains(&"cx.mls.commit"));
        assert!(kinds.contains(&"cx.flow.create"));
        assert!(kinds.contains(&"cx.space.create"));
    }

    #[test]
    fn ordered_log_handles_messages_and_audit() {
        let kinds = LatticeKind::OrderedLog.event_kinds();
        assert!(kinds.contains(&"cx.message.create"));
        assert!(kinds.contains(&"cx.audit.append"));
    }

    #[test]
    fn fsm_handles_member_state() {
        assert!(LatticeKind::Fsm.event_kinds().contains(&"cx.member.state"));
    }
}
