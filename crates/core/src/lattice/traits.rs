//! Lattice trait + closed kind enum.

use crate::{CellRef, LatticeOp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{AnchoredOp, CellState};

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

    /// Per-kind declaration of the active spec event kinds that declare this
    /// lattice in `event-kind-registry.json`.
    ///
    /// Event kinds not listed here either do not declare a cell lattice in the
    /// v1 registry or are handled by a higher-level reducer. They MUST NOT be
    /// accepted as lattice input through this closed routing table.
    pub fn event_kinds(self) -> &'static [&'static str] {
        match self {
            Self::OrSet => &[
                "cx.capability.grant",
                "cx.capability.delegate",
                "cx.capability.revoke",
                "cx.capability.derived",
                "cx.session.grant",
                "cx.consent.grant",
                "cx.consent.revoke",
                "cx.device.authorize",
                "cx.device.revoke",
                "cx.device.list_update",
            ],
            Self::MvRegister => &[
                "cx.view.create",
                "cx.view.update",
                "cx.view.reconcile",
                "cx.profile.create",
                "cx.profile.update",
                "cx.mimi.room_binding",
            ],
            Self::CasRegister => &[
                "cx.realm.upgrade",
                "cx.realm.organization",
                "cx.realm.policy",
                "cx.realm.join_rule",
                "cx.realm.history_visibility",
                "cx.realm.discovery",
                "cx.realm.policy_server",
                "cx.realm.policy_components",
                "cx.realm.history_sharing_policy",
                "cx.realm.asset_privacy_policy",
                "cx.realm.read_receipt_policy",
                "cx.realm.moderation_policy",
                "cx.realm.plaintext_visible_services",
                "cx.realm.media_service",
                "cx.realm.schema",
                "cx.realm.inheritance_policy",
                "cx.realm.archive",
                "cx.realm.freeze",
                "cx.realm.tombstone",
                "cx.realm.destroy",
                "cx.flow.move",
                "cx.flow.reorder",
                "cx.space.parent",
            ],
            Self::Fsm => &[
                "cx.member.state",
                // CXP-0008 / CXP-0009 (R3 spec-sync 2026-05-27) — personal-agent
                // lifecycle is an FSM with bottom=reject; deactivate is terminal.
                "cx.agent.pause",
                "cx.agent.resume",
                "cx.agent.deactivate",
            ],
            Self::Counter => &[],
            Self::OrderedLog => {
                &["cx.space.create", "cx.space.child", "cx.policy.rule", "cx.account.status"]
            }
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
    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError>;

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
        assert!(kinds.contains(&"cx.realm.policy"));
        assert!(kinds.contains(&"cx.flow.move"));
        assert!(kinds.contains(&"cx.space.parent"));
    }

    #[test]
    fn ordered_log_handles_registry_ordered_cells() {
        let kinds = LatticeKind::OrderedLog.event_kinds();
        assert!(kinds.contains(&"cx.space.create"));
        assert!(kinds.contains(&"cx.policy.rule"));
        assert!(kinds.contains(&"cx.account.status"));
    }

    #[test]
    fn fsm_handles_member_state() {
        assert!(LatticeKind::Fsm.event_kinds().contains(&"cx.member.state"));
    }
}
