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

    /// Per-kind declaration of the active spec event kinds that declare this
    /// lattice in `event-kind-registry.json`.
    ///
    /// Event kinds not listed here either do not declare a cell lattice in the
    /// v1 registry or are handled by a higher-level reducer. They MUST NOT be
    /// accepted as lattice input through this closed routing table.
    pub fn event_kinds(self) -> &'static [&'static str] {
        match self {
            Self::OrSet => &[
                "ak.capability.grant",
                "ak.capability.delegate",
                "ak.capability.revoke",
                "ak.capability.derived",
                "ak.session.grant",
                "ak.consent.grant",
                "ak.consent.revoke",
                "ak.device.authorize",
                "ak.device.revoke",
                "ak.device.list_update",
            ],
            Self::MvRegister => &[
                "ak.view.create",
                "ak.view.update",
                "ak.view.reconcile",
                "ak.profile.create",
                "ak.profile.update",
                "ak.mimi.room_binding",
            ],
            Self::CasRegister => &[
                "ak.realm.upgrade",
                "ak.realm.organization",
                "ak.realm.policy",
                "ak.realm.join_rule",
                "ak.realm.history_visibility",
                "ak.realm.discovery",
                "ak.realm.policy_server",
                "ak.realm.policy_components",
                "ak.realm.history_sharing_policy",
                "ak.realm.asset_privacy_policy",
                "ak.realm.read_receipt_policy",
                "ak.realm.moderation_policy",
                "ak.realm.plaintext_visible_services",
                "ak.realm.media_service",
                "ak.realm.schema",
                "ak.realm.inheritance_policy",
                "ak.realm.archive",
                "ak.realm.freeze",
                "ak.realm.tombstone",
                "ak.realm.destroy",
                "ak.strand.move",
                "ak.strand.reorder",
                "ak.space.parent",
            ],
            Self::Fsm => &[
                "ak.member.state",
                "ak.realm.link",
                "ak.audit.applet_binding",
                "ak.audit.session.request",
                "ak.audit.session.authorize",
                "ak.audit.session.notice",
                "ak.audit.session.close",
                // Personal-agent lifecycle is an FSM with bottom=reject;
                // deactivate is terminal.
                "ak.self.agent.pause",
                "ak.self.agent.resume",
                "ak.self.agent.deactivate",
            ],
            Self::Counter => &[],
            Self::OrderedLog => &[
                "ak.audit.release",
                "ak.space.create",
                "ak.space.child",
                "ak.policy.rule",
                "ak.account.status",
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
}

#[cfg(test)]
mod kind_tests {
    use std::collections::BTreeSet;

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
    fn event_kinds_have_no_cross_kind_overlap() {
        // Every ak.<...> event kind MUST belong to exactly one lattice kind
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
                assert!(
                    seen.insert(ek),
                    "event kind {ek} appears in more than one LatticeKind"
                );
            }
        }
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
