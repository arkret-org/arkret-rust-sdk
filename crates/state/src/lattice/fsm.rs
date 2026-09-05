//! Finite-state-machine Lattice.
//!
//! Per spec §5.3:
//! - Each cell instance carries an `allowed_transitions: Vec<(from, to)>` declaration loaded from
//!   its schema.
//! - `transition(from, to)` op is valid only if `(from, to)` is in `allowed_transitions`. The op
//!   also requires that the cell's current value equals `from` at the moment the op is applied
//!   (this is checked per Seal batch by the runtime; the join here just walks sealed ops in order
//!   and surfaces ⊥ on illegal transitions).
//! - Concurrent valid transitions from the same `from` to different `to` produce a
//!   `kind=invalid_transition` Bottom (the cell's safety contract — e.g. membership state machine —
//!   requires a single resolved next state).
//!
//! `from` / `to` values are JSON; equality is by JSON canonical form.

use std::collections::HashMap;

use serde_json::{Value, json};

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{Bottom, BottomKind, CellRef, LatticeOp, LatticeOpType, bottom_details};

/// FSM Lattice instance with declared `allowed_transitions` and an
/// optional `initial_state` for empty cells.
#[derive(Clone, Debug)]
pub struct Fsm {
    pub allowed_transitions: Vec<(Value, Value)>,
    pub initial_state: Option<Value>,
}

impl Fsm {
    pub fn new(allowed_transitions: Vec<(Value, Value)>) -> Self {
        Self {
            allowed_transitions,
            initial_state: None,
        }
    }

    pub fn with_initial(mut self, initial: Value) -> Self {
        self.initial_state = Some(initial);
        self
    }

    fn is_allowed(&self, from: &Value, to: &Value) -> bool {
        self.allowed_transitions
            .iter()
            .any(|(f, t)| f == from && t == to)
    }
}

/// The registered initial state of `ak.fsm.membership.v1`.
///
/// The membership state machine is shared by `ak.component.member.state.v1` and
/// `ak.component.circle.member.v1`, and its contract lives in
/// `contract-registry.json` under `event_kind_registry.fsm_templates`. This
/// constant exists because the two callers of
/// [`membership_transition_head_into`] sit below the lattice registry that
/// resolves that contract, and repeating the literal at each of them is how
/// three separate copies of this fold came to exist.
///
/// It is a stopgap, not a design: the `fsm` transition algebra is unresolved
/// (`arkret-work/review/spec-open/2026-09-06-1610`), and when it lands this fold
/// and this constant both go away in favour of the resolved contract.
pub const MEMBERSHIP_INITIAL_STATE: &str = "leave";

/// The identity of the write that most recently moved a membership cell into
/// `target`, or `None` if the cell does not resolve there.
///
/// **This is the arrival-ordered fold, kept in one place rather than fixed.**
/// It walks the op log in delivery order, so it inherits every defect
/// `2026-09-06-1610` documents: it is not commutative, its `(from, to)`
/// deduplication cannot tell `A -> B -> A` from `A -> B -> A -> B`, and it
/// truncates at the last `recovery_reset` even though §9.5.1 item 5 forbids
/// exactly that for `fsm`. It existed in three independent copies — here, in the
/// MLS governance proof replay, and in soland's notary — each with its own
/// hardcoded `"leave"`. Converging them does not make the semantics right; it
/// makes there be one thing to correct when the algebra is adjudicated.
///
/// `Err` is a history that does not fold at all: a non-transition op in a
/// transition cell, a sibling that contradicts an earlier transition from the
/// same state, or a `from` that does not match the state the walk is in.
pub fn membership_transition_head_into(
    ops: &[crate::lattice::ordered_log::IssuedOp],
    target: &str,
) -> Result<Option<crate::Hash>, String> {
    let ops = ops
        .iter()
        .rposition(|issued| issued.op.recovery_reset)
        .map_or(ops, |boundary| &ops[boundary..]);
    let mut current = MEMBERSHIP_INITIAL_STATE.to_owned();
    let mut seen = std::collections::BTreeSet::<(String, String)>::new();
    let mut head = None;
    for issued in ops {
        let from = issued.op.op.from.as_ref().and_then(Value::as_str);
        let to = issued.op.op.to.as_ref().and_then(Value::as_str);
        let (Some(from), Some(to)) = (from, to) else {
            return Err("membership cell contains a non-transition operation".to_owned());
        };
        let transition = (from.to_owned(), to.to_owned());
        if seen.contains(&transition) {
            continue;
        }
        if seen
            .iter()
            .any(|(seen_from, seen_to)| seen_from == from && seen_to != to)
            || current != from
        {
            return Err(
                "membership operation history does not resolve to the effective FSM value"
                    .to_owned(),
            );
        }
        seen.insert(transition);
        current.clear();
        current.push_str(to);
        head = (to == target).then(|| issued.op.move_id.clone());
    }
    Ok(head)
}

impl Lattice for Fsm {
    fn kind(&self) -> LatticeKind {
        LatticeKind::Fsm
    }

    fn initial_state(&self) -> Option<Value> {
        self.initial_state.clone()
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Transition => {
                if op.from.is_none() {
                    return Err(OpError::MissingField {
                        kind: "fsm",
                        field: "from",
                    });
                }
                if op.to.is_none() {
                    return Err(OpError::MissingField {
                        kind: "fsm",
                        field: "to",
                    });
                }
                let from = op.from.as_ref().unwrap();
                let to = op.to.as_ref().unwrap();
                if !self.is_allowed(from, to) {
                    return Err(OpError::InvalidValue {
                        kind: "fsm",
                        field: "transition",
                        reason: format!(
                            "transition from {from} to {to} is not in allowed_transitions"
                        ),
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: other.as_str().to_owned(),
                expected_kind: "fsm",
            }),
        }
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        let mut current: Option<Value> = self.initial_state.clone();
        let mut seen_transitions: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for entry in sealed_ops {
            let op = &entry.op;
            // Skip ops that don't pass shape (defensive — same rule as
            // OrSet etc.).
            if self.validate_op(op).is_err() {
                let mut bottom = Bottom::new(BottomKind::InvalidTransition, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("current", current.clone().unwrap_or(Value::Null)),
                    ("from", op.from.clone().unwrap_or(Value::Null)),
                    ("to", op.to.clone().unwrap_or(Value::Null)),
                ]));
                return CellState::Bottom(bottom);
            }
            let from = op.from.as_ref().unwrap();
            let to = op.to.as_ref().unwrap();
            let Ok(from_key) = arkret_canonical::canonical_json_value_bytes(from) else {
                let mut bottom = Bottom::new(BottomKind::InvalidTransition, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("current", current.clone().unwrap_or(Value::Null)),
                    ("from", from.clone()),
                    ("to", to.clone()),
                ]));
                return CellState::Bottom(bottom);
            };
            let Ok(to_key) = arkret_canonical::canonical_json_value_bytes(to) else {
                let mut bottom = Bottom::new(BottomKind::InvalidTransition, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("current", current.clone().unwrap_or(Value::Null)),
                    ("from", from.clone()),
                    ("to", to.clone()),
                ]));
                return CellState::Bottom(bottom);
            };
            // Whether the walk is standing where this transition starts. A
            // `None` current is the first transition on a cell with no declared
            // initial state, which starts wherever it says it does.
            //
            // Everything below hangs off this. `seen_transitions` alone cannot
            // tell a replay from a *return*: a cell that legally came back to
            // `from` is at the start of that transition again, and the same
            // `(from, to)` pair is then a new occurrence rather than a repeat of
            // the old one. Deciding by the pair alone is what made
            // `A -> B -> A -> B` read `A`, and what made a registered self-loop
            // turn the next legal transition into a phantom sibling conflict.
            let at_from = current.as_ref().is_none_or(|cur| cur == from);
            if !at_from {
                if seen_transitions.get(&from_key) == Some(&to_key) {
                    // Redelivery of a transition already folded in. The walk has
                    // moved on, so applying it again would rewind the cell.
                    continue;
                }
                if seen_transitions.contains_key(&from_key) {
                    // Two transitions out of one state that the walk never
                    // returned to: genuine concurrent siblings.
                    let mut bottom = Bottom::new(BottomKind::Conflict, vec![cell.clone()]);
                    bottom.move_ids = vec![entry.move_id.clone()];
                    bottom.details = Some(bottom_details([
                        ("current", current.clone().unwrap_or(Value::Null)),
                        ("from", from.clone()),
                        ("reason", json!("same_from_different_to")),
                        ("to", to.clone()),
                    ]));
                    return CellState::Bottom(bottom);
                }
                let cur = current.clone().unwrap_or(Value::Null);
                let mut bottom = Bottom::new(BottomKind::InvalidTransition, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("current", cur.clone()),
                    ("expected_from", cur),
                    ("from", from.clone()),
                    ("to", to.clone()),
                ]));
                return CellState::Bottom(bottom);
            }
            seen_transitions.insert(from_key, to_key);
            current = Some(to.clone());
        }
        match current {
            Some(v) => CellState::Value(v),
            None => CellState::Value(Value::Null),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, LatticeOp};

    fn cell() -> CellRef {
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn membership_fsm() -> Fsm {
        Fsm::new(vec![
            (json!("invited"), json!("join")),
            (json!("join"), json!("leave")),
            (json!("join"), json!("ban")),
            (json!("leave"), json!("join")),
        ])
        .with_initial(json!("invited"))
    }

    fn transition(from: Value, to: Value) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(from),
            to: Some(to),
            reason: None,
            issuer_seq: None,
        }
    }

    #[test]
    fn validate_accepts_declared_transition() {
        let f = membership_fsm();
        f.validate_op(&transition(json!("invited"), json!("join")))
            .unwrap();
    }

    #[test]
    fn validate_rejects_undeclared_transition() {
        let f = membership_fsm();
        let err = f
            .validate_op(&transition(json!("invited"), json!("ban")))
            .unwrap_err();
        assert!(format!("{err}").contains("not in allowed_transitions"));
    }

    #[test]
    fn join_walks_through_to_final_state() {
        let f = membership_fsm();
        let ops = vec![
            SealedOp::new(move_id(1), transition(json!("invited"), json!("join"))),
            SealedOp::new(move_id(2), transition(json!("join"), json!("leave"))),
            SealedOp::new(move_id(3), transition(json!("leave"), json!("join"))),
        ];
        assert_eq!(f.join(&cell(), &ops), CellState::Value(json!("join")));
    }

    #[test]
    fn join_rejects_op_when_from_doesnt_match_current() {
        let f = membership_fsm();
        // After this sequence current=join. Next op claims from=leave -> mismatch.
        let ops = vec![
            SealedOp::new(move_id(1), transition(json!("invited"), json!("join"))),
            SealedOp::new(move_id(2), transition(json!("leave"), json!("join"))),
        ];
        let state = f.join(&cell(), &ops);
        match state {
            CellState::Bottom(b) => {
                assert_eq!(b.kind, BottomKind::InvalidTransition);
                assert_eq!(b.move_ids, vec![move_id(2)]);
            }
            _ => panic!("expected Bottom"),
        }
    }

    #[test]
    fn join_with_undeclared_transition_yields_bottom() {
        let f = membership_fsm();
        // invited -> ban is not declared.
        let ops = vec![SealedOp::new(
            move_id(1),
            transition(json!("invited"), json!("ban")),
        )];
        let state = f.join(&cell(), &ops);
        assert!(state.is_bottom());
    }

    #[test]
    fn empty_join_returns_initial_state() {
        let f = membership_fsm();
        assert_eq!(f.join(&cell(), &[]), CellState::Value(json!("invited")));
    }

    #[test]
    fn empty_join_without_initial_returns_null() {
        let f = Fsm::new(vec![(json!("a"), json!("b"))]);
        assert_eq!(f.join(&cell(), &[]), CellState::Value(Value::Null));
    }

    #[test]
    fn kind_is_fsm() {
        assert_eq!(membership_fsm().kind(), LatticeKind::Fsm);
        assert_eq!(LatticeKind::Fsm.as_wire_str(), "fsm");
    }

    #[test]
    fn validate_rejects_non_transition_op() {
        let f = membership_fsm();
        let op = LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(json!("x")),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        f.validate_op(&op).expect_err("non-transition op must fail");
    }

    #[test]
    fn validate_rejects_missing_from() {
        let f = membership_fsm();
        let op = LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: None,
            to: Some(json!("join")),
            reason: None,
            issuer_seq: None,
        };
        let err = f.validate_op(&op).unwrap_err();
        assert!(format!("{err}").contains("requires field from"));
    }

    #[test]
    fn validate_rejects_missing_to() {
        let f = membership_fsm();
        let op = LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!("join")),
            to: None,
            reason: None,
            issuer_seq: None,
        };
        let err = f.validate_op(&op).unwrap_err();
        assert!(format!("{err}").contains("requires field to"));
    }
}

#[cfg(test)]
mod causal_regression_tests {
    use super::*;
    use crate::lattice::SealedOp;

    fn reversible() -> Fsm {
        Fsm::new(vec![
            (json!("active"), json!("archived")),
            (json!("archived"), json!("active")),
            (json!("active"), json!("active")),
            (json!("active"), json!("tombstoned")),
        ])
        .with_initial(json!("active"))
    }

    fn cell_ref() -> CellRef {
        CellRef::new("ak:cell:ak.component.strand.lifecycle.v1:ak.strand.0196".to_owned()).unwrap()
    }

    fn step(id: u8, from: Value, to: Value) -> SealedOp {
        SealedOp::new(
            crate::Hash::new(format!("sha256:{:064x}", id)).unwrap(),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                from: Some(from),
                to: Some(to),
                ..LatticeOp::empty()
            },
        )
    }

    /// A cell that legally returns to a state is at the start of that state's
    /// transitions again.
    ///
    /// `active -> archived -> active -> archived` must read `archived`. Deciding
    /// replay by the `(from, to)` pair alone folded the last step away and read
    /// `active` — the same failure `event-auth-state-resolution.md` §9.3.1.4
    /// names when it deletes the value-edge join for `cas_register`, reachable
    /// here on every reversible lifecycle family.
    #[test]
    fn a_reentered_transition_is_a_new_occurrence_not_a_replay() {
        let ops = vec![
            step(1, json!("active"), json!("archived")),
            step(2, json!("archived"), json!("active")),
            step(3, json!("active"), json!("archived")),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("archived")),
        );
    }

    /// Redelivering a transition the walk has already moved past stays a no-op,
    /// which is what keeps an at-least-once transport from rewinding a cell.
    #[test]
    fn a_redelivered_transition_is_still_idempotent() {
        let ops = vec![
            step(1, json!("active"), json!("archived")),
            step(1, json!("active"), json!("archived")),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("archived")),
        );
    }

    /// A registered self-loop must not consume the state it loops on.
    ///
    /// `ak.component.realm.link.v1` declares `(active, active)` precisely so a
    /// repeated declaration is legal. Recording it as "the transition out of
    /// active" then turned the next legal `active -> tombstoned` into a phantom
    /// `same_from_different_to` conflict.
    #[test]
    fn a_self_loop_does_not_poison_the_next_transition() {
        let ops = vec![
            step(1, json!("active"), json!("active")),
            step(2, json!("active"), json!("tombstoned")),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("tombstoned")),
        );
    }

    /// Two transitions out of a state the walk never returned to are still
    /// concurrent siblings, and still bottom with the kind the conformance
    /// vector requires.
    #[test]
    fn concurrent_siblings_still_conflict() {
        let ops = vec![
            step(1, json!("active"), json!("archived")),
            step(2, json!("active"), json!("tombstoned")),
        ];
        let CellState::Bottom(bottom) = reversible().join(&cell_ref(), &ops) else {
            panic!("two transitions out of one unrevisited state must conflict");
        };
        assert_eq!(bottom.kind, BottomKind::Conflict);
    }
}
