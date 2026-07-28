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
                got: format!("{other:?}").to_lowercase(),
                expected_kind: "fsm",
            }),
        }
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        let mut current: Option<Value> = self.initial_state.clone();
        let mut seen_transitions: Vec<(Value, Value)> = Vec::new();
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
            let from = op.from.clone().unwrap();
            let to = op.to.clone().unwrap();
            if seen_transitions
                .iter()
                .any(|(seen_from, seen_to)| seen_from == &from && seen_to == &to)
            {
                continue;
            }
            if seen_transitions
                .iter()
                .any(|(seen_from, seen_to)| seen_from == &from && seen_to != &to)
            {
                let mut bottom = Bottom::new(BottomKind::Conflict, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("current", current.clone().unwrap_or(Value::Null)),
                    ("from", from),
                    ("reason", json!("same_from_different_to")),
                    ("to", to),
                ]));
                return CellState::Bottom(bottom);
            }
            // If we have a current state, the op's `from` must match it.
            // A None current means we accept the first transition's
            // `from` only if it matches the declared initial state (if
            // any) or there is no initial state.
            if let Some(ref cur) = current
                && cur != &from
            {
                let mut bottom = Bottom::new(BottomKind::InvalidTransition, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("current", cur.clone()),
                    ("expected_from", cur.clone()),
                    ("from", from),
                    ("to", to),
                ]));
                return CellState::Bottom(bottom);
            }
            seen_transitions.push((from.clone(), to.clone()));
            current = Some(to);
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
