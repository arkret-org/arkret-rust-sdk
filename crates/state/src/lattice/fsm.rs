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
/// It walks with the same three decisions [`Fsm::join`] makes, and must keep
/// doing so. Two folds of one state machine that disagree are worse than two
/// copies of one fold: the notary and the MLS governance proof replay would
/// then answer differently about the same membership cell, and the disagreement
/// would only surface on the histories the weaker one gets wrong.
///
/// `Err` is a history that does not fold at all: a non-transition op in a
/// transition cell, one identity carrying two different effects, a sibling that
/// contradicts an earlier transition out of a state the walk never returned to,
/// or a `from` that does not match the state the walk is in.
pub fn membership_transition_head_into(
    ops: &[crate::lattice::ordered_log::IssuedOp],
    target: &str,
) -> Result<Option<crate::Hash>, String> {
    let ops = ops
        .iter()
        .rposition(|issued| issued.op.recovery_reset)
        .map_or(ops, |boundary| &ops[boundary..]);
    let mut current = MEMBERSHIP_INITIAL_STATE.to_owned();
    let mut seen = std::collections::BTreeMap::<String, String>::new();
    let mut applied = std::collections::BTreeMap::<&str, (&str, &str)>::new();
    let mut head = None;
    for issued in ops {
        let from = issued.op.op.from.as_ref().and_then(Value::as_str);
        let to = issued.op.op.to.as_ref().and_then(Value::as_str);
        let (Some(from), Some(to)) = (from, to) else {
            return Err("membership cell contains a non-transition operation".to_owned());
        };
        // Exact replay is deduplicated by write identity. The `(from, to)` pair
        // cannot express it: membership is reversible, so one pair legitimately
        // occurs more than once, and two writers legitimately converge on one
        // pair.
        if let Some(&(previous_from, previous_to)) = applied.get(issued.op.move_id.as_str()) {
            if (previous_from, previous_to) == (from, to) {
                continue;
            }
            return Err(
                "one membership write identity carries two different transitions".to_owned(),
            );
        }
        applied.insert(issued.op.move_id.as_str(), (from, to));
        if current != from {
            // Not standing where this transition starts. Either a redelivery by
            // a second writer of a transition already folded in, a genuine
            // sibling of one, or a transition that is simply illegal here.
            if seen.get(from).map(String::as_str) == Some(to) {
                continue;
            }
            return Err(
                "membership operation history does not resolve to the effective FSM value"
                    .to_owned(),
            );
        }
        seen.insert(from.to_owned(), to.to_owned());
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
        // Exact replay is deduplicated by **write identity**, not by the
        // `(from, to)` pair. The pair cannot express it: on a reversible family
        // the same pair legitimately occurs more than once, and on a
        // convergent one two different Moves legitimately carry the same pair.
        // Only the identity says "this is the write I already folded in".
        let mut applied: HashMap<String, &LatticeOp> = HashMap::new();
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
            if let Some(previous) = applied.get(entry.move_id.as_str()) {
                if *previous == &entry.op {
                    // Redelivery of one write. Idempotent wherever it lands.
                    continue;
                }
                // One identity carrying two different canonical effects is a
                // verification error or a §6.3.3 digest collision. The lattice
                // must refuse rather than pick, exactly as `cas_heads` does.
                let mut bottom = Bottom::new(BottomKind::Conflict, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("current", current.clone().unwrap_or(Value::Null)),
                    ("from", from.clone()),
                    ("reason", json!("one_identity_two_effects")),
                    ("to", to.clone()),
                ]));
                return CellState::Bottom(bottom);
            }
            applied.insert(entry.move_id.as_str().to_owned(), &entry.op);
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
                    // A *different* Move carrying a transition already folded
                    // in — two writers converging on one state. The walk has
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

    /// Redelivering one write is idempotent wherever it lands, which is what
    /// keeps an at-least-once transport from rewinding a cell.
    ///
    /// The second case is the one that decides the dedup key: the walk is back
    /// at `active`, so this write's `from` matches again, and a `(from, to)`
    /// key would apply it a second time and read `archived`. Only the write
    /// identity says "already folded in".
    #[test]
    fn a_redelivered_write_is_idempotent_wherever_it_lands() {
        let ops = vec![
            step(1, json!("active"), json!("archived")),
            step(1, json!("active"), json!("archived")),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("archived")),
        );

        let returned = vec![
            step(1, json!("active"), json!("archived")),
            step(2, json!("archived"), json!("active")),
            step(1, json!("active"), json!("archived")),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &returned),
            CellState::Value(json!("active")),
        );
    }

    /// Two different writers converging on one transition still converge.
    #[test]
    fn two_writes_of_one_transition_converge() {
        let ops = vec![
            step(1, json!("active"), json!("archived")),
            step(2, json!("active"), json!("archived")),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("archived")),
        );
    }

    /// The shared membership fold answers the same three questions `join` does.
    ///
    /// It is a separate walk because it returns the identity that entered a
    /// target state rather than the state itself, and the notary and the MLS
    /// governance proof replay both read it. Two folds of one state machine
    /// that disagree are worse than two copies of one fold, and the
    /// disagreement would only show on the histories the weaker one gets wrong
    /// — which is exactly the ABA and self-loop shapes.
    #[test]
    fn the_shared_membership_fold_agrees_with_join() {
        use crate::lattice::ordered_log::IssuedOp;

        fn issued(id: u8, from: &str, to: &str) -> IssuedOp {
            IssuedOp {
                issuer_id: arkret_wire::ActorId::service(
                    arkret_wire::DidCoreId::new("ak:did_core:web:fixture.example".to_owned())
                        .unwrap(),
                ),
                op: step(id, json!(from), json!(to)),
            }
        }

        // Re-entry: `leave -> join -> leave -> join` reads `join`, and the head
        // is the *last* write into it, not the first.
        let reentered = vec![
            issued(1, "leave", "join"),
            issued(2, "join", "leave"),
            issued(3, "leave", "join"),
        ];
        assert_eq!(
            membership_transition_head_into(&reentered, "join").unwrap(),
            Some(reentered[2].op.move_id.clone()),
        );

        // Redelivery of one write stays a no-op even where its `from` matches
        // again.
        let mut redelivered = reentered.clone();
        redelivered.push(reentered[0].clone());
        assert_eq!(
            membership_transition_head_into(&redelivered, "join").unwrap(),
            Some(reentered[2].op.move_id.clone()),
        );

        // Two writers converging on one transition converge here too.
        let converged = vec![issued(1, "leave", "join"), issued(2, "leave", "join")];
        assert_eq!(
            membership_transition_head_into(&converged, "join").unwrap(),
            Some(converged[0].op.move_id.clone()),
        );

        // A genuine sibling out of a state the walk never returned to still
        // fails closed.
        let sibling = vec![issued(1, "leave", "join"), issued(2, "leave", "ban")];
        assert!(membership_transition_head_into(&sibling, "join").is_err());

        // One identity with two effects fails closed, as it does in `join`.
        let mut forked = vec![issued(1, "leave", "join")];
        forked.push(IssuedOp {
            op: step(1, json!("leave"), json!("ban")),
            ..forked[0].clone()
        });
        assert!(membership_transition_head_into(&forked, "join").is_err());
    }

    /// One identity carrying two different effects is a verification error or a
    /// digest collision. The lattice refuses rather than picking one.
    #[test]
    fn one_identity_with_two_effects_fails_closed() {
        let ops = vec![
            step(1, json!("active"), json!("archived")),
            step(1, json!("active"), json!("tombstoned")),
        ];
        let CellState::Bottom(bottom) = reversible().join(&cell_ref(), &ops) else {
            panic!("one identity with two effects must not resolve");
        };
        assert_eq!(bottom.kind, BottomKind::Conflict);
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
