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

/// The registered initial state of `ak.fsm.membership.v1`.
///
/// The membership state machine is shared by `ak.component.member.state.v1` and
/// `ak.component.circle.member.v1`, and its contract lives in
/// `contract-registry.json` under `event_kind_registry.fsm_templates`. This
/// constant exists because the callers of
/// [`membership_transition_heads_into`] sit below the lattice registry that
/// resolves that contract, and repeating the literal at each of them is how
/// three separate copies of this fold came to exist.
///
/// The transition algebra itself is resolved (§9.3.1.5-§9.3.1.8, ruling in
/// `arkret-work/review/spec-done/
/// 2026-09-06-2056-station-sealed-control-chain-and-independent-recovery.md` section 8), and the
/// fold is gone: this is now the registry literal that one caller still reaches for, not a parallel
/// state machine.
pub const MEMBERSHIP_INITIAL_STATE: &str = "leave";

/// The active head identities that put a membership cell in `target`
/// (§9.3.1.5 / §9.3.1.6).
///
/// This used to be an arrival-ordered fold returning "the" head, carried in
/// three independent copies with three hardcoded initial states. §9.3.1.8 says
/// a consumer of this lattice MUST read it the way the lattice does, so it is
/// now the same [`fsm_heads`] every other reader gets.
///
/// It returns a set because the state is one: two concurrent writes may both
/// legitimately carry `to = target`, and §9.3.1.6 keeps both identities. There
/// is a total order on heads, but it fixes bytes and selects no winner — a
/// caller that needs exactly one identity MUST fail closed on more, not take
/// the first. An empty result means the cell does not resolve to `target`,
/// which includes the `⊥` case.
///
/// `Err` is a history that does not resolve at all: a non-transition op in a
/// transition cell, or one identity carrying two different transitions.
pub fn membership_transition_heads_into(
    ops: &[crate::lattice::ordered_log::IssuedOp],
    target: &str,
) -> Result<Vec<crate::Hash>, String> {
    let sealed: Vec<SealedOp> = ops.iter().map(|issued| issued.op.clone()).collect();
    if let Some(bad) = sealed
        .iter()
        .find(|entry| entry.op.op_type != LatticeOpType::Transition)
    {
        return Err(format!(
            "membership cell contains a non-transition operation ({})",
            bad.move_id.as_str()
        ));
    }
    let heads = fsm_heads(&sealed).map_err(|_| {
        "one membership write identity carries two different transitions".to_owned()
    })?;
    let settled = heads.first().map(|head| &head.value);
    if heads.iter().any(|head| Some(&head.value) != settled) {
        // `⊥`: the cell resolves to no state at all, so it resolves to no
        // target either.
        return Ok(Vec::new());
    }
    if settled.and_then(Value::as_str) != Some(target) {
        return Ok(Vec::new());
    }
    Ok(heads.into_iter().map(|head| head.move_id).collect())
}

/// The still-active transition writes of one `fsm` cell (§9.3.1.5).
///
/// Identical to [`crate::lattice::cas_register::cas_heads`] except that a head
/// carries the transition's `to`. `from` is not here on purpose: it is the
/// write's admission assertion against its own signed basis (§9.3.1.7 item 2),
/// not a join-time edge. Reading the op list as a path is what made the fold
/// non-commutative, made `(from,to)` deduplication misread ABA, and let a
/// registered self-loop poison the next legal transition.
pub fn fsm_heads(
    sealed_ops: &[SealedOp],
) -> Result<Vec<crate::lattice::cas_register::CasHead>, Box<Bottom>> {
    crate::lattice::cas_register::causal_heads(
        sealed_ops,
        // The §9.5.1 recovery is a head like any other — it is a new identity
        // write that supersedes the divergent heads, not a boundary that erases
        // them. It differs only in carrying no `from` (see
        // [`Fsm::validate_recovery_op`]), so requiring one here would drop the
        // recovery from the head set and leave the cell in `⊥` forever.
        |entry| {
            entry.op.op_type == LatticeOpType::Transition
                && entry.op.to.is_some()
                && (entry.recovery_reset || entry.op.from.is_some())
        },
        |op| op.to.clone().unwrap_or(Value::Null),
    )
}

/// The settled state of an `fsm` cell from its active heads (§9.3.1.6).
///
/// Empty heads read the registered initial state — the one place `fsm` differs
/// from `cas_register`, which reads `null`. Heads that agree read that state and
/// keep every identity; heads that disagree are `⊥`.
fn settled_from_heads(
    cell: &CellRef,
    initial_state: Option<&Value>,
    heads: &[crate::lattice::cas_register::CasHead],
) -> CellState {
    let Some(first) = heads.first() else {
        return CellState::Value(initial_state.cloned().unwrap_or(Value::Null));
    };
    if let Some(divergent) = heads.iter().find(|head| head.value != first.value) {
        let mut bottom = Bottom::new(BottomKind::Conflict, vec![cell.clone()]);
        bottom.move_ids = heads.iter().map(|head| head.move_id.clone()).collect();
        bottom.head_ids = heads.iter().map(|head| head.value.clone()).collect();
        bottom.details = Some(bottom_details([
            ("reason", json!("same_from_different_to")),
            ("to", divergent.value.clone()),
        ]));
        return CellState::Bottom(bottom);
    }
    CellState::Value(first.value.clone())
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

    /// §9.5.1: the recovery write is a `transition` carrying only its `to`.
    ///
    /// It MUST NOT carry a `from`. A recovery target is by definition in `⊥`,
    /// which for this lattice means two or more divergent `to` heads
    /// (§9.3.1.6), so the write supersedes several source states at once and no
    /// single `from` names them. Inventing one — the last head, the lowest
    /// head, the pre-conflict value — would be a producer-invisible choice that
    /// two receivers could make differently. The sources are checked as a set
    /// by [`Fsm::validate_recovery_sources`] instead.
    fn validate_recovery_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        if op.op_type != LatticeOpType::Transition {
            return Err(OpError::UnsupportedOpType {
                got: op.op_type.as_str().to_owned(),
                expected_kind: "fsm",
            });
        }
        if op.to.is_none() {
            return Err(OpError::MissingField {
                kind: "fsm",
                field: "to",
            });
        }
        if let Some(from) = &op.from {
            return Err(OpError::InvalidValue {
                kind: "fsm",
                field: "from",
                reason: format!(
                    "a recovery write supersedes every divergent head, so it carries no single \
                     from; got {from}"
                ),
            });
        }
        Ok(())
    }

    /// §9.5.1 `fsm` additional admission: the recovery MUST be a registered
    /// transition out of **every** head it supersedes.
    ///
    /// `terminal_states` needs no separate lookup. A terminal state carries no
    /// outgoing edge in `allowed_transitions` except a registered self-loop, so
    /// "a recovery out of a terminal state is rejected unless it is that
    /// registered self-loop" is exactly what table membership already says. The
    /// registry invariant that makes this equivalence hold is enforced by
    /// `arkret-spec/tools/artifact_lint`, not assumed here.
    fn validate_recovery_sources(&self, sources: &[Value], op: &LatticeOp) -> Result<(), OpError> {
        let Some(to) = op.to.as_ref() else {
            return Err(OpError::MissingField {
                kind: "fsm",
                field: "to",
            });
        };
        if sources.is_empty() {
            // Fail closed rather than vacuously true: an empty source set means
            // the caller could not see the basis heads, and a recovery admitted
            // without them has had no transition check at all.
            return Err(OpError::InvalidValue {
                kind: "fsm",
                field: "from",
                reason: "recovery basis heads are unavailable, so its transition cannot be checked"
                    .to_owned(),
            });
        }
        if let Some(source) = sources.iter().find(|source| !self.is_allowed(source, to)) {
            return Err(OpError::InvalidValue {
                kind: "fsm",
                field: "transition",
                reason: format!(
                    "recovery to {to} is not in allowed_transitions from the superseded head \
                     {source}"
                ),
            });
        }
        Ok(())
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        // §9.3.1.5: the state is the active write identities, each carrying its
        // `to`. Nothing here reads the op list as a sequence — that is what the
        // arrival-ordered fold did, and it is why the same op set gave
        // different answers under different delivery orders.
        //
        // A malformed op is not silently skipped the way `cas_heads` skips one:
        // a transition cell whose op carries no `from`/`to`, or one outside the
        // registered table, is an admission failure that reached the join, and
        // §9.3.1.7 makes that a rejection rather than a state.
        //
        // A §9.5.1 recovery is held to its own shape: it carries no `from`, so
        // running the ordinary check on it would Bottom the cell on the one
        // write whose whole purpose is to lift it out of `⊥`.
        for entry in sealed_ops {
            let shape = if entry.recovery_reset {
                self.validate_recovery_op(&entry.op)
            } else {
                self.validate_op(&entry.op)
            };
            if shape.is_err() {
                let mut bottom = Bottom::new(BottomKind::InvalidTransition, vec![cell.clone()]);
                bottom.move_ids = vec![entry.move_id.clone()];
                bottom.details = Some(bottom_details([
                    ("from", entry.op.from.clone().unwrap_or(Value::Null)),
                    ("to", entry.op.to.clone().unwrap_or(Value::Null)),
                ]));
                return CellState::Bottom(bottom);
            }
        }
        match fsm_heads(sealed_ops) {
            Ok(heads) => settled_from_heads(cell, self.initial_state.as_ref(), &heads),
            Err(mut bottom) => {
                // One identity carrying two different `to` values is a
                // verification error or a §6.3.3 digest collision. The lattice
                // refuses rather than picks, exactly as `cas_heads` does.
                bottom.cell_ids = vec![cell.clone()];
                bottom.details = Some(bottom_details([(
                    "reason",
                    json!("one_identity_two_effects"),
                )]));
                CellState::Bottom(*bottom)
            }
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

    /// A causal chain leaves exactly its terminal write as the head.
    ///
    /// `supersedes` is what says so — the reducer derives it from each write's
    /// own verified basis (§9.3.1.7 item 4). The join never infers succession
    /// from the order the ops arrive in.
    #[test]
    fn a_causal_chain_leaves_its_terminal_write_as_the_head() {
        let f = membership_fsm();
        let ops = vec![
            SealedOp::new(move_id(1), transition(json!("invited"), json!("join"))),
            SealedOp::superseding(
                move_id(2),
                transition(json!("join"), json!("leave")),
                vec![move_id(1)],
            ),
            SealedOp::superseding(
                move_id(3),
                transition(json!("leave"), json!("join")),
                vec![move_id(2)],
            ),
        ];
        assert_eq!(f.join(&cell(), &ops), CellState::Value(json!("join")));

        // The same set in any other order is the same state. A sequential fold
        // answers differently here; a causal one cannot.
        let mut reversed = ops.clone();
        reversed.reverse();
        assert_eq!(f.join(&cell(), &reversed), f.join(&cell(), &ops));
    }

    /// A `from` that does not match is an **admission** failure, not a join
    /// outcome (§9.3.1.7 item 2).
    ///
    /// The join is given writes whose bases were already checked, so it does not
    /// re-derive a walk to test `from` against. Here the two writes superseded
    /// nothing and disagree on `to`, so they are concurrent siblings and the
    /// cell is `⊥` — which is what §9.3.1.6 says, and it does not depend on
    /// which of them arrived first.
    #[test]
    fn concurrent_writes_that_disagree_on_to_are_bottom_regardless_of_order() {
        let f = membership_fsm();
        let ops = vec![
            SealedOp::new(move_id(1), transition(json!("invited"), json!("join"))),
            SealedOp::new(move_id(2), transition(json!("leave"), json!("join"))),
        ];
        // Both write `to = "join"`, so they agree and both stay heads.
        assert_eq!(f.join(&cell(), &ops), CellState::Value(json!("join")));

        let divergent = vec![
            SealedOp::new(move_id(1), transition(json!("invited"), json!("join"))),
            SealedOp::new(move_id(2), transition(json!("join"), json!("leave"))),
        ];
        let CellState::Bottom(bottom) = f.join(&cell(), &divergent) else {
            panic!("two concurrent writes with different `to` are bottom");
        };
        assert_eq!(bottom.kind, BottomKind::Conflict);
        assert_eq!(bottom.move_ids, vec![move_id(1), move_id(2)]);

        let mut swapped = divergent.clone();
        swapped.reverse();
        assert_eq!(f.join(&cell(), &swapped), f.join(&cell(), &divergent));
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

    fn move_of(id: u8) -> crate::Hash {
        crate::Hash::new(format!("sha256:{:064x}", id)).unwrap()
    }

    /// One transition write, plus the head identities its own verified basis
    /// observed. The reducer derives `supersedes` (§9.3.1.7 item 4); nothing
    /// about it is inferred from the order these land in a list.
    fn step(id: u8, from: Value, to: Value, saw: &[u8]) -> SealedOp {
        SealedOp::superseding(
            move_of(id),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                from: Some(from),
                to: Some(to),
                ..LatticeOp::empty()
            },
            saw.iter().copied().map(move_of).collect(),
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
            step(1, json!("active"), json!("archived"), &[]),
            step(2, json!("archived"), json!("active"), &[1]),
            step(3, json!("active"), json!("archived"), &[2]),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("archived")),
        );

        // The three-step chain and the two-step one differ only in the third
        // write's identity; a `(from, to)` key cannot tell them apart.
        assert_eq!(
            reversible().join(&cell_ref(), &ops[..2]),
            CellState::Value(json!("active")),
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
            step(1, json!("active"), json!("archived"), &[]),
            step(1, json!("active"), json!("archived"), &[]),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("archived")),
        );

        let returned = vec![
            step(1, json!("active"), json!("archived"), &[]),
            step(2, json!("archived"), json!("active"), &[1]),
            step(1, json!("active"), json!("archived"), &[]),
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
            step(1, json!("active"), json!("archived"), &[]),
            step(2, json!("active"), json!("archived"), &[]),
        ];
        assert_eq!(
            reversible().join(&cell_ref(), &ops),
            CellState::Value(json!("archived")),
        );
        // Two identities, one settled state: §9.3.1.6 keeps both heads, so a
        // peer that only saw the first is still told about the second.
        assert_eq!(fsm_heads(&ops).expect("both heads survive").len(), 2);
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

        fn issued(id: u8, from: &str, to: &str, saw: &[u8]) -> IssuedOp {
            IssuedOp {
                issuer_id: arkret_wire::ActorId::service(
                    arkret_wire::DidCoreId::new("ak:did_core:web:fixture.example".to_owned())
                        .unwrap(),
                ),
                op: step(id, json!(from), json!(to), saw),
            }
        }

        // Re-entry: `leave -> join -> leave -> join` resolves to `join`, and
        // the head is the write that put it there — identified causally, not by
        // being last in the list.
        let reentered = vec![
            issued(1, "leave", "join", &[]),
            issued(2, "join", "leave", &[1]),
            issued(3, "leave", "join", &[2]),
        ];
        assert_eq!(
            membership_transition_heads_into(&reentered, "join").unwrap(),
            vec![reentered[2].op.move_id.clone()],
        );

        // The same set in any order is the same answer. That is the property
        // the arrival-ordered fold could not offer.
        let mut shuffled = reentered.clone();
        shuffled.reverse();
        assert_eq!(
            membership_transition_heads_into(&shuffled, "join").unwrap(),
            membership_transition_heads_into(&reentered, "join").unwrap(),
        );

        // Redelivery of one write stays a no-op.
        let mut redelivered = reentered.clone();
        redelivered.push(reentered[0].clone());
        assert_eq!(
            membership_transition_heads_into(&redelivered, "join").unwrap(),
            vec![reentered[2].op.move_id.clone()],
        );

        // Two writers converging on one transition keep **both** identities:
        // the state is one, the writes are two, and a caller that needs exactly
        // one must fail closed rather than take the first.
        let converged = vec![
            issued(1, "leave", "join", &[]),
            issued(2, "leave", "join", &[]),
        ];
        assert_eq!(
            membership_transition_heads_into(&converged, "join")
                .unwrap()
                .len(),
            2
        );

        // A genuine sibling with a different `to` puts the cell in `⊥`, so it
        // resolves to no target at all.
        let sibling = vec![
            issued(1, "leave", "join", &[]),
            issued(2, "leave", "ban", &[]),
        ];
        assert!(
            membership_transition_heads_into(&sibling, "join")
                .unwrap()
                .is_empty()
        );

        // One identity with two effects fails closed, as it does in `join`.
        let mut forked = vec![issued(1, "leave", "join", &[])];
        forked.push(IssuedOp {
            op: step(1, json!("leave"), json!("ban"), &[]),
            ..forked[0].clone()
        });
        assert!(membership_transition_heads_into(&forked, "join").is_err());
    }

    /// One identity carrying two different effects is a verification error or a
    /// digest collision. The lattice refuses rather than picking one.
    #[test]
    fn one_identity_with_two_effects_fails_closed() {
        let ops = vec![
            step(1, json!("active"), json!("archived"), &[]),
            step(1, json!("active"), json!("tombstoned"), &[]),
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
            step(1, json!("active"), json!("active"), &[]),
            step(2, json!("active"), json!("tombstoned"), &[1]),
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
            step(1, json!("active"), json!("archived"), &[]),
            step(2, json!("active"), json!("tombstoned"), &[]),
        ];
        let CellState::Bottom(bottom) = reversible().join(&cell_ref(), &ops) else {
            panic!("two transitions out of one unrevisited state must conflict");
        };
        assert_eq!(bottom.kind, BottomKind::Conflict);
    }
}
