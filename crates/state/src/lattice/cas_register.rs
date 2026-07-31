//! CAS register Lattice.
//!
//! Per `event-auth-state-resolution.md` §9.3.1:
//! - `set(value)` writes the cell and carries its predecessor in `op.from`: the projector copies
//!   the whole-value `head_eq` precondition that the Move asserted on this cell (an initial write
//!   asserts nothing and leaves `from` absent). Reachability therefore reaches the join without the
//!   join needing Seal-DAG input.
//! - The join is the pure maximal-chain function: dedup by `(value, from)`, `Y.from == X.value` is
//!   a supersession edge, and the cell settles when every maximal chain ends on the same value.
//!   Sequential governance lifecycles (declaration -> tombstone -> declaration) settle; concurrent
//!   siblings on one predecessor, and dangling supersessions, produce a `kind=conflict` Bottom.
//!
//! Unlike `mv_register`, dependent Moves must fail closed on that Bottom because
//! this Lattice serves safety-critical state (e.g.
//! `ak.component.realm.policy.v1`, `ak.component.notary.v1`); the implicit
//! `bottom=reject` semantics are enforced by whichever cell registry uses it.
//!
//! Supersession binds by **value**, the same comparison `head_eq` performs, so
//! value reuse (ABA) is indistinguishable by design; a family that needs
//! generations carries a monotonic component inside the value itself (e.g.
//! `policy_bundle.policy_revision`).

use serde_json::Value;

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{Bottom, BottomKind, CellRef, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct CasRegister;

/// One deduplicated `set` op, indexed for chain walking.
struct ChainOp<'a> {
    value: &'a Value,
    /// The superseded predecessor value, or `None` for a chain head. An explicit
    /// `null` predecessor *is* a chain head: the settled value of an absent cell
    /// is `null`, so `head_eq null` asserts the initial state rather than naming
    /// a value some other op wrote.
    from: Option<&'a Value>,
    move_id: &'a crate::Hash,
}

impl ChainOp<'_> {
    fn is_chain_head(&self) -> bool {
        self.from.is_none()
    }
}

impl Lattice for CasRegister {
    fn kind(&self) -> LatticeKind {
        LatticeKind::CasRegister
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Set => {
                if op.value.is_none() {
                    return Err(OpError::MissingField {
                        kind: "cas_register",
                        field: "value",
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: format!("{other:?}").to_lowercase(),
                expected_kind: "cas_register",
            }),
        }
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        let ops = self.deduplicated_ops(sealed_ops);
        if ops.is_empty() {
            return CellState::Value(Value::Null);
        }

        // A non-head op whose predecessor no value in the set produced cannot be
        // reached from any initial write. Under a prefix-closed coverage set this
        // is impossible, so it means the store is damaged or incomplete: fail
        // closed rather than settle on a chain that skipped it.
        let dangling: Vec<&ChainOp<'_>> = ops
            .iter()
            .filter(|op| {
                !op.is_chain_head() && !ops.iter().any(|candidate| Some(candidate.value) == op.from)
            })
            .collect();
        if !dangling.is_empty() {
            return CellState::Bottom(conflict_bottom(cell, dangling.into_iter()));
        }

        let terminals = maximal_chain_terminals(&ops);
        match terminals.len() {
            1 => CellState::Value(ops[terminals[0]].value.clone()),
            // A non-empty set with no dangling op and no chain head is a cycle
            // reachable from nothing — the same unreachability the dangling check
            // catches, so report every op rather than an empty diagnostic.
            0 => CellState::Bottom(conflict_bottom(cell, ops.iter())),
            _ => CellState::Bottom(conflict_bottom(
                cell,
                terminals.iter().map(|index| &ops[*index]),
            )),
        }
    }
}

impl CasRegister {
    /// Valid `set` ops, deduplicated by `(value, from)`.
    ///
    /// Repeating a `(value, from)` pair is idempotent and MUST NOT open a second
    /// chain; only distinct pairs are distinct ops.
    fn deduplicated_ops<'a>(&self, sealed_ops: &'a [SealedOp]) -> Vec<ChainOp<'a>> {
        let mut ops: Vec<ChainOp<'a>> = Vec::new();
        for entry in sealed_ops
            .iter()
            .filter(|entry| self.validate_op(&entry.op).is_ok())
        {
            let Some(value) = entry.op.value.as_ref() else {
                continue;
            };
            let from = entry.op.from.as_ref().filter(|from| !from.is_null());
            if ops
                .iter()
                .any(|existing| existing.value == value && existing.from == from)
            {
                continue;
            }
            ops.push(ChainOp {
                value,
                from,
                move_id: &entry.move_id,
            });
        }
        ops
    }
}

/// One op index per **distinct** value that terminates a maximal supersession
/// chain.
///
/// A chain starts at a chain head, follows `Y.from == X.value` edges, uses each
/// op at most once (which is what terminates an ABA cycle), and is maximal when
/// no unused op supersedes its last value. Two chains ending on the same value
/// agree, so terminals are deduplicated by value; enumeration stops as soon as a
/// second distinct value appears, because the cell is already `⊥` at that point.
fn maximal_chain_terminals(ops: &[ChainOp<'_>]) -> Vec<usize> {
    let mut terminals: Vec<usize> = Vec::new();
    let mut used = vec![false; ops.len()];
    for (index, op) in ops.iter().enumerate() {
        if !op.is_chain_head() {
            continue;
        }
        walk_chain(ops, index, &mut used, &mut terminals);
        if terminals.len() > 1 {
            break;
        }
    }
    terminals
}

fn walk_chain(ops: &[ChainOp<'_>], current: usize, used: &mut [bool], terminals: &mut Vec<usize>) {
    if terminals.len() > 1 {
        return;
    }
    used[current] = true;
    let mut extended = false;
    for index in 0..ops.len() {
        if used[index] || ops[index].from != Some(ops[current].value) {
            continue;
        }
        extended = true;
        walk_chain(ops, index, used, terminals);
    }
    if !extended
        && !terminals
            .iter()
            .any(|terminal| ops[*terminal].value == ops[current].value)
    {
        terminals.push(current);
    }
    used[current] = false;
}

fn conflict_bottom<'a>(cell: &CellRef, ops: impl Iterator<Item = &'a ChainOp<'a>>) -> Bottom {
    let mut bottom = Bottom::new(BottomKind::Conflict, vec![cell.clone()]);
    for op in ops {
        bottom.move_ids.push(op.move_id.clone());
        bottom.heads.push(op.value.clone());
    }
    bottom
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Hash, LatticeOp};

    fn cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn set_op(value: Value) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    fn supersede_op(value: Value, from: Value) -> LatticeOp {
        LatticeOp {
            from: Some(from),
            ..set_op(value)
        }
    }

    fn expect_bottom(state: CellState) -> Bottom {
        match state {
            CellState::Bottom(bottom) => {
                assert_eq!(bottom.kind, BottomKind::Conflict);
                assert_eq!(bottom.cells, vec![cell()]);
                bottom
            }
            other => panic!("expected Bottom, got {other:?}"),
        }
    }

    #[test]
    fn single_set_value_resolved() {
        let ops = vec![SealedOp::new(move_id(1), set_op(json!({"policy": "open"})))];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(json!({"policy": "open"}))
        );
    }

    /// Vector case 1: the policy-server §2.2 lifecycle settles instead of
    /// collapsing to `⊥` the moment the cell is written a second time.
    #[test]
    fn sequential_governance_lifecycle_settles_on_the_last_value() {
        let declaration = json!({"policy_server": "ak.principal.01js0sp00000000000000000aa"});
        let tombstone = json!({"tombstone": true});
        let redeclaration = json!({"policy_server": "ak.principal.01js0sp00000000000000000bb"});
        let ops = vec![
            SealedOp::new(move_id(1), set_op(declaration.clone())),
            SealedOp::new(move_id(2), supersede_op(tombstone.clone(), declaration)),
            SealedOp::new(move_id(3), supersede_op(redeclaration.clone(), tombstone)),
        ];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(redeclaration)
        );
    }

    /// Vector case 2: two different values superseding the same predecessor are
    /// concurrent siblings, which is exactly what `⊥` is for.
    #[test]
    fn concurrent_siblings_on_one_predecessor_yield_conflict_bottom() {
        let declaration = json!({"policy": "declared"});
        let ops = vec![
            SealedOp::new(move_id(1), set_op(declaration.clone())),
            SealedOp::new(
                move_id(2),
                supersede_op(json!({"policy": "open"}), declaration.clone()),
            ),
            SealedOp::new(
                move_id(3),
                supersede_op(json!({"policy": "closed"}), declaration),
            ),
        ];
        let bottom = expect_bottom(CasRegister.join(&cell(), &ops));
        assert_eq!(bottom.heads.len(), 2);
        assert_eq!(bottom.move_ids.len(), 2);
    }

    /// Two initial writes are still siblings: both are chain heads.
    #[test]
    fn two_concurrent_initial_sets_yield_conflict_bottom() {
        let ops = vec![
            SealedOp::new(move_id(1), set_op(json!({"policy": "open"}))),
            SealedOp::new(move_id(2), set_op(json!({"policy": "closed"}))),
        ];
        let bottom = expect_bottom(CasRegister.join(&cell(), &ops));
        assert_eq!(bottom.heads.len(), 2);
        assert_eq!(bottom.move_ids.len(), 2);
    }

    /// Vector case 3: a supersession whose predecessor no op produced cannot have
    /// come from a prefix-closed coverage set.
    #[test]
    fn dangling_supersession_fails_closed() {
        let ops = vec![
            SealedOp::new(move_id(1), set_op(json!({"policy": "declared"}))),
            SealedOp::new(
                move_id(2),
                supersede_op(
                    json!({"policy": "open"}),
                    json!({"policy": "never_written"}),
                ),
            ),
        ];
        let bottom = expect_bottom(CasRegister.join(&cell(), &ops));
        assert_eq!(bottom.heads, vec![json!({"policy": "open"})]);
    }

    /// Vector case 4: `(value, from)` is the identity of a write.
    #[test]
    fn repeated_same_value_and_predecessor_sets_are_idempotent() {
        let declaration = json!("declared");
        let ops = vec![
            SealedOp::new(move_id(1), set_op(declaration.clone())),
            SealedOp::new(move_id(2), set_op(declaration.clone())),
            SealedOp::new(
                move_id(3),
                supersede_op(json!("closed"), declaration.clone()),
            ),
            SealedOp::new(move_id(4), supersede_op(json!("closed"), declaration)),
        ];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(json!("closed"))
        );
    }

    /// Vector case 5: value reuse is indistinguishable by design, so the chain
    /// walk converges on the longest chain's terminal rather than branching.
    #[test]
    fn value_reuse_converges_on_the_longest_chain() {
        let ops = vec![
            SealedOp::new(move_id(1), set_op(json!("a"))),
            SealedOp::new(move_id(2), supersede_op(json!("b"), json!("a"))),
            SealedOp::new(move_id(3), supersede_op(json!("a"), json!("b"))),
        ];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(json!("a"))
        );
    }

    /// Vector case 6: any prefix-closed subset recomputes that subset's view.
    #[test]
    fn prefix_closed_subsets_recompute_their_historical_view() {
        let declaration = json!({"policy": "declared"});
        let tombstone = json!({"tombstone": true});
        let full = vec![
            SealedOp::new(move_id(1), set_op(declaration.clone())),
            SealedOp::new(
                move_id(2),
                supersede_op(tombstone.clone(), declaration.clone()),
            ),
        ];
        assert_eq!(
            CasRegister.join(&cell(), &full[..1]),
            CellState::Value(declaration)
        );
        assert_eq!(
            CasRegister.join(&cell(), &full),
            CellState::Value(tombstone)
        );
    }

    /// `head_eq null` asserts the initial state, so it opens a chain rather than
    /// naming a predecessor value no op ever wrote.
    #[test]
    fn explicit_null_predecessor_is_a_chain_head() {
        let ops = vec![
            SealedOp::new(
                move_id(1),
                supersede_op(json!({"policy": "declared"}), Value::Null),
            ),
            SealedOp::new(
                move_id(2),
                supersede_op(json!({"tombstone": true}), json!({"policy": "declared"})),
            ),
        ];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(json!({"tombstone": true}))
        );
    }

    #[test]
    fn validate_rejects_non_set() {
        let op = LatticeOp {
            op_type: LatticeOpType::Inc,
            tag: None,
            value: Some(json!(1)),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        CasRegister
            .validate_op(&op)
            .expect_err("non-set op must fail");
    }

    #[test]
    fn empty_join_returns_null() {
        assert_eq!(
            CasRegister.join(&cell(), &[]),
            CellState::Value(Value::Null)
        );
    }

    #[test]
    fn kind_is_cas_register() {
        assert_eq!(CasRegister.kind(), LatticeKind::CasRegister);
        assert_eq!(LatticeKind::CasRegister.as_wire_str(), "cas_register");
    }
}
