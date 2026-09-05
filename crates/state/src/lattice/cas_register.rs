//! CAS register Lattice.
//!
//! # Status: this join is the *superseded* v1 definition
//!
//! `event-auth-state-resolution.md` sections 9.3.1.1 to 9.3.1.4 replaced the
//! value-edge maximal-chain join with a causal register: state is the map from
//! the EventId of each still-active write to its canonical value, a write
//! supersedes exactly the heads it observed in its own signed `seal_basis`, and
//! Seal admission compares the full head-identity set `H_c(B) = H_c(P)`.
//!
//! The code below still implements the deleted definition. It is kept running
//! only so the tree stays green while the causal-heads migration lands; it is a
//! known non-conformance, not a second permitted semantics. Two concrete
//! consequences that this file gets **wrong** against the current spec:
//!
//! - `A -> B -> A` and `A -> B -> A -> B` deduplicate to the same `(value,
//!   from)` set, so it cannot read `A` for one and `B` for the other.
//! - `maximal_chain_terminals` enumerates chains by backtracking DFS, which is
//!   factorial when a cell legitimately reuses one value (a claim/release slot
//!   is exactly that shape).
//!
//! The migration is tracked in `arkret-work/work/active/2026-09-05-1030`; it
//! needs `SealedOp` to carry the derived superseded-head identities, the Seal
//! admission guard, the `{"heads":[...]}` `state_root` leaf, and the matching
//! soland op-log encoding.
//!
//! # What is already migrated
//!
//! The **initial state is now `null` protocol-wide** (section 9.3.1.2). The
//! registry's `initial_value` / `sentinel_writers` mechanism is deleted, and a
//! family that needs a reusable free slot registers an explicit `set null`
//! release write. `ak.component.invite.live_target.v1` is that shape.
//!
//! Unlike `mv_register`, dependent Moves must fail closed on Bottom because
//! this Lattice serves safety-critical state (e.g.
//! `ak.component.realm.policy.v1`, `ak.component.notary.v1`); the implicit
//! `bottom=reject` semantics are enforced by whichever cell registry uses it.

use serde_json::Value;

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{Bottom, BottomKind, CellRef, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct CasRegister;

/// One deduplicated `set` op, indexed for chain walking.
struct ChainOp<'a> {
    value: &'a Value,
    /// The whole-value `head_eq` the Move asserted on this cell, copied verbatim
    /// by the projector, or `None` when the Move asserted none.
    from: Option<&'a Value>,
    move_id: &'a crate::Hash,
}

impl ChainOp<'_> {
    /// A chain head asserts the cell's initial state (`null`) rather than a
    /// value some other op wrote: either by carrying no predecessor at all, or
    /// by naming `null` itself.
    ///
    /// Both forms stay chain heads *and* keep their supersession edges, which is
    /// what makes a released register reusable under this (superseded) join:
    /// `create -> release -> create` writes `set(id_1, from=null)`,
    /// `set(null, from=id_1)`, `set(id_2, from=null)`, and the third op both
    /// opens a chain and extends the second one.
    fn is_chain_head(&self, initial: &Value) -> bool {
        self.from.is_none_or(|from| from == initial)
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
                got: other.as_str().to_owned(),
                expected_kind: "cas_register",
            }),
        }
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        // Section 9.3.1.2: an unwritten cell reads `null` protocol-wide. There
        // is no registered per-family initial value any more.
        let initial = Value::Null;
        let ops = self.deduplicated_ops(sealed_ops);
        if ops.is_empty() {
            return CellState::Value(initial);
        }

        // A non-head op whose predecessor no value in the set produced cannot be
        // reached from any initial write. Under a prefix-closed coverage set this
        // is impossible, so it means the store is damaged or incomplete: fail
        // closed rather than settle on a chain that skipped it.
        let dangling: Vec<&ChainOp<'_>> = ops
            .iter()
            .filter(|op| {
                !op.is_chain_head(&initial)
                    && !ops.iter().any(|candidate| Some(candidate.value) == op.from)
            })
            .collect();
        if !dangling.is_empty() {
            return CellState::Bottom(conflict_bottom(cell, dangling.into_iter()));
        }

        let terminals = maximal_chain_terminals(&ops, &initial);
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
            let from = entry.op.from.as_ref();
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
fn maximal_chain_terminals(ops: &[ChainOp<'_>], initial: &Value) -> Vec<usize> {
    let mut terminals: Vec<usize> = Vec::new();
    let mut used = vec![false; ops.len()];
    for (index, op) in ops.iter().enumerate() {
        if !op.is_chain_head(initial) {
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
        bottom.head_ids.push(op.value.clone());
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

    /// The reusable claim/release slot family. It has no registered initial
    /// value any more: `governance-objects.md` section 5.3 requires the
    /// claiming `ak.invite.create` to assert `head_eq: null`, and the release
    /// Move to `set null`.
    fn slot_cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.invite.live_target.v1:fAWD6k02hF3JHnquwsCU7inqyb8Qdajftruz5xEWFGc"
                .to_owned(),
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
                assert_eq!(bottom.cell_ids, vec![cell()]);
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
        assert_eq!(bottom.head_ids.len(), 2);
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
        assert_eq!(bottom.head_ids.len(), 2);
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
        assert_eq!(bottom.head_ids, vec![json!({"policy": "open"})]);
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

    /// Every family settles an empty op set on `null`, the slot family
    /// included: section 9.3.1.2 removed the per-family initial value.
    #[test]
    fn empty_join_on_the_slot_family_is_also_null() {
        assert_eq!(
            CasRegister.join(&slot_cell(), &[]),
            CellState::Value(Value::Null)
        );
    }

    /// The first claim on a slot asserts `null`, which no op ever wrote.
    /// Treating that as a dangling supersession put the cell into `⊥` on the
    /// very first `ak.invite.create` in a Realm.
    #[test]
    fn null_predecessor_opens_a_chain_on_the_slot_family() {
        let create = json!("ak:event:AUC6BgHput8c8rn_dCCz43Ytxt5ZSdlxtE9subQRQcDF");
        let ops = vec![SealedOp::new(
            move_id(1),
            supersede_op(create.clone(), Value::Null),
        )];
        assert_eq!(
            CasRegister.join(&slot_cell(), &ops),
            CellState::Value(create)
        );
    }

    /// `governance-objects.md` section 5.3: the slot is a reusable register.
    /// The release write sets `null` and the next claim asserts `null`.
    ///
    /// Note what this (superseded) join cannot express: after the release the
    /// business value is `null`, exactly as it is on a slot nobody ever
    /// claimed, and nothing here distinguishes the two. Section 9.3.1.2 makes
    /// them different protocol states by keeping the release write's own head,
    /// and section 9.3.1.3 item 3 is what rejects a create pinned to the
    /// *earlier* free state. Neither is implemented yet.
    #[test]
    fn released_slot_is_reclaimable_by_a_later_write() {
        let first = json!("ak:event:AUC6BgHput8c8rn_dCCz43Ytxt5ZSdlxtE9subQRQcDF");
        let second = json!("ak:event:AVqlgW6dOb9VNRGuL5Gff6mz-9IKoTzaekCAJaNi2z43");
        let claim = SealedOp::new(move_id(1), supersede_op(first.clone(), Value::Null));
        let release = SealedOp::new(move_id(2), supersede_op(Value::Null, first));
        let reclaim = SealedOp::new(move_id(3), supersede_op(second.clone(), Value::Null));

        assert_eq!(
            CasRegister.join(&slot_cell(), &[claim.clone(), release.clone()]),
            CellState::Value(Value::Null)
        );
        assert_eq!(
            CasRegister.join(&slot_cell(), &[claim, release, reclaim]),
            CellState::Value(second)
        );
    }

    /// Two concurrent claims of one free slot are still siblings: the whole
    /// point of the register is that only one of them can hold it.
    #[test]
    fn concurrent_claims_on_a_free_slot_yield_conflict_bottom() {
        let ops = vec![
            SealedOp::new(
                move_id(1),
                supersede_op(json!("ak:event:AUC6Bg"), Value::Null),
            ),
            SealedOp::new(
                move_id(2),
                supersede_op(json!("ak:event:AVqlgW"), Value::Null),
            ),
        ];
        let CellState::Bottom(bottom) = CasRegister.join(&slot_cell(), &ops) else {
            panic!("concurrent slot claims must conflict");
        };
        assert_eq!(bottom.kind, BottomKind::Conflict);
        assert_eq!(bottom.head_ids.len(), 2);
    }

    /// A leftover `"__unset__"` string is now an ordinary value on every
    /// family, so naming one that nothing wrote is still a dangling
    /// supersession. This locks the sentinel out after its deletion.
    #[test]
    fn the_old_unset_sentinel_is_not_a_chain_head_anywhere() {
        for target in [cell(), slot_cell()] {
            let ops = vec![SealedOp::new(
                move_id(1),
                supersede_op(json!({"policy": "open"}), json!("__unset__")),
            )];
            let CellState::Bottom(bottom) = CasRegister.join(&target, &ops) else {
                panic!("a dangling sentinel predecessor must fail closed");
            };
            assert_eq!(bottom.kind, BottomKind::Conflict);
            assert_eq!(bottom.head_ids, vec![json!({"policy": "open"})]);
        }
    }

    #[test]
    fn kind_is_cas_register() {
        assert_eq!(CasRegister.kind(), LatticeKind::CasRegister);
        assert_eq!(LatticeKind::CasRegister.as_wire_str(), "cas_register");
    }
}
