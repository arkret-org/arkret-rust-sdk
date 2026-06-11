//! Multi-value register Lattice.
//!
//! Per spec §5.3:
//! - Single `set(value)` op produces `value`.
//! - Multiple concurrent `set` ops produce a `kind=conflict` Bottom whose `heads[]` contains every
//!   concurrent value (default `bottom=expose`).
//!
//! "Concurrent" here means there is no causal ordering provided by the
//! Seal — two `set` ops in the same Seal frontier with no causal
//! refs are concurrent. The runtime that builds `sealed_ops` is
//! responsible for collapsing causally-ordered chains; this trait method
//! sees only the surviving heads.

use serde_json::Value;

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{Bottom, BottomKind, CellRef, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct MvRegister;

impl Lattice for MvRegister {
    fn kind(&self) -> LatticeKind {
        LatticeKind::MvRegister
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Set => {
                if op.value.is_none() {
                    return Err(OpError::MissingField {
                        kind: "mv_register",
                        field: "value",
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: format!("{other:?}").to_lowercase(),
                expected_kind: "mv_register",
            }),
        }
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        let valid_ops: Vec<&SealedOp> = sealed_ops
            .iter()
            .filter(|e| self.validate_op(&e.op).is_ok())
            .collect();
        match valid_ops.len() {
            0 => CellState::Value(Value::Null),
            1 => CellState::Value(valid_ops[0].op.value.clone().unwrap_or(Value::Null)),
            _ => {
                let heads: Vec<Value> = valid_ops
                    .iter()
                    .filter_map(|e| e.op.value.clone())
                    .collect();
                let move_ids = valid_ops.iter().map(|e| e.move_id.clone()).collect();
                let mut bottom = Bottom::new(BottomKind::Conflict, vec![cell.clone()]);
                bottom.move_ids = move_ids;
                bottom.heads = heads;
                CellState::Bottom(bottom)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{LatticeOp, MoveId};

    fn cell() -> CellRef {
        CellRef::new(
            "ck:cell:ck.component.space.title.v1:ck.space.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
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

    #[test]
    fn validate_rejects_non_set() {
        let op = LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some("t".into()),
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        MvRegister
            .validate_op(&op)
            .expect_err("non-set op must fail");
    }

    #[test]
    fn validate_rejects_set_without_value() {
        let op = LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        MvRegister
            .validate_op(&op)
            .expect_err("set without value must fail");
    }

    #[test]
    fn empty_join_yields_null() {
        assert_eq!(MvRegister.join(&cell(), &[]), CellState::Value(Value::Null));
    }

    #[test]
    fn single_set_returns_value() {
        let ops = vec![SealedOp::new(move_id(1), set_op(json!("hello")))];
        assert_eq!(
            MvRegister.join(&cell(), &ops),
            CellState::Value(json!("hello"))
        );
    }

    #[test]
    fn two_concurrent_sets_yields_conflict_bottom() {
        let ops = vec![
            SealedOp::new(move_id(1), set_op(json!("a"))),
            SealedOp::new(move_id(2), set_op(json!("b"))),
        ];
        match MvRegister.join(&cell(), &ops) {
            CellState::Bottom(b) => {
                assert_eq!(b.kind, BottomKind::Conflict);
                assert_eq!(b.cells, vec![cell()]);
                assert_eq!(b.heads.len(), 2);
                assert_eq!(b.move_ids.len(), 2);
            }
            _ => panic!("expected Bottom"),
        }
    }

    #[test]
    fn three_concurrent_sets_all_in_heads() {
        let ops = vec![
            SealedOp::new(move_id(1), set_op(json!(1))),
            SealedOp::new(move_id(2), set_op(json!(2))),
            SealedOp::new(move_id(3), set_op(json!(3))),
        ];
        match MvRegister.join(&cell(), &ops) {
            CellState::Bottom(b) => {
                assert_eq!(b.heads.len(), 3);
                assert_eq!(b.move_ids.len(), 3);
            }
            _ => panic!("expected Bottom"),
        }
    }

    #[test]
    fn invalid_ops_filtered_before_count() {
        let ops = vec![
            SealedOp::new(
                move_id(1),
                LatticeOp {
                    op_type: LatticeOpType::Add,
                    tag: Some("garbage".into()),
                    value: None,
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
            SealedOp::new(move_id(2), set_op(json!("only valid"))),
        ];
        // Only one valid op -> single value, no Bottom.
        assert_eq!(
            MvRegister.join(&cell(), &ops),
            CellState::Value(json!("only valid"))
        );
    }

    #[test]
    fn kind_is_mv_register() {
        assert_eq!(MvRegister.kind(), LatticeKind::MvRegister);
        assert_eq!(LatticeKind::MvRegister.as_wire_str(), "mv_register");
    }
}
