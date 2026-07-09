//! CAS register Lattice.
//!
//! Per spec §5.3:
//! - `set(value)` writes the cell.
//! - Two concurrent `set` ops produce a `kind=conflict` Bottom (default `bottom=reject`). Unlike
//!   `mv-register`, dependent Moves must fail closed because this Lattice serves safety-critical
//!   state (e.g. `ck.component.realm.policy.v1`, `ck.component.notary.v1`).
//!
//! Wire-shape and signature mirror `MvRegister`; the only behavioural
//! difference is the implicit `bottom=reject` semantics enforced by
//! whichever cell registry uses this Lattice. The runtime that processes
//! Moves whose preconditions touch a `cas-register` cell MUST consult
//! this join's Bottom and fail closed.

use serde_json::Value;

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{Bottom, BottomKind, CellRef, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct CasRegister;

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
            "ak:cell:ck.component.realm.policy.v1:ck.realm.01js0sp00000000000000000aa".to_owned(),
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
    fn single_set_value_resolved() {
        let ops = vec![SealedOp::new(move_id(1), set_op(json!({"policy": "open"})))];
        assert_eq!(
            CasRegister.join(&cell(), &ops),
            CellState::Value(json!({"policy": "open"}))
        );
    }

    #[test]
    fn two_concurrent_sets_yields_conflict_bottom() {
        let ops = vec![
            SealedOp::new(move_id(1), set_op(json!({"policy": "open"}))),
            SealedOp::new(move_id(2), set_op(json!({"policy": "closed"}))),
        ];
        match CasRegister.join(&cell(), &ops) {
            CellState::Bottom(b) => {
                assert_eq!(b.kind, BottomKind::Conflict);
                assert_eq!(b.heads.len(), 2);
                assert_eq!(b.move_ids.len(), 2);
                assert_eq!(b.cells, vec![cell()]);
            }
            _ => panic!("expected Bottom"),
        }
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
