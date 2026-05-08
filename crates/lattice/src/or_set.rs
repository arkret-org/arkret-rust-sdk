//! OR-set Lattice: tagged add/remove with deterministic remove-after-add.
//!
//! Per spec §5.3:
//! - `add(tag, value?)` adds a tagged element.
//! - `remove(tag, reason?)` removes the element bearing that tag.
//! - Remove of a tag added in the **same join** wins iff the remove op
//!   is causally later (its anchored order is later). Removing a
//!   never-added tag is a no-op (this lattice is monotonic).
//!
//! Output value is a JSON array of `{tag, value?}` objects sorted by
//! `tag` ascending so the resolved state is canonical.

use std::collections::BTreeMap;

use contrix_core::{CellRef, LatticeOpType};
use serde_json::{Value, json};

use crate::{AnchoredOp, CellState, Lattice, LatticeKind, OpError};

#[derive(Clone, Copy, Debug, Default)]
pub struct OrSet;

impl Lattice for OrSet {
    fn kind(&self) -> LatticeKind {
        LatticeKind::OrSet
    }

    fn validate_op(&self, op: &contrix_core::LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Add => {
                if op.tag.as_deref().unwrap_or("").is_empty() {
                    return Err(OpError::MissingField { kind: "or-set", field: "tag" });
                }
                Ok(())
            }
            LatticeOpType::Remove => {
                if op.tag.as_deref().unwrap_or("").is_empty() {
                    return Err(OpError::MissingField { kind: "or-set", field: "tag" });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: format!("{other:?}").to_lowercase(),
                expected_kind: "or-set",
            }),
        }
    }

    fn join(&self, _cell: &CellRef, anchored_ops: &[AnchoredOp]) -> CellState {
        // Deterministic walk over the anchored order; later remove on a
        // tag wipes the prior add(s).
        let mut state: BTreeMap<String, Option<Value>> = BTreeMap::new();
        for entry in anchored_ops {
            // Skip ops that fail validate_op (defensive — runtime should
            // have rejected at submit time, but join is pure so it stays
            // safe).
            if self.validate_op(&entry.op).is_err() {
                continue;
            }
            let Some(tag) = entry.op.tag.clone() else { continue };
            match entry.op.op_type {
                LatticeOpType::Add => {
                    state.insert(tag, entry.op.value.clone());
                }
                LatticeOpType::Remove => {
                    state.remove(&tag);
                }
                _ => {}
            }
        }
        let arr: Vec<Value> = state
            .into_iter()
            .map(|(tag, value)| {
                let mut obj = serde_json::Map::new();
                obj.insert("tag".into(), Value::String(tag));
                if let Some(v) = value {
                    obj.insert("value".into(), v);
                }
                Value::Object(obj)
            })
            .collect();
        CellState::Value(json!(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_core::{LatticeOp, MoveId};

    fn cell() -> CellRef {
        CellRef::new(
            "cx:cell:cx.component.consent.v1:cx.consent.01js0c00000000000000000000".to_owned(),
        )
        .unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("cx:move:sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn add_op(tag: &str, value: Option<Value>) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some(tag.to_owned()),
            value,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    fn remove_op(tag: &str) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Remove,
            tag: Some(tag.to_owned()),
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    #[test]
    fn validate_rejects_unsupported_op_type() {
        let op = LatticeOp {
            op_type: LatticeOpType::Set,
            tag: Some("t".into()),
            value: Some(json!("v")),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        let err = OrSet.validate_op(&op).unwrap_err();
        assert!(format!("{err}").contains("not allowed"));
    }

    #[test]
    fn validate_rejects_add_without_tag() {
        let op = LatticeOp {
            op_type: LatticeOpType::Add,
            tag: None,
            value: Some(json!("v")),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        OrSet.validate_op(&op).expect_err("add without tag must fail");
    }

    #[test]
    fn join_empty_returns_empty_array() {
        let state = OrSet.join(&cell(), &[]);
        assert_eq!(state, CellState::Value(json!([])));
    }

    #[test]
    fn add_then_remove_same_tag_in_order_yields_empty() {
        let ops = vec![
            AnchoredOp::new(move_id(1), add_op("t1", Some(json!("v1")))),
            AnchoredOp::new(move_id(2), remove_op("t1")),
        ];
        let state = OrSet.join(&cell(), &ops);
        assert_eq!(state, CellState::Value(json!([])));
    }

    #[test]
    fn remove_before_add_is_overwritten_by_add() {
        let ops = vec![
            AnchoredOp::new(move_id(1), remove_op("t1")),
            AnchoredOp::new(move_id(2), add_op("t1", Some(json!("v1")))),
        ];
        let state = OrSet.join(&cell(), &ops);
        assert_eq!(state, CellState::Value(json!([{"tag": "t1", "value": "v1"}])));
    }

    #[test]
    fn deterministic_output_is_sorted_by_tag() {
        let ops = vec![
            AnchoredOp::new(move_id(1), add_op("zeta", None)),
            AnchoredOp::new(move_id(2), add_op("alpha", None)),
            AnchoredOp::new(move_id(3), add_op("middle", None)),
        ];
        let state = OrSet.join(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                let arr = v.as_array().unwrap();
                let tags: Vec<&str> =
                    arr.iter().map(|x| x.get("tag").unwrap().as_str().unwrap()).collect();
                assert_eq!(tags, vec!["alpha", "middle", "zeta"]);
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn add_value_optional_serializes_only_when_present() {
        let ops = vec![
            AnchoredOp::new(move_id(1), add_op("plain", None)),
            AnchoredOp::new(move_id(2), add_op("with-val", Some(json!(42)))),
        ];
        let state = OrSet.join(&cell(), &ops);
        let CellState::Value(v) = state else { panic!("expected value") };
        let arr = v.as_array().unwrap();
        let plain = arr.iter().find(|x| x.get("tag").unwrap() == "plain").unwrap();
        assert!(plain.get("value").is_none());
        let with_val = arr.iter().find(|x| x.get("tag").unwrap() == "with-val").unwrap();
        assert_eq!(with_val.get("value").unwrap(), &json!(42));
    }

    #[test]
    fn remove_of_never_added_tag_is_noop() {
        let ops = vec![AnchoredOp::new(move_id(1), remove_op("nonexistent"))];
        let state = OrSet.join(&cell(), &ops);
        assert_eq!(state, CellState::Value(json!([])));
    }

    #[test]
    fn multiple_adds_same_tag_last_wins() {
        let ops = vec![
            AnchoredOp::new(move_id(1), add_op("t1", Some(json!("v1")))),
            AnchoredOp::new(move_id(2), add_op("t1", Some(json!("v2")))),
        ];
        let state = OrSet.join(&cell(), &ops);
        assert_eq!(state, CellState::Value(json!([{"tag": "t1", "value": "v2"}])));
    }

    #[test]
    fn invalid_ops_skipped_during_join() {
        // Op missing tag should be skipped (defensive).
        let ops = vec![
            AnchoredOp::new(
                move_id(1),
                LatticeOp {
                    op_type: LatticeOpType::Add,
                    tag: None,
                    value: Some(json!("orphan")),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
            AnchoredOp::new(move_id(2), add_op("valid", Some(json!("v")))),
        ];
        let state = OrSet.join(&cell(), &ops);
        assert_eq!(state, CellState::Value(json!([{"tag": "valid", "value": "v"}])));
    }

    #[test]
    fn kind_is_or_set() {
        assert_eq!(OrSet.kind(), LatticeKind::OrSet);
        assert_eq!(LatticeKind::OrSet.as_wire_str(), "or-set");
    }
}
