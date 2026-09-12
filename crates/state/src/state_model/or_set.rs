//! Observed-remove set with canonical Event dots.
//!
//! Per spec §5.3:
//! - `add(tag, value?)` adds a tagged element.
//! - `remove(tag, reason?)` removes the element bearing that tag.
//! - A remove names the exact observed add dot, so it wins regardless of input order.
//! - Removing a never-added dot is retained as a tombstone and remains a no-op in the value.
//!
//! Output value is a JSON array of `{tag, value?}` objects sorted by
//! `tag` ascending so the resolved state is canonical.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{OpError, ResolvedCellState, StateModel, StateModelKind, StateWrite};
use crate::{CellRef, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct OrSet;

impl StateModel for OrSet {
    fn kind(&self) -> StateModelKind {
        StateModelKind::OrSet
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Add => {
                if op.tag.as_deref().unwrap_or("").is_empty() {
                    return Err(OpError::MissingField {
                        kind: "or_set",
                        field: "tag",
                    });
                }
                Ok(())
            }
            LatticeOpType::Remove => {
                if op.tag.as_deref().unwrap_or("").is_empty() {
                    return Err(OpError::MissingField {
                        kind: "or_set",
                        field: "tag",
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: other.as_str().to_owned(),
                expected_kind: "or_set",
            }),
        }
    }

    fn resolve(
        &self,
        _cell: &CellRef,
        sealed_ops: &[StateWrite],
    ) -> Result<ResolvedCellState, OpError> {
        let mut adds: BTreeMap<String, Option<Value>> = BTreeMap::new();
        let mut removals = BTreeSet::new();
        for entry in sealed_ops {
            self.validate_op(&entry.op)?;
            let tag = entry.op.tag.clone().expect("validated OR-set dot");
            match entry.op.op_type {
                LatticeOpType::Add => {
                    if let Some(previous) = adds.get(&tag)
                        && previous != &entry.op.value
                    {
                        return Err(OpError::InvalidValue {
                            kind: "or_set",
                            field: "tag",
                            reason: format!("dot {tag:?} maps to different values"),
                        });
                    }
                    adds.insert(tag, entry.op.value.clone());
                }
                LatticeOpType::Remove => {
                    removals.insert(tag);
                }
                _ => unreachable!("validated OR-set operation"),
            }
        }
        let arr: Vec<Value> = adds
            .into_iter()
            .filter(|(tag, _)| !removals.contains(tag))
            .map(|(tag, value)| {
                let mut obj = serde_json::Map::new();
                obj.insert("tag".into(), Value::String(tag));
                if let Some(v) = value {
                    obj.insert("value".into(), v);
                }
                Value::Object(obj)
            })
            .collect();
        Ok(ResolvedCellState::Value(json!(arr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, LatticeOp};

    fn cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.consent.v1:ak.consent.01js0c00000000000000000000".to_owned(),
        )
        .unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
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
        OrSet
            .validate_op(&op)
            .expect_err("add without tag must fail");
    }

    #[test]
    fn join_empty_returns_empty_array() {
        let state = OrSet.resolve(&cell(), &[]).unwrap();
        assert_eq!(state, ResolvedCellState::Value(json!([])));
    }

    #[test]
    fn add_then_remove_same_tag_in_order_yields_empty() {
        let ops = vec![
            StateWrite::new(move_id(1), add_op("t1", Some(json!("v1")))),
            StateWrite::new(move_id(2), remove_op("t1")),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        assert_eq!(state, ResolvedCellState::Value(json!([])));
    }

    #[test]
    fn remove_before_add_still_removes_the_observed_dot() {
        let ops = vec![
            StateWrite::new(move_id(1), remove_op("t1")),
            StateWrite::new(move_id(2), add_op("t1", Some(json!("v1")))),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        assert_eq!(state, ResolvedCellState::Value(json!([])));
    }

    #[test]
    fn deterministic_output_is_sorted_by_tag() {
        let ops = vec![
            StateWrite::new(move_id(1), add_op("zeta", None)),
            StateWrite::new(move_id(2), add_op("alpha", None)),
            StateWrite::new(move_id(3), add_op("middle", None)),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        match state {
            ResolvedCellState::Value(v) => {
                let arr = v.as_array().unwrap();
                let tags: Vec<&str> = arr
                    .iter()
                    .map(|x| x.get("tag").unwrap().as_str().unwrap())
                    .collect();
                assert_eq!(tags, vec!["alpha", "middle", "zeta"]);
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn add_value_optional_serializes_only_when_present() {
        let ops = vec![
            StateWrite::new(move_id(1), add_op("plain", None)),
            StateWrite::new(move_id(2), add_op("with-val", Some(json!(42)))),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        let ResolvedCellState::Value(v) = state else {
            panic!("expected value")
        };
        let arr = v.as_array().unwrap();
        let plain = arr
            .iter()
            .find(|x| x.get("tag").unwrap() == "plain")
            .unwrap();
        assert!(plain.get("value").is_none());
        let with_val = arr
            .iter()
            .find(|x| x.get("tag").unwrap() == "with-val")
            .unwrap();
        assert_eq!(with_val.get("value").unwrap(), &json!(42));
    }

    #[test]
    fn remove_of_never_added_tag_is_noop() {
        let ops = vec![StateWrite::new(move_id(1), remove_op("nonexistent"))];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        assert_eq!(state, ResolvedCellState::Value(json!([])));
    }

    #[test]
    fn one_dot_cannot_name_different_values() {
        let ops = vec![
            StateWrite::new(move_id(1), add_op("t1", Some(json!("v1")))),
            StateWrite::new(move_id(2), add_op("t1", Some(json!("v2")))),
        ];
        assert!(OrSet.resolve(&cell(), &ops).is_err());
    }

    #[test]
    fn invalid_ops_fail_resolution() {
        let ops = vec![
            StateWrite::new(
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
            StateWrite::new(move_id(2), add_op("valid", Some(json!("v")))),
        ];
        assert!(OrSet.resolve(&cell(), &ops).is_err());
    }

    #[test]
    fn kind_is_or_set() {
        assert_eq!(OrSet.kind(), StateModelKind::OrSet);
        assert_eq!(StateModelKind::OrSet.as_wire_str(), "or_set");
    }
}
