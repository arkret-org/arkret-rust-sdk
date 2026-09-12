//! Observed-remove set with canonical Event dots.
//!
//! Per spec §5.3:
//! - `add(tag, value?)` adds a tagged element.
//! - `remove(tag, reason?)` removes the element bearing that tag.
//! - A remove names the exact observed add dot, so it wins regardless of input order.
//! - Removing a never-added dot is retained as a tombstone and remains a no-op in the value.
//!
//! Output retains both the complete add-dot map and every removal tombstone as
//! `{adds:[{tag_id,value}],removed_tag_ids:[...]}`. Both arrays are sorted by
//! tag id so snapshots round-trip the full convergent state rather than only
//! its currently visible elements.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{OpError, ResolvedCellState, StateModel, StateModelKind, StateWrite};
use crate::{CanonicalOrSetValue, CanonicalSetEntry, CellRef, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct OrSet;

impl StateModel for OrSet {
    fn kind(&self) -> StateModelKind {
        StateModelKind::OrSet
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Add => validate_dot(op.tag.as_deref()),
            LatticeOpType::Remove => validate_dot(op.tag.as_deref()),
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
        let mut adds: BTreeMap<String, Value> = BTreeMap::new();
        let mut removals = BTreeSet::new();
        for entry in sealed_ops {
            self.validate_op(&entry.op)?;
            let tag = entry.op.tag.clone().expect("validated OR-set dot");
            match entry.op.op_type {
                LatticeOpType::Add => {
                    let value = entry.op.value.clone().unwrap_or(Value::Null);
                    if let Some(previous) = adds.get(&tag)
                        && previous != &value
                    {
                        return Err(OpError::InvalidValue {
                            kind: "or_set",
                            field: "tag",
                            reason: format!("dot {tag:?} maps to different values"),
                        });
                    }
                    adds.insert(tag, value);
                }
                LatticeOpType::Remove => {
                    removals.insert(tag);
                }
                _ => unreachable!("validated OR-set operation"),
            }
        }
        let adds = adds
            .into_iter()
            .map(|(tag_id, value)| CanonicalSetEntry { tag_id, value })
            .collect::<Vec<_>>();
        let removed_tag_ids = removals.into_iter().collect::<Vec<_>>();
        let value = CanonicalOrSetValue {
            adds,
            removed_tag_ids,
        };
        Ok(ResolvedCellState::Value(
            serde_json::to_value(value).expect("canonical OR-set state is JSON serializable"),
        ))
    }
}

fn validate_dot(tag: Option<&str>) -> Result<(), OpError> {
    let tag = tag.ok_or(OpError::MissingField {
        kind: "or_set",
        field: "tag",
    })?;
    let Some((event_id, write_index)) = tag.rsplit_once(':') else {
        return Err(OpError::InvalidValue {
            kind: "or_set",
            field: "tag",
            reason: "must be a canonical Event dot".to_owned(),
        });
    };
    if crate::EventId::new(event_id.to_owned()).is_err()
        || write_index.is_empty()
        || !write_index.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(OpError::InvalidValue {
            kind: "or_set",
            field: "tag",
            reason: "must be a canonical Event dot".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

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

    fn dot(byte: u8, write_index: u64) -> String {
        format!(
            "{}:{write_index}",
            crate::EventId::from_event_digest(&move_id(byte)).unwrap()
        )
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
        let tag = dot(1, 0);
        let op = LatticeOp {
            op_type: LatticeOpType::Set,
            tag: Some(tag),
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
    fn join_empty_returns_complete_empty_state() {
        let state = OrSet.resolve(&cell(), &[]).unwrap();
        assert_eq!(
            state,
            ResolvedCellState::Value(json!({"adds": [], "removed_tag_ids": []}))
        );
    }

    #[test]
    fn add_then_remove_retains_add_and_tombstone() {
        let tag = dot(1, 0);
        let ops = vec![
            StateWrite::new(move_id(1), add_op(&tag, Some(json!("v1")))),
            StateWrite::new(move_id(2), remove_op(&tag)),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        assert_eq!(
            state,
            ResolvedCellState::Value(json!({
                "adds": [{"tag_id": tag, "value": "v1"}],
                "removed_tag_ids": [tag]
            }))
        );
    }

    #[test]
    fn remove_before_add_converges_to_the_same_retained_state() {
        let tag = dot(1, 0);
        let ops = vec![
            StateWrite::new(move_id(1), remove_op(&tag)),
            StateWrite::new(move_id(2), add_op(&tag, Some(json!("v1")))),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        assert_eq!(
            state,
            ResolvedCellState::Value(json!({
                "adds": [{"tag_id": tag, "value": "v1"}],
                "removed_tag_ids": [tag]
            }))
        );
    }

    #[test]
    fn deterministic_output_is_sorted_by_tag() {
        let alpha = dot(1, 0);
        let middle = dot(2, 0);
        let zeta = dot(3, 0);
        let ops = vec![
            StateWrite::new(move_id(1), add_op(&zeta, None)),
            StateWrite::new(move_id(2), add_op(&alpha, None)),
            StateWrite::new(move_id(3), add_op(&middle, None)),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        match state {
            ResolvedCellState::Value(v) => {
                let arr = v["adds"].as_array().unwrap();
                let tags: Vec<&str> = arr
                    .iter()
                    .map(|x| x.get("tag_id").unwrap().as_str().unwrap())
                    .collect();
                let mut expected = vec![alpha.as_str(), middle.as_str(), zeta.as_str()];
                expected.sort_unstable();
                assert_eq!(tags, expected);
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn add_without_value_serializes_as_explicit_null() {
        let plain_tag = dot(1, 0);
        let valued_tag = dot(2, 0);
        let ops = vec![
            StateWrite::new(move_id(1), add_op(&plain_tag, None)),
            StateWrite::new(move_id(2), add_op(&valued_tag, Some(json!(42)))),
        ];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        let ResolvedCellState::Value(v) = state else {
            panic!("expected value")
        };
        let arr = v["adds"].as_array().unwrap();
        let plain = arr
            .iter()
            .find(|x| x.get("tag_id").and_then(Value::as_str) == Some(plain_tag.as_str()))
            .unwrap();
        assert!(plain.get("value").unwrap().is_null());
        let with_val = arr
            .iter()
            .find(|x| x.get("tag_id").and_then(Value::as_str) == Some(valued_tag.as_str()))
            .unwrap();
        assert_eq!(with_val.get("value").unwrap(), &json!(42));
    }

    #[test]
    fn remove_of_never_added_tag_is_retained_as_tombstone() {
        let tag = dot(1, 0);
        let ops = vec![StateWrite::new(move_id(1), remove_op(&tag))];
        let state = OrSet.resolve(&cell(), &ops).unwrap();
        assert_eq!(
            state,
            ResolvedCellState::Value(json!({"adds": [], "removed_tag_ids": [tag]}))
        );
    }

    #[test]
    fn one_dot_cannot_name_different_values() {
        let tag = dot(1, 0);
        let ops = vec![
            StateWrite::new(move_id(1), add_op(&tag, Some(json!("v1")))),
            StateWrite::new(move_id(2), add_op(&tag, Some(json!("v2")))),
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
            StateWrite::new(move_id(2), add_op(&dot(2, 0), Some(json!("v")))),
        ];
        assert!(OrSet.resolve(&cell(), &ops).is_err());
    }

    #[test]
    fn bare_event_id_is_not_a_dot() {
        let event_id = crate::EventId::from_event_digest(&move_id(1)).unwrap();
        let error = OrSet
            .validate_op(&add_op(event_id.as_str(), Some(json!("v"))))
            .unwrap_err();
        assert!(format!("{error}").contains("canonical Event dot"));
    }

    #[test]
    fn kind_is_or_set() {
        assert_eq!(OrSet.kind(), StateModelKind::OrSet);
        assert_eq!(StateModelKind::OrSet.as_wire_str(), "or_set");
    }
}
