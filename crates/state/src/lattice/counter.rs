//! PN-Counter Lattice.
//!
//! Per spec §5.3:
//! - `inc(value)` adds a non-negative integer increment.
//! - `dec(value)` subtracts a non-negative integer.
//! - Optional `tag` partitions the counter into named per-counter dimensions (returned as a JSON
//!   object). Without tag, the cell is a single global counter and the return value is a JSON
//!   integer.
//!
//! Negative increments / decrements are validation errors; the counter
//! sum may go negative if dec exceeds inc on a tag, which the runtime
//! treats as a domain violation surfaced via `bottom=reject` semantics
//! when the cell schema declares non-negative invariant. This Lattice
//! itself is monotonic over Z.

use std::collections::BTreeMap;

use serde_json::{Number, Value, json};

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{Bottom, BottomKind, CellRef, LatticeOp, LatticeOpType, bottom_details};

#[derive(Clone, Copy, Debug, Default)]
pub struct Counter;

impl Lattice for Counter {
    fn kind(&self) -> LatticeKind {
        LatticeKind::Counter
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Inc | LatticeOpType::Dec => {
                let value = op.value.as_ref().ok_or(OpError::MissingField {
                    kind: "counter",
                    field: "value",
                })?;
                let n = value.as_i64().ok_or(OpError::InvalidValue {
                    kind: "counter",
                    field: "value",
                    reason: "must be a JSON integer".to_owned(),
                })?;
                if n < 0 {
                    return Err(OpError::InvalidValue {
                        kind: "counter",
                        field: "value",
                        reason: "increment / decrement value must be non-negative".to_owned(),
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: format!("{other:?}").to_lowercase(),
                expected_kind: "counter",
            }),
        }
    }

    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        // Tagged dimensions go into a sorted map; un-tagged go into the
        // empty-string bucket. We return either an integer (single
        // un-tagged dim) or an object (when any tagged dim exists).
        let mut totals: BTreeMap<String, i64> = BTreeMap::new();
        let mut any_tagged = false;
        for entry in sealed_ops {
            if self.validate_op(&entry.op).is_err() {
                continue;
            }
            let Some(v) = entry.op.value.as_ref().and_then(|v| v.as_i64()) else {
                continue;
            };
            let signed = match entry.op.op_type {
                LatticeOpType::Inc => v,
                LatticeOpType::Dec => -v,
                _ => continue,
            };
            let tag = entry.op.tag.clone().unwrap_or_default();
            if !tag.is_empty() {
                any_tagged = true;
            }
            // SDK-COR-01: an arbitrary number of sealed ops can be accumulated
            // here (the count is not bounded by this lattice), so a naive `+=`
            // could panic in debug / silently wrap in release. Overflow is a
            // domain violation -> resolve the cell to ⊥ rather than emit a
            // corrupted count.
            let slot = totals.entry(tag.clone()).or_insert(0);
            match slot.checked_add(signed) {
                Some(next) => *slot = next,
                None => {
                    let mut bottom = Bottom::new(BottomKind::SchemaError, vec![cell.clone()]);
                    bottom.move_ids = vec![entry.move_id.clone()];
                    bottom.details = Some(bottom_details([
                        ("error", json!("pn_counter_overflow")),
                        ("tag", json!(tag)),
                    ]));
                    return CellState::Bottom(bottom);
                }
            }
        }
        if any_tagged {
            let mut obj = serde_json::Map::new();
            for (tag, total) in totals {
                let key = if tag.is_empty() {
                    "_default".to_owned()
                } else {
                    tag
                };
                obj.insert(key, Value::Number(Number::from(total)));
            }
            CellState::Value(Value::Object(obj))
        } else {
            // Single un-tagged bucket; values already overflow-checked above,
            // and there is at most one entry, so a plain read cannot overflow.
            let total: i64 = totals.values().copied().next().unwrap_or(0);
            CellState::Value(json!(total))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, LatticeOp};

    fn cell() -> CellRef {
        CellRef::new("ak:cell:ak.component.metric.counter.v1:ak.metric.signups".to_owned()).unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn inc(value: i64) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Inc,
            tag: None,
            value: Some(json!(value)),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    fn inc_tag(tag: &str, value: i64) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Inc,
            tag: Some(tag.to_owned()),
            value: Some(json!(value)),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    fn dec(value: i64) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Dec,
            tag: None,
            value: Some(json!(value)),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    #[test]
    fn validate_rejects_negative_value() {
        let err = Counter.validate_op(&inc(-1)).unwrap_err();
        assert!(format!("{err}").contains("must be non-negative"));
    }

    #[test]
    fn validate_rejects_missing_value() {
        let op = LatticeOp {
            op_type: LatticeOpType::Inc,
            tag: None,
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        Counter
            .validate_op(&op)
            .expect_err("missing value must fail");
    }

    #[test]
    fn validate_rejects_non_integer() {
        let op = LatticeOp {
            op_type: LatticeOpType::Inc,
            tag: None,
            value: Some(json!("3")),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        let err = Counter.validate_op(&op).unwrap_err();
        assert!(format!("{err}").contains("must be a JSON integer"));
    }

    #[test]
    fn untagged_inc_dec_sums_deterministically() {
        let ops = vec![
            SealedOp::new(move_id(1), inc(5)),
            SealedOp::new(move_id(2), inc(3)),
            SealedOp::new(move_id(3), dec(2)),
        ];
        assert_eq!(Counter.join(&cell(), &ops), CellState::Value(json!(6)));
    }

    #[test]
    fn empty_join_returns_zero() {
        assert_eq!(Counter.join(&cell(), &[]), CellState::Value(json!(0)));
    }

    #[test]
    fn tagged_dimensions_returns_object() {
        let ops = vec![
            SealedOp::new(move_id(1), inc_tag("approve", 3)),
            SealedOp::new(move_id(2), inc_tag("reject", 1)),
            SealedOp::new(move_id(3), inc_tag("approve", 2)),
        ];
        let state = Counter.join(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                assert_eq!(v.get("approve").unwrap().as_i64().unwrap(), 5);
                assert_eq!(v.get("reject").unwrap().as_i64().unwrap(), 1);
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn mixed_tagged_and_untagged_uses_object_with_default_bucket() {
        let ops = vec![
            SealedOp::new(move_id(1), inc(10)),
            SealedOp::new(move_id(2), inc_tag("voted", 3)),
        ];
        let state = Counter.join(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                assert_eq!(v.get("_default").unwrap().as_i64().unwrap(), 10);
                assert_eq!(v.get("voted").unwrap().as_i64().unwrap(), 3);
            }
            _ => panic!("expected object value"),
        }
    }

    #[test]
    fn dec_can_drive_total_negative() {
        let ops = vec![SealedOp::new(move_id(1), dec(5))];
        assert_eq!(Counter.join(&cell(), &ops), CellState::Value(json!(-5)));
    }

    #[test]
    fn validate_rejects_other_op_types() {
        let op = LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some("t".into()),
            value: Some(json!(1)),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        Counter
            .validate_op(&op)
            .expect_err("non-inc/dec op must fail");
    }

    #[test]
    fn kind_is_counter() {
        assert_eq!(Counter.kind(), LatticeKind::Counter);
        assert_eq!(LatticeKind::Counter.as_wire_str(), "counter");
    }

    #[test]
    fn invalid_ops_skipped() {
        let ops = vec![
            SealedOp::new(move_id(1), inc(-3)), // invalid
            SealedOp::new(move_id(2), inc(7)),
        ];
        // Invalid op skipped; result is just inc(7) = 7.
        assert_eq!(Counter.join(&cell(), &ops), CellState::Value(json!(7)));
    }
}
