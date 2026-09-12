//! PN-Counter StateModel.
//!
//! Per spec §5.3:
//! - `inc(value)` adds a non-negative integer increment.
//! - `dec(value)` subtracts a non-negative integer.
//! - State retains one monotone positive/negative component per issuer. The presented scalar is
//!   derived by summing those components; it is not the canonical stored state.
//!
//! Negative increments / decrements are validation errors. The presented sum
//! may be negative when the negative components exceed the positive ones; both
//! component families remain monotone.

use std::collections::BTreeMap;

use serde_json::Value;

use super::ordered_log::IssuedOp;
use super::{OpError, ResolvedCellState, StateModel, StateModelKind, StateWrite};
use crate::{ActorId, CanonicalCounterEntry, CellRef, LatticeOp, LatticeOpType};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Default)]
pub struct Counter;

impl StateModel for Counter {
    fn kind(&self) -> StateModelKind {
        StateModelKind::Counter
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Inc | LatticeOpType::Dec => {
                if op.tag.is_some() {
                    return Err(OpError::InvalidValue {
                        kind: "counter",
                        field: "tag",
                        reason: "counter state has no custom tag dimensions".to_owned(),
                    });
                }
                let value = op.value.as_ref().ok_or(OpError::MissingField {
                    kind: "counter",
                    field: "value",
                })?;
                let n = value.as_u64().ok_or(OpError::InvalidValue {
                    kind: "counter",
                    field: "value",
                    reason: "must be a non-negative JSON integer".to_owned(),
                })?;
                if n > MAX_SAFE_INTEGER {
                    return Err(OpError::InvalidValue {
                        kind: "counter",
                        field: "value",
                        reason: "exceeds the protocol safe-integer maximum".to_owned(),
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: other.as_str().to_owned(),
                expected_kind: "counter",
            }),
        }
    }

    fn resolve(
        &self,
        _cell: &CellRef,
        sealed_ops: &[StateWrite],
    ) -> Result<ResolvedCellState, OpError> {
        let _ = sealed_ops;
        Err(OpError::InvalidValue {
            kind: "counter",
            field: "issuer_id",
            reason: "issuer attribution is required; use join_with_issuers".to_owned(),
        })
    }
}

impl Counter {
    pub fn join_with_issuers(
        &self,
        _cell: &CellRef,
        ops: &[IssuedOp],
    ) -> Result<ResolvedCellState, OpError> {
        let mut unique = BTreeMap::<crate::EventId, (&ActorId, &LatticeOp)>::new();
        for entry in ops {
            self.validate_op(&entry.op.op)?;
            if let Some((issuer, op)) = unique.get(&entry.op.event_id)
                && (*issuer != &entry.issuer_id || *op != &entry.op.op)
            {
                return Err(OpError::InvalidValue {
                    kind: "counter",
                    field: "event_id",
                    reason: "one Event identity maps to different counter writes".to_owned(),
                });
            }
            unique.insert(entry.op.event_id.clone(), (&entry.issuer_id, &entry.op.op));
        }

        let mut components = BTreeMap::<String, (ActorId, u64, u64)>::new();
        for (issuer, op) in unique.into_values() {
            let value = op
                .value
                .as_ref()
                .and_then(Value::as_u64)
                .expect("validated counter value");
            let issuer_key = issuer
                .canonical_key()
                .map_err(|error| OpError::InvalidValue {
                    kind: "counter",
                    field: "issuer_id",
                    reason: error.to_string(),
                })?;
            let component = components
                .entry(issuer_key)
                .or_insert_with(|| (issuer.clone(), 0, 0));
            let target = match op.op_type {
                LatticeOpType::Inc => &mut component.1,
                LatticeOpType::Dec => &mut component.2,
                _ => unreachable!("validated counter operation"),
            };
            *target = target
                .checked_add(value)
                .ok_or_else(|| OpError::Unrepresentable {
                    kind: "counter",
                    reason: "issuer component overflow".to_owned(),
                })?;
            if *target > MAX_SAFE_INTEGER {
                return Err(OpError::Unrepresentable {
                    kind: "counter",
                    reason: "issuer component exceeds the protocol safe-integer maximum".to_owned(),
                });
            }
        }

        let value = components
            .into_values()
            .map(|(issuer_id, positive, negative)| CanonicalCounterEntry {
                issuer_id,
                positive,
                negative,
            })
            .collect::<Vec<_>>();
        Ok(ResolvedCellState::Value(
            serde_json::to_value(value).expect("canonical counter state is JSON serializable"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{DidCoreId, Hash, LatticeOp};

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

    fn issuer(name: &str) -> ActorId {
        ActorId::service(DidCoreId::new(format!("ak:did_core:webvh:{name}")).unwrap())
    }

    fn issued(issuer_id: ActorId, byte: u8, op: LatticeOp) -> IssuedOp {
        IssuedOp {
            issuer_id,
            op: StateWrite::new(move_id(byte), op),
        }
    }

    #[test]
    fn validate_rejects_negative_value() {
        let err = Counter.validate_op(&inc(-1)).unwrap_err();
        assert!(format!("{err}").contains("non-negative JSON integer"));
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
        assert!(format!("{err}").contains("must be a non-negative JSON integer"));
    }

    #[test]
    fn issuer_components_preserve_positive_and_negative_totals() {
        let alice = issuer("z6mkfixturealice");
        let ops = vec![
            issued(alice.clone(), 1, inc(5)),
            issued(alice.clone(), 2, inc(3)),
            issued(alice.clone(), 3, dec(2)),
        ];
        let state = Counter.join_with_issuers(&cell(), &ops).unwrap();
        assert_eq!(
            state,
            ResolvedCellState::Value(json!([{
                "issuer_id": alice,
                "positive": 8,
                "negative": 2
            }]))
        );
    }

    #[test]
    fn empty_join_returns_empty_component_array() {
        assert_eq!(
            Counter.join_with_issuers(&cell(), &[]).unwrap(),
            ResolvedCellState::Value(json!([]))
        );
    }

    #[test]
    fn components_are_sorted_by_canonical_issuer() {
        let alice = issuer("z6mkfixturealice");
        let bob = issuer("z6mkfixturebob");
        let ops = vec![
            issued(bob.clone(), 1, inc(3)),
            issued(alice.clone(), 2, dec(1)),
        ];
        let ResolvedCellState::Value(value) = Counter.join_with_issuers(&cell(), &ops).unwrap()
        else {
            panic!("expected value")
        };
        assert_eq!(value[0]["issuer_id"], json!(alice));
        assert_eq!(value[0]["positive"], 0);
        assert_eq!(value[0]["negative"], 1);
        assert_eq!(value[1]["issuer_id"], json!(bob));
        assert_eq!(value[1]["positive"], 3);
        assert_eq!(value[1]["negative"], 0);
    }

    #[test]
    fn counter_rejects_custom_tag_dimensions() {
        let mut op = inc(3);
        op.tag = Some("approve".to_owned());
        Counter
            .validate_op(&op)
            .expect_err("counter tags are not part of the canonical state");
    }

    #[test]
    fn issuer_free_join_fails_closed() {
        let ops = vec![StateWrite::new(move_id(1), dec(5))];
        assert_eq!(
            Counter.resolve(&cell(), &ops).unwrap_err(),
            OpError::InvalidValue {
                kind: "counter",
                field: "issuer_id",
                reason: "issuer attribution is required; use join_with_issuers".to_owned(),
            }
        );
    }

    #[test]
    fn exact_event_replay_is_idempotent() {
        let write = issued(issuer("z6mkfixturealice"), 1, inc(5));
        let state = Counter
            .join_with_issuers(&cell(), &[write.clone(), write])
            .unwrap();
        let ResolvedCellState::Value(value) = state else {
            panic!("expected value")
        };
        assert_eq!(value[0]["positive"], 5);
    }

    #[test]
    fn one_event_identity_cannot_name_different_writes() {
        let alice = issuer("z6mkfixturealice");
        let ops = vec![issued(alice.clone(), 1, inc(1)), issued(alice, 1, inc(2))];
        assert!(Counter.join_with_issuers(&cell(), &ops).is_err());
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
        assert_eq!(Counter.kind(), StateModelKind::Counter);
        assert_eq!(StateModelKind::Counter.as_wire_str(), "counter");
    }

    #[test]
    fn issuer_component_must_remain_within_safe_integer_range() {
        let alice = issuer("z6mkfixturealice");
        let ops = vec![
            issued(alice.clone(), 1, inc(MAX_SAFE_INTEGER as i64)),
            issued(alice, 2, inc(1)),
        ];
        assert!(matches!(
            Counter.join_with_issuers(&cell(), &ops),
            Err(OpError::Unrepresentable { .. })
        ));
    }
}
