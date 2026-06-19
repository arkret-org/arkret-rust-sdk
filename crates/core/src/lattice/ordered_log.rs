//! Ordered-log Lattice (per-issuer-seq deduped append log).
//!
//! Per spec §5.3:
//! - `append(value, issuer_seq)` adds an entry to the log.
//! - `(issuer, issuer_seq)` is the deduplication key — duplicate entries under the same Move
//!   issuer's seq are coalesced (idempotent reappend).
//! - Output is the sorted entry list, ordered by `(issuer, issuer_seq)` ascending, projected as
//!   `[{issuer, issuer_seq, value}, ...]`.
//!
//! Since the deduplication key includes the issuer DID, this Lattice
//! requires the SealedOp to expose the Move's `issuer`. Move
//! preconditions / capability checks (which look at the issuer) live at
//! the Move verifier; the lattice receives the joined ops post-verify.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use serde_json::{Value, json};

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{CellRef, Did, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct OrderedLog;

/// An sealed op carrying issuer DID, used by [`OrderedLog::join_with_issuers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedOp {
    pub issuer: Did,
    pub op: SealedOp,
}

/// Diagnostic for an append withheld behind a per-issuer sequence gap.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderedLogPendingGap {
    pub issuer: String,
    pub missing_seq: u64,
    pub pending_seq: u64,
    pub reason: String,
    pub value: Value,
}

/// Ordered-log join report: materialized contiguous prefix plus gaps.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderedLogJoinReport {
    pub entries: Vec<Value>,
    pub pending_gaps: Vec<OrderedLogPendingGap>,
}

impl OrderedLog {
    /// Join with explicit issuer attribution and gap diagnostics.
    pub fn join_with_issuer_report(&self, ops: &[IssuedOp]) -> OrderedLogJoinReport {
        let mut by_issuer: BTreeMap<String, BTreeMap<u64, Value>> = BTreeMap::new();
        for entry in ops {
            if Self.validate_op(&entry.op.op).is_err() {
                continue;
            }
            let Some(seq) = entry.op.op.issuer_seq else {
                continue;
            };
            let Some(value) = entry.op.op.value.clone() else {
                continue;
            };

            let issuer_entries = by_issuer
                .entry(entry.issuer.as_str().to_owned())
                .or_default();
            match issuer_entries.entry(seq) {
                Entry::Vacant(slot) => {
                    slot.insert(value);
                }
                Entry::Occupied(mut slot) => {
                    if entry_id(&value) < entry_id(slot.get()) {
                        slot.insert(value);
                    }
                }
            }
        }

        let mut entries = Vec::new();
        let mut pending_gaps = Vec::new();
        for (issuer, seq_entries) in by_issuer {
            let mut expected_seq = None;
            for (seq, value) in seq_entries {
                let expected = expected_seq.unwrap_or(seq);
                if seq == expected {
                    entries.push(json!({
                        "issuer": issuer,
                        "issuer_seq": seq,
                        "value": value,
                    }));
                    expected_seq = Some(seq + 1);
                } else {
                    pending_gaps.push(OrderedLogPendingGap {
                        issuer: issuer.clone(),
                        missing_seq: expected,
                        pending_seq: seq,
                        reason: "dependency_missing".to_owned(),
                        value,
                    });
                }
            }
        }

        OrderedLogJoinReport {
            entries,
            pending_gaps,
        }
    }

    /// Join with explicit issuer attribution.
    ///
    /// Use this entry point when materialising effective state from a
    /// store that knows each Move's issuer. The plain [`Lattice::join`]
    /// path (no issuer) treats every op as having issuer
    /// `did:unknown:_` — useful for tests but loses dedup behaviour
    /// across issuers.
    pub fn join_with_issuers(&self, _cell: &CellRef, ops: &[IssuedOp]) -> CellState {
        CellState::Value(json!(self.join_with_issuer_report(ops).entries))
    }
}

fn entry_id(value: &Value) -> Option<&str> {
    value.get("entry_id").and_then(Value::as_str)
}

impl Lattice for OrderedLog {
    fn kind(&self) -> LatticeKind {
        LatticeKind::OrderedLog
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        match op.op_type {
            LatticeOpType::Append => {
                if op.value.is_none() {
                    return Err(OpError::MissingField {
                        kind: "ordered_log",
                        field: "value",
                    });
                }
                if op.issuer_seq.is_none() {
                    return Err(OpError::MissingField {
                        kind: "ordered_log",
                        field: "issuer_seq",
                    });
                }
                Ok(())
            }
            other => Err(OpError::UnsupportedOpType {
                got: format!("{other:?}").to_lowercase(),
                expected_kind: "ordered_log",
            }),
        }
    }

    /// Plain join treats every op as anonymous (issuer=`did:unknown:_`).
    /// Real runtime should use [`OrderedLog::join_with_issuers`].
    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        let unknown = Did::new("did:unknown:_".to_owned()).unwrap();
        let issued: Vec<IssuedOp> = sealed_ops
            .iter()
            .cloned()
            .map(|op| IssuedOp {
                issuer: unknown.clone(),
                op,
            })
            .collect();
        self.join_with_issuers(cell, &issued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LatticeOp, MoveId};

    fn cell() -> CellRef {
        CellRef::new(
            "ck:cell:ck.component.audit.log.v1:ck.audit.01js0au0000000000000000000".to_owned(),
        )
        .unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn append(seq: u64, value: Value) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Append,
            tag: None,
            value: Some(value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: Some(seq),
        }
    }

    fn issued(issuer_str: &str, seq: u64, value: Value, mid: u8) -> IssuedOp {
        IssuedOp {
            issuer: Did::new(issuer_str.to_owned()).unwrap(),
            op: SealedOp::new(move_id(mid), append(seq, value)),
        }
    }

    #[test]
    fn validate_rejects_non_append() {
        let op = LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(json!("x")),
            from: None,
            to: None,
            reason: None,
            issuer_seq: Some(1),
        };
        OrderedLog
            .validate_op(&op)
            .expect_err("non-append op must fail");
    }

    #[test]
    fn validate_rejects_missing_issuer_seq() {
        let op = LatticeOp {
            op_type: LatticeOpType::Append,
            tag: None,
            value: Some(json!("x")),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        };
        let err = OrderedLog.validate_op(&op).unwrap_err();
        assert!(format!("{err}").contains("issuer_seq"));
    }

    #[test]
    fn validate_rejects_missing_value() {
        let op = LatticeOp {
            op_type: LatticeOpType::Append,
            tag: None,
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: Some(1),
        };
        let err = OrderedLog.validate_op(&op).unwrap_err();
        assert!(format!("{err}").contains("value"));
    }

    #[test]
    fn join_with_issuers_dedupes_same_issuer_seq() {
        let ops = vec![
            issued("did:web:alice.example", 1, json!("e1"), 1),
            issued("did:web:alice.example", 1, json!("e1-dup"), 2), // dup key: dropped
            issued("did:web:alice.example", 2, json!("e2"), 3),
        ];
        let state = OrderedLog.join_with_issuers(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                let arr = v.as_array().unwrap();
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0].get("value").unwrap(), &json!("e1"));
                assert_eq!(arr[1].get("issuer_seq").unwrap().as_u64().unwrap(), 2);
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn join_orders_by_issuer_then_seq() {
        let ops = vec![
            issued("did:web:bob.example", 1, json!("b1"), 1),
            issued("did:web:alice.example", 2, json!("a2"), 2),
            issued("did:web:alice.example", 1, json!("a1"), 3),
        ];
        let state = OrderedLog.join_with_issuers(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                let arr = v.as_array().unwrap();
                assert_eq!(arr[0].get("issuer").unwrap(), "did:web:alice.example");
                assert_eq!(arr[0].get("issuer_seq").unwrap().as_u64().unwrap(), 1);
                assert_eq!(arr[1].get("issuer").unwrap(), "did:web:alice.example");
                assert_eq!(arr[1].get("issuer_seq").unwrap().as_u64().unwrap(), 2);
                assert_eq!(arr[2].get("issuer").unwrap(), "did:web:bob.example");
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn join_reports_gaps_and_recomputes_after_backfill() {
        let gap_ops = vec![
            issued(
                "did:web:alice.example",
                0,
                json!({"entry_id": "entry-0000", "kind": "start"}),
                1,
            ),
            issued(
                "did:web:alice.example",
                1,
                json!({"entry_id": "entry-0001", "kind": "next"}),
                2,
            ),
            issued(
                "did:web:alice.example",
                3,
                json!({"entry_id": "entry-0003-b", "kind": "late-b"}),
                3,
            ),
        ];
        let gap_report = OrderedLog.join_with_issuer_report(&gap_ops);
        assert_eq!(gap_report.entries.len(), 2);
        assert_eq!(gap_report.pending_gaps.len(), 1);
        assert_eq!(gap_report.pending_gaps[0].missing_seq, 2);
        assert_eq!(gap_report.pending_gaps[0].pending_seq, 3);
        assert_eq!(gap_report.pending_gaps[0].reason, "dependency_missing");

        let backfilled_a = vec![
            issued(
                "did:web:alice.example",
                0,
                json!({"entry_id": "entry-0000", "kind": "start"}),
                1,
            ),
            issued(
                "did:web:alice.example",
                1,
                json!({"entry_id": "entry-0001", "kind": "next"}),
                2,
            ),
            issued(
                "did:web:alice.example",
                3,
                json!({"entry_id": "entry-0003-b", "kind": "late-b"}),
                3,
            ),
            issued(
                "did:web:alice.example",
                2,
                json!({"entry_id": "entry-0002", "kind": "backfill"}),
                4,
            ),
            issued(
                "did:web:alice.example",
                3,
                json!({"entry_id": "entry-0003-a", "kind": "late-a"}),
                5,
            ),
        ];
        let backfilled_b = vec![
            issued(
                "did:web:alice.example",
                0,
                json!({"entry_id": "entry-0000", "kind": "start"}),
                1,
            ),
            issued(
                "did:web:alice.example",
                1,
                json!({"entry_id": "entry-0001", "kind": "next"}),
                2,
            ),
            issued(
                "did:web:alice.example",
                2,
                json!({"entry_id": "entry-0002", "kind": "backfill"}),
                4,
            ),
            issued(
                "did:web:alice.example",
                3,
                json!({"entry_id": "entry-0003-a", "kind": "late-a"}),
                5,
            ),
            issued(
                "did:web:alice.example",
                3,
                json!({"entry_id": "entry-0003-b", "kind": "late-b"}),
                3,
            ),
        ];
        let report_a = OrderedLog.join_with_issuer_report(&backfilled_a);
        let report_b = OrderedLog.join_with_issuer_report(&backfilled_b);
        assert!(report_a.pending_gaps.is_empty());
        assert_eq!(report_a.entries, report_b.entries);
        assert_eq!(report_a.entries.len(), 4);
        assert_eq!(
            report_a.entries[3]["value"],
            json!({"entry_id": "entry-0003-a", "kind": "late-a"})
        );
    }

    #[test]
    fn empty_log_returns_empty_array() {
        let state = OrderedLog.join_with_issuers(&cell(), &[]);
        assert_eq!(state, CellState::Value(json!([])));
    }

    #[test]
    fn plain_join_collapses_under_unknown_issuer() {
        let ops = vec![
            SealedOp::new(move_id(1), append(1, json!("e1"))),
            SealedOp::new(move_id(2), append(1, json!("e1-dup"))), /* same seq, same
                                                                    * issuer=unknown ->
                                                                    * dropped */
            SealedOp::new(move_id(3), append(2, json!("e2"))),
        ];
        let state = OrderedLog.join(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                let arr = v.as_array().unwrap();
                assert_eq!(arr.len(), 2);
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn invalid_ops_skipped() {
        let ops = vec![
            issued("did:web:alice.example", 1, json!("good"), 1),
            // invalid: missing issuer_seq -> filtered
            IssuedOp {
                issuer: Did::new("did:web:alice.example".to_owned()).unwrap(),
                op: SealedOp::new(
                    move_id(2),
                    LatticeOp {
                        op_type: LatticeOpType::Append,
                        tag: None,
                        value: Some(json!("orphan")),
                        from: None,
                        to: None,
                        reason: None,
                        issuer_seq: None,
                    },
                ),
            },
        ];
        let state = OrderedLog.join_with_issuers(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                let arr = v.as_array().unwrap();
                assert_eq!(arr.len(), 1);
                assert_eq!(arr[0].get("value").unwrap(), &json!("good"));
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn kind_is_ordered_log() {
        assert_eq!(OrderedLog.kind(), LatticeKind::OrderedLog);
        assert_eq!(LatticeKind::OrderedLog.as_wire_str(), "ordered_log");
    }
}
