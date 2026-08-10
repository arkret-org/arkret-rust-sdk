//! Ordered-log Lattice (per-issuer-seq append log with equivocation tie-break).
//!
//! Per `authz/event-auth-state-resolution.md` §9.3.1:
//! - `append(value, issuer_seq)` adds an entry. `issuer_seq` is scoped to `(cell, actor_id)` and
//!   counts up from `0`.
//! - Only the contiguous prefix starting at `issuer_seq = 0` enters the cell value. Entries behind
//!   a gap stay pending diagnostics and MUST NOT reach the cell value, the `state_root` leaf or any
//!   authorization decision.
//! - Candidates for one `(cell, actor_id, issuer_seq)` are compared by the **full canonical
//!   projected-op JSON bytes** — not by `op.value` alone and not by any open "covers at least these
//!   fields" profile. Identical bytes are an idempotent duplicate; differing bytes are issuer
//!   equivocation.
//! - Equivocation resolves through the protocol-wide tie-break in `conformance/encoding.md` §4.2:
//!   the candidate whose Event carries the greatest canonical `event_digest` wins. Losers stay
//!   available as equivocation diagnostics and are never removed from the canonical event log.
//! - A digest collision — differing canonical bytes under one identical typed digest — MUST fail
//!   closed and MUST NOT fall back to `event_id`, a field inside `op.value`, arrival order or any
//!   implementation-private id.
//!
//! Since the slot key includes the issuer DID, this Lattice requires the
//! SealedOp to travel with its Control Move's `actor_id`. Preconditions and
//! capability checks (which look at the actor) live at the Control Move
//! verifier; the lattice receives the joined ops post-verify.
//! [`SealedOp::move_id`] carries the enclosing Event's canonical
//! `event_digest`, which is what §4.2 compares.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{
    Bottom, BottomKind, CellRef, DidCoreId, Hash, LatticeOp, LatticeOpType, ProjectionEffect,
    bottom_details, canonical,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct OrderedLog;

/// An sealed op carrying issuer DID, used by [`OrderedLog::join_with_issuers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedOp {
    pub issuer: DidCoreId,
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

/// Diagnostic for a slot the lattice refuses to resolve.
///
/// `encoding.md` §4.2 fails closed rather than falling back to a forbidden
/// tie-break key, so the slot yields no entry and the issuer's contiguous
/// prefix stops here.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderedLogFailClosed {
    pub issuer: String,
    pub issuer_seq: u64,
    pub reason: String,
    pub event_digests: Vec<String>,
}

/// Diagnostic for a slot where one issuer made competing non-equivalent claims.
///
/// §9.3.1 keeps every candidate in the canonical event log and the audit view;
/// only one enters the cell value. This record is what surfaces the losers, so
/// selecting a winner never looks like the losers were dropped.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderedLogEquivocation {
    pub issuer: String,
    pub issuer_seq: u64,
    pub reason: String,
    pub winner_event_digest: String,
    pub loser_event_digests: Vec<String>,
}

/// Ordered-log join report: materialized contiguous prefix plus diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderedLogJoinReport {
    pub entries: Vec<Value>,
    pub pending_gaps: Vec<OrderedLogPendingGap>,
    pub equivocations: Vec<OrderedLogEquivocation>,
    pub fail_closed: Vec<OrderedLogFailClosed>,
}

/// One Event claiming the same ordered-log slot more than once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedLogSlotConflict {
    pub cell: String,
    pub issuer_seq: u64,
}

/// Reject an Event whose derived writes claim one ordered-log slot twice.
///
/// A multi-target reducer contract can project two writes onto the same
/// `(cell, issuer_seq)` with different `op`. Both candidates would then share
/// one `event_digest`, so `encoding.md` §4.2 cannot disambiguate them — and
/// this is *not* a hash collision between two Events. The Event is malformed
/// and MUST be rejected with `schema_violation` before any of it reaches the
/// lattice; picking by projection order or splitting it into two candidates
/// are both forbidden.
///
/// `issuer_seq` is only carried by ordered-log appends, so writes without it
/// are not in scope here.
pub fn ensure_unique_ordered_log_slots(
    effects: &[ProjectionEffect],
) -> Result<(), OrderedLogSlotConflict> {
    let mut seen: BTreeSet<(&str, u64)> = BTreeSet::new();
    for effect in effects {
        let Some(seq) = effect.op.issuer_seq else {
            continue;
        };
        if !seen.insert((effect.cell.as_str(), seq)) {
            return Err(OrderedLogSlotConflict {
                cell: effect.cell.as_str().to_owned(),
                issuer_seq: seq,
            });
        }
    }
    Ok(())
}

/// Winner-selection key for one ordered-log slot candidate.
///
/// `encoding.md` §4.2 fixes the comparison to the **decoded digest octets**,
/// not the typed wire string: comparing `<suite>:<hex>` as UTF-8 would let the
/// suite name decide the winner before the content does. The canonical suite id
/// is only a second key, used when two candidates carry byte-identical octets
/// under different suites, so the order stays total. Field order here *is* the
/// comparison order — `derive(Ord)` compares `octets` first.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DigestKey {
    octets: Vec<u8>,
    suite: String,
}

impl DigestKey {
    /// Parse a typed digest. Returns `None` for anything this receiver cannot
    /// order, so the caller fails the slot closed instead of silently dropping
    /// a candidate an attacker could then make disappear.
    fn parse(move_id: &Hash) -> Option<Self> {
        Self::parse_str(move_id.as_str())
    }

    fn parse_str(value: &str) -> Option<Self> {
        let (suite, hex_digits) = value.split_once(':')?;
        if suite.is_empty() {
            return None;
        }
        let octets = hex::decode(hex_digits).ok()?;
        if octets.is_empty() {
            return None;
        }
        Some(Self {
            octets,
            suite: suite.to_owned(),
        })
    }
}

/// Compare canonical typed digests using the protocol-wide ordered-log
/// tie-break order: decoded digest octets first, canonical suite id second.
///
/// `None` means at least one value is not a valid typed digest; callers must
/// fail closed instead of falling back to lexical wire-string ordering.
pub fn compare_canonical_digests(left: &str, right: &str) -> Option<Ordering> {
    Some(DigestKey::parse_str(left)?.cmp(&DigestKey::parse_str(right)?))
}

/// One append competing for a single `(issuer, issuer_seq)` slot.
struct Candidate {
    op_bytes: Vec<u8>,
    digest: DigestKey,
    digest_wire: String,
    value: Value,
}

/// Every candidate seen for one slot, including the ones that could not be
/// keyed at all.
#[derive(Default)]
struct Slot {
    candidates: Vec<Candidate>,
    unresolved: Vec<String>,
}

impl Slot {
    /// Deterministic value for diagnostics only — never a canonical entry.
    fn representative(&self) -> Value {
        self.candidates
            .iter()
            .max_by(|a, b| a.digest.cmp(&b.digest))
            .map_or(Value::Null, |c| c.value.clone())
    }
}

/// Outcome of adjudicating one slot.
enum SlotOutcome {
    Entry {
        value: Value,
        /// `Some((winner, losers))` only when the slot held genuinely competing
        /// claims; a slot that merely saw the same canonical `effect.op` twice
        /// is an idempotent duplicate, not equivocation.
        equivocation: Option<(String, Vec<String>)>,
    },
    FailClosed {
        reason: &'static str,
        event_digests: Vec<String>,
    },
}

/// Adjudicate one `(issuer, issuer_seq)` slot per §9.3.1 + §4.2.
///
/// Order-independent by construction: the whole candidate set is collected
/// first, then reduced. Byte-identical canonical `effect.op` is an idempotent
/// duplicate, so a slot whose candidates all agree resolves to that one value
/// regardless of how many times it arrived.
fn resolve_slot(mut slot: Slot) -> SlotOutcome {
    if !slot.unresolved.is_empty() {
        return SlotOutcome::FailClosed {
            reason: "unresolvable_event_digest",
            event_digests: slot.unresolved,
        };
    }

    // A typed digest covering more than one distinct canonical `effect.op` is a
    // digest collision: `op` is part of the digest preimage, so differing op
    // bytes imply differing preimages under one digest.
    let mut ops_by_digest: BTreeMap<&DigestKey, BTreeSet<&[u8]>> = BTreeMap::new();
    for candidate in &slot.candidates {
        ops_by_digest
            .entry(&candidate.digest)
            .or_default()
            .insert(candidate.op_bytes.as_slice());
    }
    let collisions: Vec<String> = slot
        .candidates
        .iter()
        .filter(|c| {
            ops_by_digest
                .get(&c.digest)
                .is_some_and(|ops| ops.len() > 1)
        })
        .map(|c| c.digest_wire.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !collisions.is_empty() {
        return SlotOutcome::FailClosed {
            reason: "digest_collision",
            event_digests: collisions,
        };
    }

    let distinct_ops: BTreeSet<&[u8]> = slot
        .candidates
        .iter()
        .map(|c| c.op_bytes.as_slice())
        .collect();
    let is_equivocation = distinct_ops.len() > 1;

    let Some(winner_index) = (0..slot.candidates.len())
        .max_by(|&a, &b| slot.candidates[a].digest.cmp(&slot.candidates[b].digest))
    else {
        return SlotOutcome::FailClosed {
            reason: "no_candidate",
            event_digests: Vec::new(),
        };
    };

    let equivocation = is_equivocation.then(|| {
        let winner = slot.candidates[winner_index].digest_wire.clone();
        let losers: Vec<String> = slot
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != winner_index)
            .map(|(_, c)| c.digest_wire.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        (winner, losers)
    });

    SlotOutcome::Entry {
        value: slot.candidates.swap_remove(winner_index).value,
        equivocation,
    }
}

impl OrderedLog {
    /// Join with explicit issuer attribution and gap diagnostics.
    pub fn join_with_issuer_report(&self, ops: &[IssuedOp]) -> OrderedLogJoinReport {
        let mut by_issuer: BTreeMap<String, BTreeMap<u64, Slot>> = BTreeMap::new();
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

            let slot = by_issuer
                .entry(entry.issuer.as_str().to_owned())
                .or_default()
                .entry(seq)
                .or_default();

            // Equivalence is the full canonical `effect.op` bytes (§9.3.1), so
            // two appends that share `op.value` but differ anywhere else in
            // `op` stay distinct equivocation candidates.
            let (Ok(op_bytes), Some(digest)) = (
                canonical::canonical_json_bytes(&entry.op.op),
                DigestKey::parse(&entry.op.move_id),
            ) else {
                slot.unresolved.push(entry.op.move_id.as_str().to_owned());
                continue;
            };
            slot.candidates.push(Candidate {
                op_bytes,
                digest,
                digest_wire: entry.op.move_id.as_str().to_owned(),
                value,
            });
        }

        let mut entries = Vec::new();
        let mut pending_gaps = Vec::new();
        let mut equivocations = Vec::new();
        let mut fail_closed = Vec::new();
        for (issuer, slots) in by_issuer {
            // §9.3.1 fixes the prefix start at `issuer_seq = 0`. Starting at the
            // lowest seq actually seen would materialize an entry whose own
            // predecessors are still missing.
            let mut expected: u64 = 0;
            let mut blocked = false;
            for (seq, slot) in slots {
                if blocked || seq != expected {
                    pending_gaps.push(OrderedLogPendingGap {
                        issuer: issuer.clone(),
                        missing_seq: expected,
                        pending_seq: seq,
                        reason: "dependency_missing".to_owned(),
                        value: slot.representative(),
                    });
                    blocked = true;
                    continue;
                }
                match resolve_slot(slot) {
                    SlotOutcome::Entry {
                        value,
                        equivocation,
                    } => {
                        if let Some((winner_event_digest, loser_event_digests)) = equivocation {
                            equivocations.push(OrderedLogEquivocation {
                                issuer: issuer.clone(),
                                issuer_seq: seq,
                                reason: "issuer_equivocation".to_owned(),
                                winner_event_digest,
                                loser_event_digests,
                            });
                        }
                        entries.push(json!({
                            "issuer": issuer,
                            "issuer_seq": seq,
                            "value": value,
                        }));
                        // SDK-COR-02: `issuer_seq` is external input; `seq + 1`
                        // could overflow `u64::MAX` (debug panic / release wrap
                        // to 0, poisoning continuity). At u64::MAX the issuer
                        // sequence is exhausted — stop advancing this issuer
                        // (unreachable in practice; fail-safe rather than wrap).
                        match seq.checked_add(1) {
                            Some(next) => expected = next,
                            None => blocked = true,
                        }
                    }
                    SlotOutcome::FailClosed {
                        reason,
                        event_digests,
                    } => {
                        // The slot has no determinable winner, so it yields no
                        // entry and the prefix MUST NOT skip past it.
                        fail_closed.push(OrderedLogFailClosed {
                            issuer: issuer.clone(),
                            issuer_seq: seq,
                            reason: reason.to_owned(),
                            event_digests,
                        });
                        blocked = true;
                    }
                }
            }
        }

        OrderedLogJoinReport {
            entries,
            pending_gaps,
            equivocations,
            fail_closed,
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

    /// `ordered_log` has no issuer-free join.
    ///
    /// §9.3.1 scopes the sequence to `(effect.cell, actor_id)`, so a join that
    /// cannot see the issuer has no way to separate sub-chains. The previous
    /// behaviour — collapsing every op onto a synthetic `did:unknown:_` —
    /// silently merged distinct actors into one slot (turning independent
    /// `issuer_seq = 0` appends into equivocation) and stamped that synthetic
    /// DID into the projected entry and therefore the `state_root` leaf.
    ///
    /// Returning `⊥` here keeps the failure loud and local: real callers MUST
    /// use [`OrderedLog::join_with_issuers`] / [`OrderedLog::join_with_issuer_report`].
    fn join(&self, cell: &CellRef, sealed_ops: &[SealedOp]) -> CellState {
        let mut bottom = Bottom::new(BottomKind::MissingDependency, vec![cell.clone()]);
        bottom.move_ids = sealed_ops.iter().map(|op| op.move_id.clone()).collect();
        bottom.details = Some(bottom_details([(
            "reason",
            Value::String(
                "ordered_log requires issuer attribution; call join_with_issuers".to_owned(),
            ),
        )]));
        CellState::Bottom(bottom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, LatticeOp};

    fn cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.audit.log.v1:ak.audit.01js0au0000000000000000000".to_owned(),
        )
        .unwrap()
    }

    fn suited_move_id(suite: &str, byte: u8) -> Hash {
        Hash::new(format!("{suite}:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        suited_move_id("sha256", byte)
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

    /// Same `op.value`, different `op.reason` — distinct canonical `effect.op`
    /// bytes, so §9.3.1 treats these as equivocation rather than a duplicate.
    fn append_with_reason(seq: u64, value: Value, reason: &str) -> LatticeOp {
        LatticeOp {
            reason: Some(reason.to_owned()),
            ..append(seq, value)
        }
    }

    fn issued(issuer_str: &str, seq: u64, value: Value, mid: u8) -> IssuedOp {
        IssuedOp {
            issuer: DidCoreId::new(issuer_str.to_owned()).unwrap(),
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
    fn byte_identical_effect_op_is_idempotent() {
        let ops = vec![
            issued("ak:did_core:webvh:z6mkfixturealice", 0, json!("e0"), 1),
            // Same canonical `effect.op`, different Event: idempotent duplicate.
            issued("ak:did_core:webvh:z6mkfixturealice", 0, json!("e0"), 2),
            issued("ak:did_core:webvh:z6mkfixturealice", 1, json!("e1"), 3),
        ];
        let report = OrderedLog.join_with_issuer_report(&ops);
        assert!(report.fail_closed.is_empty());
        assert!(
            report.equivocations.is_empty(),
            "a byte-identical reappend is a duplicate, not equivocation"
        );
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].get("value").unwrap(), &json!("e0"));
        assert_eq!(
            report.entries[1]
                .get("issuer_seq")
                .unwrap()
                .as_u64()
                .unwrap(),
            1
        );
    }

    #[test]
    fn join_orders_by_issuer_then_seq() {
        let ops = vec![
            issued("ak:did_core:webvh:z6mkfixturebob", 0, json!("b0"), 1),
            issued("ak:did_core:webvh:z6mkfixturealice", 1, json!("a1"), 2),
            issued("ak:did_core:webvh:z6mkfixturealice", 0, json!("a0"), 3),
        ];
        let state = OrderedLog.join_with_issuers(&cell(), &ops);
        match state {
            CellState::Value(v) => {
                let arr = v.as_array().unwrap();
                assert_eq!(arr.len(), 3);
                assert_eq!(
                    arr[0].get("issuer").unwrap(),
                    "ak:did_core:webvh:z6mkfixturealice"
                );
                assert_eq!(arr[0].get("issuer_seq").unwrap().as_u64().unwrap(), 0);
                assert_eq!(
                    arr[1].get("issuer").unwrap(),
                    "ak:did_core:webvh:z6mkfixturealice"
                );
                assert_eq!(arr[1].get("issuer_seq").unwrap().as_u64().unwrap(), 1);
                assert_eq!(
                    arr[2].get("issuer").unwrap(),
                    "ak:did_core:webvh:z6mkfixturebob"
                );
            }
            _ => panic!("expected value"),
        }
    }

    #[test]
    fn issuer_prefix_starts_at_seq_zero() {
        // Only seq 3 arrived: the prefix starts at 0, so nothing materializes
        // and the gap is reported against the missing seq 0.
        let ops = vec![issued(
            "ak:did_core:webvh:z6mkfixturealice",
            3,
            json!("late"),
            1,
        )];
        let report = OrderedLog.join_with_issuer_report(&ops);
        assert!(report.entries.is_empty(), "prefix must not start at seq 3");
        assert_eq!(report.pending_gaps.len(), 1);
        assert_eq!(report.pending_gaps[0].missing_seq, 0);
        assert_eq!(report.pending_gaps[0].pending_seq, 3);
    }

    #[test]
    fn equivocation_resolves_to_max_event_digest() {
        let ops = vec![
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                0,
                json!("loser"),
                0x11,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                0,
                json!("winner"),
                0x22,
            ),
        ];
        let report = OrderedLog.join_with_issuer_report(&ops);
        assert!(report.fail_closed.is_empty());
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].get("value").unwrap(), &json!("winner"));

        // The loser is not silently dropped: it stays visible as an
        // equivocation diagnostic alongside the winning digest.
        assert_eq!(report.equivocations.len(), 1);
        assert_eq!(report.equivocations[0].reason, "issuer_equivocation");
        assert_eq!(
            report.equivocations[0].winner_event_digest,
            move_id(0x22).as_str()
        );
        assert_eq!(
            report.equivocations[0].loser_event_digests,
            vec![move_id(0x11).as_str().to_owned()]
        );

        // Arrival order (and therefore any causal edge the producer added) MUST
        // NOT change the slot winner.
        let mut reversed = ops;
        reversed.reverse();
        let reversed_report = OrderedLog.join_with_issuer_report(&reversed);
        assert_eq!(reversed_report.entries, report.entries);
        assert_eq!(reversed_report.equivocations, report.equivocations);
    }

    #[test]
    fn same_op_value_different_op_field_is_equivocation() {
        let alice = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap();
        let ops = vec![
            IssuedOp {
                issuer: alice.clone(),
                op: SealedOp::new(move_id(0x11), append(0, json!("same"))),
            },
            IssuedOp {
                issuer: alice,
                op: SealedOp::new(
                    move_id(0x22),
                    append_with_reason(0, json!("same"), "different-op"),
                ),
            },
        ];
        let report = OrderedLog.join_with_issuer_report(&ops);
        // Not a duplicate: equivalence is the full canonical `effect.op`.
        assert_eq!(report.entries.len(), 1);
        assert!(report.fail_closed.is_empty());
        assert_eq!(report.entries[0].get("value").unwrap(), &json!("same"));
    }

    #[test]
    fn max_event_digest_compares_decoded_octets_across_suites() {
        let alice = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap();
        // As UTF-8 wire strings "sha256:00.." > "blake3:ff..", but the decoded
        // octets order the other way. §4.2 compares octets, so blake3 wins.
        let ops = vec![
            IssuedOp {
                issuer: alice.clone(),
                op: SealedOp::new(
                    suited_move_id("blake3", 0xff),
                    append(0, json!("greatest-octets")),
                ),
            },
            IssuedOp {
                issuer: alice,
                op: SealedOp::new(
                    suited_move_id("sha256", 0x00),
                    append(0, json!("greatest-wire-string")),
                ),
            },
        ];
        let report = OrderedLog.join_with_issuer_report(&ops);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(
            report.entries[0].get("value").unwrap(),
            &json!("greatest-octets"),
            "winner must come from decoded octets, not the typed wire string"
        );
    }

    #[test]
    fn distinct_op_under_same_event_digest_fails_closed() {
        let alice = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap();
        let ops = vec![
            IssuedOp {
                issuer: alice.clone(),
                op: SealedOp::new(move_id(0x11), append(0, json!("one"))),
            },
            IssuedOp {
                issuer: alice,
                op: SealedOp::new(move_id(0x11), append(0, json!("other"))),
            },
        ];
        let report = OrderedLog.join_with_issuer_report(&ops);
        assert!(
            report.entries.is_empty(),
            "colliding slot must not materialize an entry"
        );
        assert_eq!(report.fail_closed.len(), 1);
        assert_eq!(report.fail_closed[0].reason, "digest_collision");
        assert_eq!(report.fail_closed[0].issuer_seq, 0);
    }

    #[test]
    fn fail_closed_slot_blocks_the_rest_of_the_prefix() {
        let alice = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap();
        let ops = vec![
            IssuedOp {
                issuer: alice.clone(),
                op: SealedOp::new(move_id(0x11), append(0, json!("one"))),
            },
            IssuedOp {
                issuer: alice.clone(),
                op: SealedOp::new(move_id(0x11), append(0, json!("other"))),
            },
            IssuedOp {
                issuer: alice,
                op: SealedOp::new(move_id(0x33), append(1, json!("after"))),
            },
        ];
        let report = OrderedLog.join_with_issuer_report(&ops);
        assert!(report.entries.is_empty());
        assert_eq!(report.fail_closed.len(), 1);
        assert_eq!(
            report.pending_gaps.len(),
            1,
            "seq 1 must not skip the unresolved seq 0"
        );
        assert_eq!(report.pending_gaps[0].pending_seq, 1);
        assert_eq!(report.pending_gaps[0].missing_seq, 0);
    }

    #[test]
    fn join_reports_gaps_and_recomputes_after_backfill() {
        let gap_ops = vec![
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                0,
                json!({"entry_id": "entry-0000", "kind": "start"}),
                1,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                1,
                json!({"entry_id": "entry-0001", "kind": "next"}),
                2,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                3,
                json!({"entry_id": "entry-0003-b", "kind": "late-b"}),
                5,
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
                "ak:did_core:webvh:z6mkfixturealice",
                0,
                json!({"entry_id": "entry-0000", "kind": "start"}),
                1,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                1,
                json!({"entry_id": "entry-0001", "kind": "next"}),
                2,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                3,
                json!({"entry_id": "entry-0003-b", "kind": "late-b"}),
                5,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                2,
                json!({"entry_id": "entry-0002", "kind": "backfill"}),
                4,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                3,
                json!({"entry_id": "entry-0003-a", "kind": "late-a"}),
                3,
            ),
        ];
        let backfilled_b = vec![
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                0,
                json!({"entry_id": "entry-0000", "kind": "start"}),
                1,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                1,
                json!({"entry_id": "entry-0001", "kind": "next"}),
                2,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                2,
                json!({"entry_id": "entry-0002", "kind": "backfill"}),
                4,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                3,
                json!({"entry_id": "entry-0003-a", "kind": "late-a"}),
                3,
            ),
            issued(
                "ak:did_core:webvh:z6mkfixturealice",
                3,
                json!({"entry_id": "entry-0003-b", "kind": "late-b"}),
                5,
            ),
        ];
        let report_a = OrderedLog.join_with_issuer_report(&backfilled_a);
        let report_b = OrderedLog.join_with_issuer_report(&backfilled_b);
        assert!(report_a.pending_gaps.is_empty());
        assert!(report_a.fail_closed.is_empty());
        assert_eq!(report_a.entries, report_b.entries);
        assert_eq!(report_a.entries.len(), 4);
        // seq 3 is contested: `entry-0003-b` carries the greater event_digest
        // (0x05.. vs 0x03..) and wins, even though its `entry_id` sorts last —
        // no payload field may act as the tie-break key.
        assert_eq!(
            report_a.entries[3]["value"],
            json!({"entry_id": "entry-0003-b", "kind": "late-b"})
        );
    }

    #[test]
    fn same_event_claiming_one_slot_twice_is_rejected() {
        let cell_ref = cell();
        let effects = vec![
            ProjectionEffect::join(cell_ref.clone(), append(0, json!("one"))),
            ProjectionEffect::join(cell_ref, append(0, json!("other"))),
        ];
        // Not equivocation and not a digest collision: one malformed Event.
        let conflict = ensure_unique_ordered_log_slots(&effects).unwrap_err();
        assert_eq!(conflict.issuer_seq, 0);
    }

    #[test]
    fn distinct_slots_in_one_event_are_accepted() {
        let cell_ref = cell();
        let effects = vec![
            ProjectionEffect::join(cell_ref.clone(), append(0, json!("one"))),
            ProjectionEffect::join(cell_ref, append(1, json!("two"))),
        ];
        assert!(ensure_unique_ordered_log_slots(&effects).is_ok());
    }

    #[test]
    fn empty_log_returns_empty_array() {
        let state = OrderedLog.join_with_issuers(&cell(), &[]);
        assert_eq!(state, CellState::Value(json!([])));
    }

    #[test]
    fn plain_issuer_free_join_fails_closed() {
        // The issuer-free entry point used to collapse every op onto
        // `did:unknown:_`, which merged distinct actors into one slot and put
        // that synthetic DID into the projected entry (and the state root).
        // It now yields Bottom so the miswiring is loud instead of silent.
        let ops = vec![
            SealedOp::new(move_id(1), append(0, json!("e0"))),
            SealedOp::new(move_id(2), append(0, json!("e0-rival"))),
            SealedOp::new(move_id(3), append(1, json!("e1"))),
        ];
        match OrderedLog.join(&cell(), &ops) {
            CellState::Bottom(bottom) => {
                assert_eq!(bottom.kind, BottomKind::MissingDependency);
                assert_eq!(bottom.move_ids.len(), 3, "every op stays attributable");
            }
            other => panic!("issuer-free ordered_log join must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn invalid_ops_skipped() {
        let ops = vec![
            issued("ak:did_core:webvh:z6mkfixturealice", 0, json!("good"), 1),
            // invalid: missing issuer_seq -> filtered
            IssuedOp {
                issuer: DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
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
