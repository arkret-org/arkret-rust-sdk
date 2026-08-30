//! Ordered-log lattice: a grow-only set of accepted Event entries.
//!
//! `issuer_seq` is the enclosing Event's Realm-scoped `actor_seq`. It is a
//! sparse coordinate inside any one cell, not a cell-local counter. Every
//! accepted same-height sibling remains in the joined value. Digest order is
//! used only to produce stable bytes and never selects a winner.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{CellState, Lattice, LatticeKind, OpError, SealedOp};
use crate::{
    ActorId, Bottom, BottomKind, CellRef, Hash, LatticeOp, LatticeOpType, ProjectionEffect,
    bottom_details, canonical,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct OrderedLog;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedOp {
    pub issuer_id: ActorId,
    pub op: SealedOp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedLogSiblingGroup {
    pub issuer: String,
    pub issuer_seq: u64,
    pub reason: String,
    pub event_digests: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedLogIdentityCollision {
    pub issuer: String,
    pub issuer_seq: u64,
    pub reason: String,
    pub event_digest: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OrderedLogJoinReport {
    pub entries: Vec<Value>,
    pub sibling_groups: Vec<OrderedLogSiblingGroup>,
    pub identity_collisions: Vec<OrderedLogIdentityCollision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedLogSlotConflict {
    pub cell: String,
    pub issuer_seq: u64,
}

/// Reject one Event projecting two ordered-log entries into the same cell.
pub fn ensure_unique_ordered_log_slots(
    effects: &[ProjectionEffect],
) -> Result<(), OrderedLogSlotConflict> {
    let mut seen: BTreeSet<(&str, u64)> = BTreeSet::new();
    for effect in effects {
        let Some(seq) = effect.op.issuer_seq else {
            continue;
        };
        if !seen.insert((effect.cell_id.as_str(), seq)) {
            return Err(OrderedLogSlotConflict {
                cell: effect.cell_id.as_str().to_owned(),
                issuer_seq: seq,
            });
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DigestKey {
    octets: Vec<u8>,
    suite: String,
}

impl DigestKey {
    fn parse(hash: &Hash) -> Option<Self> {
        Self::parse_str(hash.as_str())
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

/// Compare typed digests for canonical presentation/serialization only.
pub fn compare_canonical_digests(left: &str, right: &str) -> Option<Ordering> {
    Some(DigestKey::parse_str(left)?.cmp(&DigestKey::parse_str(right)?))
}

struct Candidate {
    issuer: String,
    issuer_seq: u64,
    digest: DigestKey,
    digest_wire: String,
    op_bytes: Vec<u8>,
    value: Value,
}

impl OrderedLog {
    pub fn join_with_issuer_report(&self, ops: &[IssuedOp]) -> OrderedLogJoinReport {
        let mut candidates = Vec::new();
        for entry in ops {
            if Self.validate_op(&entry.op.op).is_err() {
                continue;
            }
            let (Some(issuer_seq), Some(value), Some(digest), Ok(op_bytes)) = (
                entry.op.op.issuer_seq,
                entry.op.op.value.clone(),
                DigestKey::parse(&entry.op.move_id),
                canonical::canonical_json_bytes(&entry.op.op),
            ) else {
                continue;
            };
            candidates.push(Candidate {
                issuer: entry
                    .issuer_id
                    .canonical_key()
                    .expect("validated ActorId in accepted Event"),
                issuer_seq,
                digest,
                digest_wire: entry.op.move_id.as_str().to_owned(),
                op_bytes,
                value,
            });
        }

        let mut bytes_by_identity: BTreeMap<(String, u64, String), BTreeSet<Vec<u8>>> =
            BTreeMap::new();
        for candidate in &candidates {
            bytes_by_identity
                .entry((
                    candidate.issuer.clone(),
                    candidate.issuer_seq,
                    candidate.digest_wire.clone(),
                ))
                .or_default()
                .insert(candidate.op_bytes.clone());
        }
        let colliding: BTreeSet<(String, u64, String)> = bytes_by_identity
            .into_iter()
            .filter_map(|(key, values)| (values.len() > 1).then_some(key))
            .collect();

        let identity_collisions = colliding
            .iter()
            .map(
                |(issuer, issuer_seq, event_digest)| OrderedLogIdentityCollision {
                    issuer: issuer.clone(),
                    issuer_seq: *issuer_seq,
                    reason: "event_identity_collision".to_owned(),
                    event_digest: event_digest.clone(),
                },
            )
            .collect();

        candidates.retain(|candidate| {
            !colliding.contains(&(
                candidate.issuer.clone(),
                candidate.issuer_seq,
                candidate.digest_wire.clone(),
            ))
        });
        candidates.sort_by(|left, right| {
            left.issuer
                .cmp(&right.issuer)
                .then(left.issuer_seq.cmp(&right.issuer_seq))
                .then(left.digest.cmp(&right.digest))
        });
        candidates.dedup_by(|left, right| {
            left.issuer == right.issuer
                && left.issuer_seq == right.issuer_seq
                && left.digest_wire == right.digest_wire
                && left.op_bytes == right.op_bytes
        });

        let mut sibling_groups = Vec::new();
        let mut sibling_digests: BTreeMap<(String, u64), Vec<String>> = BTreeMap::new();
        for candidate in &candidates {
            sibling_digests
                .entry((candidate.issuer.clone(), candidate.issuer_seq))
                .or_default()
                .push(candidate.digest_wire.clone());
        }
        for ((issuer, issuer_seq), event_digests) in sibling_digests {
            if event_digests.len() > 1 {
                sibling_groups.push(OrderedLogSiblingGroup {
                    issuer,
                    issuer_seq,
                    reason: "actor_seq_siblings".to_owned(),
                    event_digests,
                });
            }
        }

        let entries = candidates
            .into_iter()
            .map(|candidate| {
                json!({
                    "issuer_id": candidate.issuer,
                    "issuer_seq": candidate.issuer_seq,
                    "event_digest": candidate.digest_wire,
                    "value": candidate.value,
                })
            })
            .collect();

        OrderedLogJoinReport {
            entries,
            sibling_groups,
            identity_collisions,
        }
    }

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
                got: other.as_str().to_owned(),
                expected_kind: "ordered_log",
            }),
        }
    }

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
    use arkret_wire::{ActorId, DidCoreId};

    use super::*;

    fn cell() -> CellRef {
        CellRef::new("ak:cell:ak.component.audit.log.v1:test".to_owned()).unwrap()
    }

    fn suited_digest(suite: &str, byte: u8) -> Hash {
        Hash::new(format!("{suite}:{}", format!("{byte:02x}").repeat(32))).unwrap()
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

    fn issued(issuer: &str, seq: u64, value: Value, byte: u8) -> IssuedOp {
        IssuedOp {
            issuer_id: ActorId::service(DidCoreId::new(issuer.to_owned()).unwrap()),
            op: SealedOp::new(suited_digest("sha256", byte), append(seq, value)),
        }
    }

    #[test]
    fn sparse_sequences_join_without_pending_gap() {
        let report = OrderedLog.join_with_issuer_report(&[
            issued("ak:did_core:webvh:z6mkfixturealice", 3, json!("three"), 3),
            issued("ak:did_core:webvh:z6mkfixturealice", 0, json!("zero"), 1),
        ]);
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0]["issuer_seq"], 0);
        assert_eq!(report.entries[1]["issuer_seq"], 3);
    }

    #[test]
    fn same_height_siblings_all_join() {
        let report = OrderedLog.join_with_issuer_report(&[
            issued("ak:did_core:webvh:z6mkfixturealice", 7, json!("a"), 1),
            issued("ak:did_core:webvh:z6mkfixturealice", 7, json!("b"), 2),
        ]);
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.sibling_groups.len(), 1);
        assert_eq!(report.sibling_groups[0].event_digests.len(), 2);
    }

    #[test]
    fn exact_replay_is_idempotent() {
        let first = issued("ak:did_core:webvh:z6mkfixturealice", 4, json!("x"), 1);
        let report = OrderedLog.join_with_issuer_report(&[first.clone(), first]);
        assert_eq!(report.entries.len(), 1);
        assert!(report.sibling_groups.is_empty());
    }

    #[test]
    fn canonical_order_uses_decoded_digest_octets() {
        let issuer = ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        );
        let report = OrderedLog.join_with_issuer_report(&[
            IssuedOp {
                issuer_id: issuer.clone(),
                op: SealedOp::new(suited_digest("blake3", 0xff), append(1, json!("last"))),
            },
            IssuedOp {
                issuer_id: issuer,
                op: SealedOp::new(suited_digest("sha256", 0x01), append(1, json!("first"))),
            },
        ]);
        assert_eq!(report.entries[0]["value"], "first");
        assert_eq!(report.entries[1]["value"], "last");
    }

    #[test]
    fn identity_collision_is_quarantined_without_blocking_sibling() {
        let issuer = ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        );
        let collision_digest = suited_digest("sha256", 0x11);
        let report = OrderedLog.join_with_issuer_report(&[
            IssuedOp {
                issuer_id: issuer.clone(),
                op: SealedOp::new(collision_digest.clone(), append(1, json!("a"))),
            },
            IssuedOp {
                issuer_id: issuer.clone(),
                op: SealedOp::new(collision_digest, append(1, json!("b"))),
            },
            IssuedOp {
                issuer_id: issuer,
                op: SealedOp::new(suited_digest("sha256", 0x22), append(2, json!("later"))),
            },
        ]);
        assert_eq!(report.identity_collisions.len(), 1);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0]["value"], "later");
    }

    #[test]
    fn duplicate_cell_projection_is_rejected() {
        let cell_ref = cell();
        let effects = vec![
            ProjectionEffect::join(cell_ref.clone(), append(0, json!("one"))),
            ProjectionEffect::join(cell_ref, append(0, json!("other"))),
        ];
        assert!(ensure_unique_ordered_log_slots(&effects).is_err());
    }

    #[test]
    fn issuer_free_join_fails_closed() {
        let ops = vec![SealedOp::new(
            suited_digest("sha256", 1),
            append(0, json!("e0")),
        )];
        assert!(matches!(
            OrderedLog.join(&cell(), &ops),
            CellState::Bottom(_)
        ));
    }
}
