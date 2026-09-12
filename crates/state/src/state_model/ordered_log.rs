//! Ordered-log model: a grow-only set of accepted Event entries.
//!
//! `issuer_seq` is the enclosing Event's Realm-scoped `actor_seq`. It is a
//! sparse coordinate inside any one cell, not a cell-local counter. Every
//! accepted same-height sibling remains in the joined value. Digest order is
//! used only to produce stable bytes and never selects a winner.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{OpError, ResolvedCellState, StateModel, StateModelKind, StateWrite};
use crate::{
    ActorId, CanonicalLogEntry, CellRef, Hash, LatticeOp, LatticeOpType, ProjectionEffect,
    canonical,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct OrderedLog;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedOp {
    pub issuer_id: ActorId,
    pub op: StateWrite,
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
    pub entries: Vec<CanonicalLogEntry>,
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
    issuer_id: ActorId,
    issuer_key: String,
    issuer_seq: u64,
    digest: DigestKey,
    event_digest: Hash,
    op_bytes: Vec<u8>,
    value: Value,
}

impl OrderedLog {
    pub fn join_with_issuer_report(
        &self,
        ops: &[IssuedOp],
    ) -> Result<OrderedLogJoinReport, OpError> {
        let mut candidates = Vec::new();
        for entry in ops {
            Self.validate_op(&entry.op.op)?;
            let event_digest = entry.op.event_id.event_digest();
            let issuer_seq = entry.op.op.issuer_seq.expect("validated issuer sequence");
            let value = entry.op.op.value.clone().expect("validated log value");
            let digest = DigestKey::parse(&event_digest).ok_or_else(|| OpError::InvalidValue {
                kind: "ordered_log",
                field: "event_digest",
                reason: "must be a canonical digest".to_owned(),
            })?;
            let op_bytes = canonical::canonical_json_bytes(&entry.op.op).map_err(|error| {
                OpError::InvalidValue {
                    kind: "ordered_log",
                    field: "value",
                    reason: error.to_string(),
                }
            })?;
            let issuer_key =
                entry
                    .issuer_id
                    .canonical_key()
                    .map_err(|error| OpError::InvalidValue {
                        kind: "ordered_log",
                        field: "issuer_id",
                        reason: error.to_string(),
                    })?;
            candidates.push(Candidate {
                issuer_id: entry.issuer_id.clone(),
                issuer_key,
                issuer_seq,
                digest,
                event_digest,
                op_bytes,
                value,
            });
        }

        let mut values_by_identity: BTreeMap<String, BTreeSet<(String, u64, Vec<u8>)>> =
            BTreeMap::new();
        for candidate in &candidates {
            values_by_identity
                .entry(candidate.event_digest.as_str().to_owned())
                .or_default()
                .insert((
                    candidate.issuer_key.clone(),
                    candidate.issuer_seq,
                    candidate.op_bytes.clone(),
                ));
        }
        let colliding: BTreeSet<String> = values_by_identity
            .into_iter()
            .filter_map(|(key, values)| (values.len() > 1).then_some(key))
            .collect();

        let identity_collisions = colliding
            .iter()
            .filter_map(|event_digest| {
                candidates
                    .iter()
                    .find(|candidate| candidate.event_digest.as_str() == event_digest)
                    .map(|candidate| OrderedLogIdentityCollision {
                        issuer: candidate.issuer_key.clone(),
                        issuer_seq: candidate.issuer_seq,
                        reason: "event_identity_collision".to_owned(),
                        event_digest: event_digest.clone(),
                    })
            })
            .collect();

        candidates.retain(|candidate| !colliding.contains(candidate.event_digest.as_str()));
        candidates.sort_by(|left, right| {
            left.issuer_key
                .cmp(&right.issuer_key)
                .then(left.issuer_seq.cmp(&right.issuer_seq))
                .then(left.digest.cmp(&right.digest))
        });
        candidates.dedup_by(|left, right| {
            left.issuer_key == right.issuer_key
                && left.issuer_seq == right.issuer_seq
                && left.event_digest == right.event_digest
                && left.op_bytes == right.op_bytes
        });

        let mut sibling_groups = Vec::new();
        let mut sibling_digests: BTreeMap<(String, u64), Vec<String>> = BTreeMap::new();
        for candidate in &candidates {
            sibling_digests
                .entry((candidate.issuer_key.clone(), candidate.issuer_seq))
                .or_default()
                .push(candidate.event_digest.as_str().to_owned());
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
            .map(|candidate| CanonicalLogEntry {
                event_digest: candidate.event_digest,
                issuer_id: candidate.issuer_id,
                issuer_seq: candidate.issuer_seq,
                value: candidate.value,
            })
            .collect();

        Ok(OrderedLogJoinReport {
            entries,
            sibling_groups,
            identity_collisions,
        })
    }

    pub fn join_with_issuers(
        &self,
        _cell: &CellRef,
        ops: &[IssuedOp],
    ) -> Result<ResolvedCellState, OpError> {
        let report = self.join_with_issuer_report(ops)?;
        if !report.identity_collisions.is_empty() {
            return Err(OpError::InvalidValue {
                kind: "ordered_log",
                field: "event_digest",
                reason: "one Event identity maps to different ordered-log entries".to_owned(),
            });
        }
        Ok(ResolvedCellState::Value(
            serde_json::to_value(report.entries)
                .expect("canonical ordered-log state is JSON serializable"),
        ))
    }
}

impl StateModel for OrderedLog {
    fn kind(&self) -> StateModelKind {
        StateModelKind::OrderedLog
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
                if op.issuer_seq.is_some_and(|seq| seq > 9_007_199_254_740_991) {
                    return Err(OpError::InvalidValue {
                        kind: "ordered_log",
                        field: "issuer_seq",
                        reason: "exceeds the protocol safe-integer maximum".to_owned(),
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

    fn resolve(
        &self,
        _cell: &CellRef,
        _sealed_ops: &[StateWrite],
    ) -> Result<ResolvedCellState, OpError> {
        Err(OpError::InvalidValue {
            kind: "ordered_log",
            field: "issuer_id",
            reason: "issuer attribution is required; use join_with_issuers".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{ActorId, DidCoreId};
    use serde_json::json;

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
            op: StateWrite::new(suited_digest("sha256", byte), append(seq, value)),
        }
    }

    #[test]
    fn sparse_sequences_join_without_pending_gap() {
        let report = OrderedLog
            .join_with_issuer_report(&[
                issued("ak:did_core:webvh:z6mkfixturealice", 3, json!("three"), 3),
                issued("ak:did_core:webvh:z6mkfixturealice", 0, json!("zero"), 1),
            ])
            .unwrap();
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].issuer_seq, 0);
        assert_eq!(report.entries[1].issuer_seq, 3);
        assert_eq!(
            report.entries[0].event_digest.as_str(),
            suited_digest("sha256", 1).as_str()
        );
    }

    #[test]
    fn same_height_siblings_all_join() {
        let report = OrderedLog
            .join_with_issuer_report(&[
                issued("ak:did_core:webvh:z6mkfixturealice", 7, json!("a"), 1),
                issued("ak:did_core:webvh:z6mkfixturealice", 7, json!("b"), 2),
            ])
            .unwrap();
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.sibling_groups.len(), 1);
        assert_eq!(report.sibling_groups[0].event_digests.len(), 2);
    }

    #[test]
    fn exact_replay_is_idempotent() {
        let first = issued("ak:did_core:webvh:z6mkfixturealice", 4, json!("x"), 1);
        let report = OrderedLog
            .join_with_issuer_report(&[first.clone(), first])
            .unwrap();
        assert_eq!(report.entries.len(), 1);
        assert!(report.sibling_groups.is_empty());
    }

    #[test]
    fn canonical_order_uses_decoded_digest_octets() {
        let issuer = ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        );
        let report = OrderedLog
            .join_with_issuer_report(&[
                IssuedOp {
                    issuer_id: issuer.clone(),
                    op: StateWrite::new(suited_digest("blake3", 0xff), append(1, json!("last"))),
                },
                IssuedOp {
                    issuer_id: issuer,
                    op: StateWrite::new(suited_digest("sha256", 0x01), append(1, json!("first"))),
                },
            ])
            .unwrap();
        assert_eq!(report.entries[0].value, "first");
        assert_eq!(report.entries[1].value, "last");
    }

    #[test]
    fn identity_collision_is_quarantined_without_blocking_sibling() {
        let issuer = ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        );
        let collision_digest = suited_digest("sha256", 0x11);
        let report = OrderedLog
            .join_with_issuer_report(&[
                IssuedOp {
                    issuer_id: issuer.clone(),
                    op: StateWrite::new(collision_digest.clone(), append(1, json!("a"))),
                },
                IssuedOp {
                    issuer_id: issuer.clone(),
                    op: StateWrite::new(collision_digest, append(1, json!("b"))),
                },
                IssuedOp {
                    issuer_id: issuer,
                    op: StateWrite::new(suited_digest("sha256", 0x22), append(2, json!("later"))),
                },
            ])
            .unwrap();
        assert_eq!(report.identity_collisions.len(), 1);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].value, "later");
    }

    #[test]
    fn canonical_join_rejects_an_identity_collision() {
        let issuer = ActorId::service(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
        );
        let digest = suited_digest("sha256", 0x11);
        let writes = [
            IssuedOp {
                issuer_id: issuer.clone(),
                op: StateWrite::new(digest.clone(), append(1, json!("a"))),
            },
            IssuedOp {
                issuer_id: issuer,
                op: StateWrite::new(digest, append(1, json!("b"))),
            },
        ];
        assert!(matches!(
            OrderedLog.join_with_issuers(&cell(), &writes),
            Err(OpError::InvalidValue {
                field: "event_digest",
                ..
            })
        ));
    }

    #[test]
    fn canonical_join_serializes_the_typed_issuer_and_event_digest() {
        let write = issued("ak:did_core:webvh:z6mkfixturealice", 4, json!("entry"), 1);
        let ResolvedCellState::Value(value) = OrderedLog
            .join_with_issuers(&cell(), std::slice::from_ref(&write))
            .unwrap()
        else {
            panic!("expected value")
        };
        assert_eq!(value[0]["issuer_id"], json!(write.issuer_id));
        assert_eq!(
            value[0]["event_digest"],
            suited_digest("sha256", 1).as_str()
        );
        assert_ne!(value[0]["event_digest"], write.op.event_id.as_str());
    }

    #[test]
    fn invalid_or_unsafe_sequence_fails_closed() {
        let missing = LatticeOp {
            issuer_seq: None,
            ..append(0, json!("entry"))
        };
        let unsafe_sequence = append(9_007_199_254_740_992, json!("entry"));
        assert!(OrderedLog.validate_op(&missing).is_err());
        assert!(OrderedLog.validate_op(&unsafe_sequence).is_err());
    }

    #[test]
    fn duplicate_cell_projection_is_rejected() {
        let cell_ref = cell();
        let effects = vec![
            ProjectionEffect::new(cell_ref.clone(), append(0, json!("one"))),
            ProjectionEffect::new(cell_ref, append(0, json!("other"))),
        ];
        assert!(ensure_unique_ordered_log_slots(&effects).is_err());
    }

    #[test]
    fn issuer_free_join_fails_closed() {
        let ops = vec![StateWrite::new(
            suited_digest("sha256", 1),
            append(0, json!("e0")),
        )];
        assert!(matches!(
            OrderedLog.resolve(&cell(), &ops),
            Err(OpError::InvalidValue { .. })
        ));
    }
}
