//! MAL-11 Anchor compaction policy.
//!
//! Compaction is a two-step process:
//!
//! 1. The anchorer publishes a [`crate::AnchorKind::Compaction`] anchor
//!    whose `frontier` equals the predecessor-frontier union (no new
//!    Moves). The compaction Anchor is signed and indexed in the DAG
//!    just like a normal Anchor; receivers MUST validate its id and
//!    signature.
//!
//! 2. After a compaction Anchor has finalized (depth + age sufficient),
//!    the store may [`crate::AnchorStore::prune_predecessor`] historical
//!    Anchors that the compaction Anchor witnesses. The
//!    [`CompactionPolicy`] decides which predecessors are eligible.
//!
//! This module is **policy only** — it doesn't touch the store. The
//! caller (typically the principal-server) drives the prune walk after
//! consulting [`CompactionPolicy::is_eligible`] for each candidate.

use serde::{Deserialize, Serialize};

use crate::Anchor;

/// Compaction policy parameters. Tunable per Realm; sensible defaults
/// are provided by [`CompactionPolicy::default`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CompactionPolicy {
    /// Minimum age (in seconds) of an Anchor before it becomes
    /// prune-eligible. Anchors younger than this MUST NOT be pruned even
    /// when a compaction Anchor has witnessed them — gives slow
    /// federation peers time to backfill and verify before history is
    /// dropped.
    ///
    /// Default: 7 days (`604_800`).
    pub min_anchor_age_seconds: u64,

    /// Minimum number of compaction Anchors between the pruning candidate
    /// and the current leaf set. A value of 1 means "any Anchor witnessed
    /// by ≥ 1 compaction Anchor is eligible". Higher values give
    /// stronger safety at the cost of slower DAG shrinkage.
    ///
    /// Default: 1.
    pub min_compaction_witnesses: u32,

    /// Refuse to prune the genesis Anchor. Set `true` to enforce the
    /// "Realm always retains its genesis" property — useful for audit
    /// trails. Set `false` only when the operator explicitly accepts
    /// genesis prune (e.g. for ephemeral test Spaces).
    ///
    /// Default: `true`.
    pub preserve_genesis: bool,

    /// Refuse to prune Anchors with more than one direct successor
    /// (DAG forks). Pruning a fork-point is structurally valid but
    /// generally indicates the operator wants to flatten history; this
    /// flag keeps the prune walk conservative by default.
    ///
    /// Default: `true`.
    pub prune_only_singleton_successors: bool,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            min_anchor_age_seconds: 7 * 24 * 60 * 60, // 7 days
            min_compaction_witnesses: 1,
            preserve_genesis: true,
            prune_only_singleton_successors: true,
        }
    }
}

/// Reason a candidate Anchor was rejected for pruning. `None`-equivalent
/// (i.e. eligible) means [`CompactionPolicy::is_eligible`] returned
/// [`PruneEligibility::Eligible`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PruneEligibility {
    /// All policy checks passed — caller MAY invoke
    /// [`crate::AnchorStore::prune_predecessor`].
    Eligible,
    /// Candidate is younger than [`CompactionPolicy::min_anchor_age_seconds`].
    TooYoung { age_seconds: u64, required: u64 },
    /// Fewer than [`CompactionPolicy::min_compaction_witnesses`]
    /// compaction Anchors stand between this candidate and the leaf
    /// set.
    InsufficientWitnesses { witnesses: u32, required: u32 },
    /// Candidate is the genesis Anchor and policy preserves genesis.
    PreservedGenesis,
    /// Candidate is a fork-point (multiple direct successors) and policy
    /// disallows pruning across forks.
    ForkPoint { successor_count: usize },
    /// Candidate is a compaction Anchor itself. Compaction Anchors
    /// anchor the prune walk; pruning one would invalidate the witness
    /// chain.
    CompactionItself,
}

impl PruneEligibility {
    pub fn is_eligible(&self) -> bool {
        matches!(self, PruneEligibility::Eligible)
    }
}

/// Inputs needed to evaluate [`CompactionPolicy::is_eligible`] for one
/// candidate. The caller pre-computes these from the store before
/// asking the policy whether to prune.
#[derive(Clone, Debug)]
pub struct PruneCandidate<'a> {
    /// The candidate Anchor itself.
    pub candidate: &'a Anchor,
    /// Wall-clock time (seconds since the candidate's `hlc` was minted).
    /// The caller derives this from the HLC's leading timestamp segment
    /// or from a separate `received_at` field.
    pub age_seconds: u64,
    /// Number of compaction Anchors on every path from the candidate to
    /// the current leaf set. The caller is responsible for the DAG
    /// traversal; the policy only counts.
    pub compaction_witnesses: u32,
    /// Number of direct successors. Used by the fork-point check.
    pub successor_count: usize,
    /// Whether the candidate is the Realm's genesis Anchor.
    pub is_genesis: bool,
}

impl CompactionPolicy {
    /// Evaluate this policy against a single candidate. Returns
    /// [`PruneEligibility::Eligible`] when the caller MAY proceed with
    /// the prune.
    pub fn is_eligible(&self, candidate: &PruneCandidate<'_>) -> PruneEligibility {
        if candidate.candidate.kind.is_compaction() {
            return PruneEligibility::CompactionItself;
        }
        if self.preserve_genesis && candidate.is_genesis {
            return PruneEligibility::PreservedGenesis;
        }
        if self.prune_only_singleton_successors && candidate.successor_count != 1 {
            return PruneEligibility::ForkPoint { successor_count: candidate.successor_count };
        }
        if candidate.age_seconds < self.min_anchor_age_seconds {
            return PruneEligibility::TooYoung {
                age_seconds: candidate.age_seconds,
                required: self.min_anchor_age_seconds,
            };
        }
        if candidate.compaction_witnesses < self.min_compaction_witnesses {
            return PruneEligibility::InsufficientWitnesses {
                witnesses: candidate.compaction_witnesses,
                required: self.min_compaction_witnesses,
            };
        }
        PruneEligibility::Eligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnchorId, AnchorKind, AnchorerSig, Hash, Hlc, MoveId, MoveSignature, RealmId};

    fn anchor(kind: AnchorKind) -> Anchor {
        let sig = MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:a.example#k1".to_owned(),
            payload_digest: Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap(),
            created_at: chrono::Utc::now(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        };
        Anchor {
            id: AnchorId::new(format!("ck:anchor:sha256:{}", "00".repeat(32))).unwrap(),
            realm_id: RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned())
                .unwrap(),
            predecessor_refs: vec![],
            frontier: vec![MoveId::new(format!("sha256:{}", "11".repeat(32))).unwrap()],
            state_root: Hash::new(format!("sha256:{}", "77".repeat(32))).unwrap(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            anchorer_signature: AnchorerSig::Single(sig),
            anchored_at: chrono::Utc::now(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind,
        }
    }

    fn candidate(
        a: &Anchor,
        age: u64,
        witnesses: u32,
        succ: usize,
        is_g: bool,
    ) -> PruneCandidate<'_> {
        PruneCandidate {
            candidate: a,
            age_seconds: age,
            compaction_witnesses: witnesses,
            successor_count: succ,
            is_genesis: is_g,
        }
    }

    #[test]
    fn default_policy_has_sane_values() {
        let p = CompactionPolicy::default();
        assert_eq!(p.min_anchor_age_seconds, 604_800);
        assert_eq!(p.min_compaction_witnesses, 1);
        assert!(p.preserve_genesis);
        assert!(p.prune_only_singleton_successors);
    }

    #[test]
    fn compaction_anchor_itself_never_eligible() {
        let a = anchor(AnchorKind::Compaction);
        let p = CompactionPolicy::default();
        // Even with all other conditions perfect, a compaction anchor is
        // never pruned (it anchors the witness chain).
        let c = candidate(&a, u64::MAX, u32::MAX, 1, false);
        assert_eq!(p.is_eligible(&c), PruneEligibility::CompactionItself);
    }

    #[test]
    fn genesis_preserved_by_default() {
        let a = anchor(AnchorKind::Normal);
        let p = CompactionPolicy::default();
        let c = candidate(&a, u64::MAX, u32::MAX, 1, true);
        assert_eq!(p.is_eligible(&c), PruneEligibility::PreservedGenesis);
    }

    #[test]
    fn fork_point_rejected_by_default() {
        let a = anchor(AnchorKind::Normal);
        let p = CompactionPolicy::default();
        // Two direct successors — fork point.
        let c = candidate(&a, u64::MAX, u32::MAX, 2, false);
        match p.is_eligible(&c) {
            PruneEligibility::ForkPoint { successor_count } => {
                assert_eq!(successor_count, 2);
            }
            other => panic!("expected ForkPoint, got {other:?}"),
        }
        // Zero successors (leaf) also gets ForkPoint per policy.
        let c0 = candidate(&a, u64::MAX, u32::MAX, 0, false);
        assert!(matches!(p.is_eligible(&c0), PruneEligibility::ForkPoint { .. }));
    }

    #[test]
    fn too_young_rejected() {
        let a = anchor(AnchorKind::Normal);
        let p = CompactionPolicy::default();
        let c = candidate(&a, 60, 5, 1, false); // 1 minute old
        match p.is_eligible(&c) {
            PruneEligibility::TooYoung { age_seconds, required } => {
                assert_eq!(age_seconds, 60);
                assert_eq!(required, 604_800);
            }
            other => panic!("expected TooYoung, got {other:?}"),
        }
    }

    #[test]
    fn insufficient_witnesses_rejected() {
        let a = anchor(AnchorKind::Normal);
        let p = CompactionPolicy::default();
        // Old enough, but zero compaction witnesses.
        let c = candidate(&a, u64::MAX, 0, 1, false);
        match p.is_eligible(&c) {
            PruneEligibility::InsufficientWitnesses { witnesses, required } => {
                assert_eq!(witnesses, 0);
                assert_eq!(required, 1);
            }
            other => panic!("expected InsufficientWitnesses, got {other:?}"),
        }
    }

    #[test]
    fn eligible_when_all_conditions_met() {
        let a = anchor(AnchorKind::Normal);
        let p = CompactionPolicy::default();
        let c = candidate(&a, 604_800, 1, 1, false);
        assert_eq!(p.is_eligible(&c), PruneEligibility::Eligible);
        assert!(p.is_eligible(&c).is_eligible());
    }

    #[test]
    fn relaxed_policy_allows_younger_anchors() {
        let a = anchor(AnchorKind::Normal);
        let p = CompactionPolicy {
            min_anchor_age_seconds: 60,
            min_compaction_witnesses: 1,
            preserve_genesis: true,
            prune_only_singleton_successors: true,
        };
        let c = candidate(&a, 60, 1, 1, false);
        assert_eq!(p.is_eligible(&c), PruneEligibility::Eligible);
    }

    #[test]
    fn aggressive_policy_allows_fork_point_pruning() {
        let a = anchor(AnchorKind::Normal);
        let p = CompactionPolicy {
            min_anchor_age_seconds: 0,
            min_compaction_witnesses: 0,
            preserve_genesis: false,
            prune_only_singleton_successors: false,
        };
        // Fork point with 3 children, genesis, zero age, zero witnesses —
        // everything off — still eligible.
        let c = candidate(&a, 0, 0, 3, true);
        assert_eq!(p.is_eligible(&c), PruneEligibility::Eligible);
    }

    #[test]
    fn prune_eligibility_serializes_for_diagnostics() {
        // Just sanity-check that the policy itself round-trips.
        let p = CompactionPolicy::default();
        let json = serde_json::to_string(&p).unwrap();
        let back: CompactionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
