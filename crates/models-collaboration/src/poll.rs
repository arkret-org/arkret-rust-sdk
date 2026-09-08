//! Derived Poll response state (content-types §4.9). This is not a wire carrier.
//!
//! Callers supply accepted, verified facts from one validity baseline. Encrypted
//! Events whose content is still unknown must not be classified as non-responses.
//! Rebuild this state when quarantine or fork resolution changes that baseline.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use arkret_wire::{ActorId, CircleId, Hash, MessageId, RealmId};

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PollSelectionError {
    #[error("poll_selection_empty")]
    Empty,
    #[error("poll_selection_duplicate")]
    Duplicate,
    #[error("poll_selection_unknown")]
    Unknown,
    #[error("poll_selection_limit_exceeded")]
    LimitExceeded,
}

pub fn validate_poll_selections(
    selections: &[String],
    answer_ids: &BTreeSet<String>,
    max_selections: usize,
) -> Result<BTreeSet<String>, PollSelectionError> {
    if selections.is_empty() {
        return Err(PollSelectionError::Empty);
    }
    let unique: BTreeSet<_> = selections.iter().cloned().collect();
    if unique.len() != selections.len() {
        return Err(PollSelectionError::Duplicate);
    }
    if !unique.is_subset(answer_ids) {
        return Err(PollSelectionError::Unknown);
    }
    if unique.len() > max_selections {
        return Err(PollSelectionError::LimitExceeded);
    }
    Ok(unique)
}

/// Equality of the complete typed ActorId is equality of its canonical JCS value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PollPartition {
    pub realm_id: RealmId,
    pub scope_circle_id: Option<CircleId>,
    pub poll_ref: MessageId,
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollResponseFact {
    pub partition: PollPartition,
    pub selections: BTreeSet<String>,
    pub causal_refs: BTreeSet<Hash>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PollResponseSet {
    responses: BTreeMap<Hash, PollResponseFact>,
    non_responses: BTreeSet<Hash>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PollOutcome {
    pub heads: BTreeSet<Hash>,
    pub winner: Option<Hash>,
    pub selections: BTreeSet<String>,
    pub pending: BTreeSet<Hash>,
    /// Cycles, self-references and their same-partition descendants cannot vote.
    pub invalid: BTreeSet<Hash>,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("conflicting verified Poll classification for canonical Event digest {0}")]
pub struct PollFactConflict(pub Hash);

impl PollResponseSet {
    pub fn responses(&self) -> &BTreeMap<Hash, PollResponseFact> {
        &self.responses
    }

    pub fn awaits_classification(&self, digest: &Hash) -> bool {
        !self.non_responses.contains(digest)
            && !self.responses.contains_key(digest)
            && self
                .responses
                .values()
                .any(|fact| fact.causal_refs.contains(digest))
    }

    pub fn insert(&mut self, digest: Hash, fact: PollResponseFact) -> Result<(), PollFactConflict> {
        if self.non_responses.contains(&digest)
            || self.responses.get(&digest).is_some_and(|old| old != &fact)
        {
            return Err(PollFactConflict(digest));
        }
        self.responses.insert(digest, fact);
        Ok(())
    }

    /// Record a verified Event known not to be a valid Poll response. An unknown
    /// or not-yet-decrypted Event must remain absent from both collections.
    pub fn observe_non_response(&mut self, digest: Hash) -> Result<(), PollFactConflict> {
        if self.responses.contains_key(&digest) {
            return Err(PollFactConflict(digest));
        }
        self.non_responses.insert(digest);
        Ok(())
    }

    /// Join complete verified facts, never cached winners. Conflicts are atomic.
    pub fn merge(&mut self, other: &Self) -> Result<(), PollFactConflict> {
        for (digest, fact) in &other.responses {
            if self.non_responses.contains(digest)
                || self.responses.get(digest).is_some_and(|old| old != fact)
            {
                return Err(PollFactConflict(digest.clone()));
            }
        }
        if let Some(digest) = other
            .non_responses
            .iter()
            .find(|d| self.responses.contains_key(*d))
        {
            return Err(PollFactConflict(digest.clone()));
        }
        self.responses.extend(other.responses.clone());
        self.non_responses.extend(other.non_responses.clone());
        Ok(())
    }

    /// Withdraw a fact and its classification when the validity baseline changes.
    /// Successors wait until the caller resolves their dependencies again.
    pub fn remove(&mut self, digest: &Hash) {
        self.responses.remove(digest);
        self.non_responses.remove(digest);
    }

    pub fn project(&self) -> BTreeMap<PollPartition, PollOutcome> {
        let mut outcomes = BTreeMap::<PollPartition, PollOutcome>::new();
        let mut predecessors = BTreeMap::<Hash, BTreeSet<Hash>>::new();
        let mut successors = BTreeMap::<Hash, BTreeSet<Hash>>::new();
        let mut unresolved = BTreeSet::new();
        for (digest, fact) in &self.responses {
            outcomes.entry(fact.partition.clone()).or_default();
            let edges = predecessors.entry(digest.clone()).or_default();
            for dependency in &fact.causal_refs {
                match self.responses.get(dependency) {
                    Some(prior) if prior.partition == fact.partition => {
                        edges.insert(dependency.clone());
                        successors
                            .entry(dependency.clone())
                            .or_default()
                            .insert(digest.clone());
                    }
                    Some(_) => {}
                    None if self.non_responses.contains(dependency) => {}
                    None => {
                        unresolved.insert(digest.clone());
                    }
                }
            }
        }
        // Topological traversal detects cycles without recursion. Dependencies
        // from another partition never become an edge or a transitive bridge.
        let mut degree: BTreeMap<_, _> = predecessors
            .iter()
            .map(|(d, p)| (d.clone(), p.len()))
            .collect();
        let mut ready: VecDeque<_> = degree
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(d, _)| d.clone())
            .collect();
        let mut visited = BTreeSet::new();
        let mut closed = BTreeSet::new();
        while let Some(digest) = ready.pop_front() {
            visited.insert(digest.clone());
            if !unresolved.contains(&digest)
                && predecessors[&digest].iter().all(|d| closed.contains(d))
            {
                closed.insert(digest.clone());
            }
            if let Some(next) = successors.get(&digest) {
                for successor in next {
                    let count = degree.get_mut(successor).expect("known response successor");
                    *count -= 1;
                    if *count == 0 {
                        ready.push_back(successor.clone());
                    }
                }
            }
        }
        for (digest, fact) in &self.responses {
            let outcome = outcomes
                .get_mut(&fact.partition)
                .expect("known response partition");
            if !visited.contains(digest) {
                outcome.invalid.insert(digest.clone());
            } else if !closed.contains(digest) {
                outcome.pending.insert(digest.clone());
            } else if successors
                .get(digest)
                .is_none_or(|next| next.iter().all(|d| !closed.contains(d)))
            {
                outcome.heads.insert(digest.clone());
            }
        }
        for outcome in outcomes.values_mut() {
            outcome.winner = outcome
                .heads
                .iter()
                .max_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()))
                .cloned();
            if let Some(winner) = &outcome.winner {
                outcome
                    .selections
                    .clone_from(&self.responses[winner].selections);
            }
        }
        outcomes
    }
}
