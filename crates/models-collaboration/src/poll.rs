//! Poll responses reduced from one verified authority Commit stream.
//!
//! A response belongs to a complete Realm/Circle, poll and Actor partition.
//! Its vote is ordered only by its accepted RealmCommit position. Producer
//! replacement declarations are checked at admission, never used to pick a
//! winner. The caller verifies the Commit chain and supplies whether its scan
//! is a contiguous prefix before showing a projection as final.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{ActorId, CommitStreamRef, CommittedEventRef, EventId, MessageId, RealmId};

use crate::events_payloads::message::PollResponseHead;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PollPartition {
    pub realm_id: RealmId,
    pub stream_ref: CommitStreamRef,
    pub poll_ref: MessageId,
    pub poll_event_ref: EventId,
    pub actor_id: ActorId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PollError {
    #[error("poll response scope differs from its accepted Commit stream")]
    InvalidScope,
    #[error("poll selection is empty")]
    EmptySelection,
    #[error("poll selection contains a duplicate")]
    DuplicateSelection,
    #[error("poll selection names an unknown answer")]
    UnknownAnswer,
    #[error("poll selection exceeds the registered maximum")]
    SelectionLimitExceeded,
    #[error("poll replacement declaration names another partition")]
    InvalidHead,
    #[error("one Event has conflicting poll response facts")]
    DuplicateEventConflict,
    #[error("two Event responses claim one accepted Commit position")]
    CommitPositionConflict,
}

pub fn validate_poll_selections(
    selections: &[String],
    answer_ids: &BTreeSet<String>,
    max_selections: usize,
) -> Result<BTreeSet<String>, PollError> {
    if selections.is_empty() {
        return Err(PollError::EmptySelection);
    }
    let unique = selections.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != selections.len() {
        return Err(PollError::DuplicateSelection);
    }
    if !unique.is_subset(answer_ids) {
        return Err(PollError::UnknownAnswer);
    }
    if unique.len() > max_selections {
        return Err(PollError::SelectionLimitExceeded);
    }
    Ok(unique)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPollResponse {
    pub partition: PollPartition,
    pub accepted_ref: CommittedEventRef,
    pub selections: BTreeSet<String>,
    pub declared_heads: Vec<PollResponseHead>,
}

impl VerifiedPollResponse {
    /// `resolve_response` must read accepted response Event bindings at the
    /// same authority cut. Unknown, quarantined or different-partition heads
    /// are rejected before this response can enter the reducer.
    pub fn new(
        partition: PollPartition,
        accepted_ref: CommittedEventRef,
        selections: &[String],
        answer_ids: &BTreeSet<String>,
        max_selections: usize,
        declared_heads: Vec<PollResponseHead>,
        mut resolve_response: impl FnMut(&EventId) -> Option<(PollPartition, CommittedEventRef)>,
    ) -> Result<Self, PollError> {
        if matches!(partition.stream_ref, CommitStreamRef::Sidecar { .. })
            || partition.realm_id != *partition.stream_ref.realm_id()
            || partition.poll_ref != MessageId::from_event_id(&partition.poll_event_ref)
            || accepted_ref.stream_ref != partition.stream_ref
        {
            return Err(PollError::InvalidScope);
        }
        let selections = validate_poll_selections(selections, answer_ids, max_selections)?;
        let mut seen = BTreeSet::new();
        if declared_heads.len() > 64 {
            return Err(PollError::InvalidHead);
        }
        for head in &declared_heads {
            let predecessor = resolve_response(&head.response_event_ref);
            if head.poll_event_ref != partition.poll_event_ref
                || head.response_event_ref == accepted_ref.event_id
                || !seen.insert(head.response_event_ref.clone())
                || !predecessor.is_some_and(|(prior_partition, prior_ref)| {
                    prior_partition == partition
                        && prior_ref.event_id == head.response_event_ref
                        && prior_ref.stream_ref == accepted_ref.stream_ref
                        && prior_ref.stream_position < accepted_ref.stream_position
                })
            {
                return Err(PollError::InvalidHead);
            }
        }
        Ok(Self {
            partition,
            accepted_ref,
            selections,
            declared_heads,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PollResponseSet {
    responses: BTreeMap<PollPartition, BTreeMap<EventId, VerifiedPollResponse>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollProjection {
    pub winner: Option<CommittedEventRef>,
    pub selections: BTreeSet<String>,
    /// True until the caller has verified a contiguous accepted Commit prefix.
    pub provisional: bool,
}

impl PollResponseSet {
    pub fn insert(&mut self, response: VerifiedPollResponse) -> Result<(), PollError> {
        let rows = self
            .responses
            .entry(response.partition.clone())
            .or_default();
        if let Some(existing) = rows.get(&response.accepted_ref.event_id) {
            return if existing == &response {
                Ok(())
            } else {
                Err(PollError::DuplicateEventConflict)
            };
        }
        if rows.values().any(|existing| {
            existing.accepted_ref.stream_position == response.accepted_ref.stream_position
        }) {
            return Err(PollError::CommitPositionConflict);
        }
        rows.insert(response.accepted_ref.event_id.clone(), response);
        Ok(())
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), PollError> {
        let mut next = self.clone();
        for rows in other.responses.values() {
            for response in rows.values() {
                next.insert(response.clone())?;
            }
        }
        *self = next;
        Ok(())
    }

    /// Rebuild after a quarantine or fork decision changes the valid input set.
    pub fn remove(&mut self, partition: &PollPartition, event_id: &EventId) {
        if let Some(rows) = self.responses.get_mut(partition) {
            rows.remove(event_id);
            if rows.is_empty() {
                self.responses.remove(partition);
            }
        }
    }

    pub fn project(
        &self,
        contiguous_prefix_verified: bool,
    ) -> BTreeMap<PollPartition, PollProjection> {
        self.responses
            .iter()
            .map(|(partition, rows)| {
                let winner = rows
                    .values()
                    .max_by_key(|row| row.accepted_ref.stream_position);
                (
                    partition.clone(),
                    PollProjection {
                        winner: winner.map(|row| row.accepted_ref.clone()),
                        selections: winner.map(|row| row.selections.clone()).unwrap_or_default(),
                        provisional: !contiguous_prefix_verified,
                    },
                )
            })
            .collect()
    }
}
