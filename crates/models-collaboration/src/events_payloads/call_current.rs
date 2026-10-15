//! Complete Call assertion sets and their source-ordered effective folds.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{CommitStreamRef, CurrentRevision, RealmCommit, Result, WireError};

use super::call::*;
use crate::exact_current_results::CanonicalEventDot;

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}

fn validate_sources<'a>(
    assertions: impl Iterator<Item = (&'a CanonicalEventDot, &'a RealmCommit)>,
    stream: &CommitStreamRef,
    revision: &CurrentRevision,
    write_index: u16,
) -> Result<()> {
    let mut previous = None;
    let mut positions = BTreeSet::new();
    let mut latest: Option<&RealmCommit> = None;
    for (dot, commit) in assertions {
        commit.validate_shape()?;
        commit.validate_content_address()?;
        if dot.write_index() != write_index
            || dot.event_id() != &commit.event_ref
            || &commit.stream_ref != stream
            || &commit.realm_id != stream.realm_id()
            || !positions.insert(commit.stream_position)
            || previous.is_some_and(|old| old >= dot)
        {
            return Err(invalid(
                "Call assertion set has conflicting source provenance",
            ));
        }
        previous = Some(dot);
        if latest.is_none_or(|old| old.stream_position < commit.stream_position) {
            latest = Some(commit);
        }
    }
    let latest = latest.ok_or_else(|| invalid("Call current has no accepted assertion"))?;
    if latest.stream_position != revision.stream_position || latest.commit_id != revision.commit_id
    {
        return Err(invalid(
            "Call current revision differs from its final assertion",
        ));
    }
    Ok(())
}

impl CallRosterCurrentValue {
    pub fn validate_for_axis(
        &self,
        stream: &CommitStreamRef,
        revision: &CurrentRevision,
    ) -> Result<()> {
        validate_sources(
            self.assertions
                .iter()
                .map(|row| (&row.tag_id, &row.source_commit)),
            stream,
            revision,
            7,
        )?;
        self.effective_participants().map(|_| ())
    }

    pub fn with_assertion(mut self, entry: CallRosterAssertion) -> Result<Self> {
        match self
            .assertions
            .binary_search_by(|row| row.tag_id.cmp(&entry.tag_id))
        {
            Ok(index) => {
                if serde_json::to_value(&self.assertions[index])? != serde_json::to_value(entry)? {
                    return Err(invalid("Call roster dot has a different immutable carrier"));
                }
            }
            Err(index) => self.assertions.insert(index, entry),
        }
        Ok(self)
    }

    pub fn effective_participants(&self) -> Result<Vec<CallParticipant>> {
        let mut ordered: Vec<_> = self.assertions.iter().collect();
        ordered.sort_by_key(|row| row.source_commit.stream_position);
        let mut active = BTreeMap::new();
        let mut revision: Option<CurrentRevision> = None;
        for row in ordered {
            match &row.value {
                CallRosterDelta::Join { participant } => {
                    participant.validate_binding_carrier().map_err(invalid)?;
                    active.insert(
                        (participant.actor_id.clone(), participant.device_id.clone()),
                        participant.clone(),
                    );
                    if active.len() > 1000 {
                        return Err(invalid(
                            "Call effective roster exceeds its participant limit",
                        ));
                    }
                }
                CallRosterDelta::Leave {
                    actor_id,
                    device_id,
                    expected_revision,
                } => {
                    if revision.as_ref() != Some(expected_revision)
                        || active
                            .remove(&(actor_id.clone(), device_id.clone()))
                            .is_none()
                    {
                        return Err(invalid(
                            "Call leave does not match its complete roster revision",
                        ));
                    }
                }
            }
            revision = Some(CurrentRevision {
                commit_id: row.source_commit.commit_id.clone(),
                stream_position: row.source_commit.stream_position,
            });
        }
        Ok(active.into_values().collect())
    }
}

impl CallModerationCurrentValue {
    pub fn validate_for_axis(
        &self,
        stream: &CommitStreamRef,
        revision: &CurrentRevision,
    ) -> Result<()> {
        validate_sources(
            self.assertions
                .iter()
                .map(|row| (&row.tag_id, &row.source_commit)),
            stream,
            revision,
            6,
        )?;
        self.effective_removals().map(|_| ())
    }

    pub fn with_assertion(mut self, entry: CallModerationAssertion) -> Result<Self> {
        match self
            .assertions
            .binary_search_by(|row| row.tag_id.cmp(&entry.tag_id))
        {
            Ok(index) => {
                if serde_json::to_value(&self.assertions[index])? != serde_json::to_value(entry)? {
                    return Err(invalid(
                        "Call moderation dot has a different immutable carrier",
                    ));
                }
            }
            Err(index) => self.assertions.insert(index, entry),
        }
        Ok(self)
    }

    pub fn effective_removals(&self) -> Result<Vec<CallParticipantRemoval>> {
        let mut ordered: Vec<_> = self.assertions.iter().collect();
        ordered.sort_by_key(|row| row.source_commit.stream_position);
        let mut active: Vec<CallParticipantRemoval> = Vec::new();
        let mut revision: Option<CurrentRevision> = None;
        for row in ordered {
            match &row.value {
                CallModerationDelta::RemoveParticipant { removal } => {
                    if (removal.action == CallParticipantRemovalAction::Kick)
                        != removal.device_id.is_some()
                    {
                        return Err(invalid(
                            "Call kick or ban target has an invalid device carrier",
                        ));
                    }
                    active.retain(|old| {
                        old.actor_id != removal.actor_id
                            || old.device_id != removal.device_id
                            || old.action != removal.action
                    });
                    active.push(removal.clone());
                }
                CallModerationDelta::RestoreParticipant {
                    actor_id,
                    expected_revision,
                    ..
                } => {
                    if revision.as_ref() != Some(expected_revision)
                        || !active.iter().any(|old| {
                            &old.actor_id == actor_id
                                && old.action == CallParticipantRemovalAction::Ban
                        })
                    {
                        return Err(invalid(
                            "Call restore does not match an active ban and axis revision",
                        ));
                    }
                    active.retain(|old| {
                        &old.actor_id != actor_id || old.action != CallParticipantRemovalAction::Ban
                    });
                }
            }
            revision = Some(CurrentRevision {
                commit_id: row.source_commit.commit_id.clone(),
                stream_position: row.source_commit.stream_position,
            });
        }
        Ok(active)
    }
}
