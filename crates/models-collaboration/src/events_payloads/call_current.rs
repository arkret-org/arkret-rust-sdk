//! Complete Call assertion sets and their source-ordered effective folds.

use std::collections::BTreeMap;

use arkret_wire::{CommitStreamRef, CurrentRevision, Result, WireError};

use super::call::*;

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}

impl CallRosterCurrentValue {
    pub fn validate_for_axis(
        &self,
        stream: &CommitStreamRef,
        revision: &CurrentRevision,
    ) -> Result<()> {
        self.validate_sources(stream, revision)?;
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
        Ok(self
            .active_participants()?
            .into_iter()
            .map(|(participant, _)| participant)
            .collect())
    }

    pub fn active_participants(&self) -> Result<Vec<(CallParticipant, arkret_wire::RealmCommit)>> {
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
                        (participant.clone(), row.source_commit.clone()),
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
        self.validate_sources(stream, revision)?;
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
