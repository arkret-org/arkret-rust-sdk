//! Complete effective Call entries and their exact last accepted source.

use std::collections::BTreeSet;

use arkret_wire::{CommitStreamRef, CurrentRevision, Result, WireError};

use super::call::*;

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}
fn revision(commit: &arkret_wire::RealmCommit) -> CurrentRevision {
    CurrentRevision {
        commit_id: commit.commit_id.clone(),
        stream_position: commit.stream_position,
    }
}

impl CallRosterCurrentValue {
    pub fn validate_for_axis(
        &self,
        stream: &CommitStreamRef,
        current: &CurrentRevision,
    ) -> Result<()> {
        self.validate_sources(stream, current)
    }
    pub fn apply_delta(
        previous: Option<&Self>,
        source: CallRosterSource,
        key: Option<CallParticipantSigningKey>,
    ) -> Result<Self> {
        if let Some(previous) = previous {
            previous.validate_for_axis(
                &previous.last_source.source_commit.stream_ref,
                &revision(&previous.last_source.source_commit),
            )?;
            if source.source_commit.stream_ref != previous.last_source.source_commit.stream_ref
                || source.source_commit.stream_position
                    <= previous.last_source.source_commit.stream_position
            {
                return Err(invalid("Call roster delta does not advance its exact axis"));
            }
        }
        let mut entries = previous.map(|p| p.entries.clone()).unwrap_or_default();
        match &source.value {
            CallRosterDelta::Join { participant } => {
                entries.retain(|entry| !matches!(&entry.value, CallRosterDelta::Join { participant: old } if old.actor_id == participant.actor_id && old.device_id == participant.device_id));
                entries.push(CallRosterEntry {
                    tag_id: source.tag_id.clone(),
                    source_commit: source.source_commit.clone(),
                    value: source.value.clone(),
                    participant_signing_key: key,
                });
            }
            CallRosterDelta::Leave {
                actor_id,
                device_id,
                expected_revision,
            } => {
                arkret_wire::DeviceId::new(device_id.clone())
                    .map_err(|error| invalid(&error.to_string()))?;
                if previous
                    .is_none_or(|p| revision(&p.last_source.source_commit) != *expected_revision)
                    || key.is_some()
                {
                    return Err(invalid(
                        "Call leave does not match its preceding axis revision",
                    ));
                }
                let old_len = entries.len();
                entries.retain(|entry| !matches!(&entry.value, CallRosterDelta::Join { participant } if participant.actor_id == *actor_id && participant.device_id == *device_id));
                if entries.len() == old_len {
                    return Err(invalid("Call leave target is absent"));
                }
            }
        }
        entries.sort_by(|a, b| a.tag_id.cmp(&b.tag_id));
        let result = Self {
            entries,
            last_source: source,
        };
        result.validate_for_axis(
            &result.last_source.source_commit.stream_ref,
            &revision(&result.last_source.source_commit),
        )?;
        Ok(result)
    }
    pub(crate) fn validate_effective_entries(&self) -> Result<()> {
        if self.entries.len() > 1000 {
            return Err(invalid(
                "Call effective roster exceeds its participant limit",
            ));
        }
        let mut identities = BTreeSet::new();
        for entry in &self.entries {
            let CallRosterDelta::Join { participant } = &entry.value else {
                return Err(invalid("Call roster entry is not a join"));
            };
            participant.validate_binding_carrier().map_err(invalid)?;
            arkret_wire::DeviceId::new(participant.device_id.clone())
                .map_err(|error| invalid(&error.to_string()))?;
            if participant
                .participant_binding
                .as_ref()
                .is_some_and(|binding| binding.expires_at <= entry.source_commit.committed_at)
            {
                return Err(invalid(
                    "Call original binding expired before its accepting Commit",
                ));
            }

            if !identities.insert((participant.actor_id.clone(), participant.device_id.clone())) {
                return Err(invalid("Call roster repeats an actor/device"));
            }
            if participant.participant_binding.is_some() != entry.participant_signing_key.is_some()
            {
                return Err(invalid(
                    "Call participant binding and historical issuer key differ",
                ));
            }
            if let Some(key) = &entry.participant_signing_key {
                let bytes = arkret_canonical::base64url_decode(&key.public_key_b64u)
                    .map_err(|e| invalid(&e.to_string()))?;
                if bytes.len() != 32
                    || arkret_canonical::base64url_encode(&bytes) != key.public_key_b64u
                {
                    return Err(invalid("Call participant issuer key is not Ed25519"));
                }
            }
        }
        match &self.last_source.value {
            CallRosterDelta::Join { .. } => {
                let entry = self
                    .entries
                    .iter()
                    .find(|entry| entry.tag_id == self.last_source.tag_id)
                    .ok_or_else(|| invalid("Call roster omits its latest join"))?;
                if serde_json::to_value(&entry.value)?
                    != serde_json::to_value(&self.last_source.value)?
                {
                    return Err(invalid("Call roster latest join value differs"));
                }
            }
            CallRosterDelta::Leave {
                actor_id,
                device_id,
                expected_revision,
            } => {
                arkret_wire::DeviceId::new(device_id.clone())
                    .map_err(|error| invalid(&error.to_string()))?;
                if expected_revision.stream_position
                    >= self.last_source.source_commit.stream_position
                    || self.entries.iter().any(|e| {
                        e.source_commit.stream_position
                            >= self.last_source.source_commit.stream_position
                    })
                {
                    return Err(invalid(
                        "Call leave provenance does not follow its prior axis",
                    ));
                }
                if identities.contains(&(actor_id.clone(), device_id.clone())) {
                    return Err(invalid("Call roster retains its latest departed leg"));
                }
            }
        }
        Ok(())
    }
    pub fn effective_participants(&self) -> Result<Vec<CallParticipant>> {
        Ok(self
            .active_participants()?
            .into_iter()
            .map(|(participant, _)| participant)
            .collect())
    }
    pub fn active_participants(&self) -> Result<Vec<(CallParticipant, arkret_wire::RealmCommit)>> {
        self.validate_effective_entries()?;
        self.entries
            .iter()
            .map(|entry| match &entry.value {
                CallRosterDelta::Join { participant } => {
                    Ok((participant.clone(), entry.source_commit.clone()))
                }
                _ => Err(invalid("Call roster contains a non-join entry")),
            })
            .collect()
    }
}

impl CallModerationCurrentValue {
    pub fn validate_for_axis(
        &self,
        stream: &CommitStreamRef,
        current: &CurrentRevision,
    ) -> Result<()> {
        self.validate_sources(stream, current)
    }
    pub fn apply_delta(previous: Option<&Self>, source: CallModerationSource) -> Result<Self> {
        if let Some(previous) = previous {
            previous.validate_for_axis(
                &previous.last_source.source_commit.stream_ref,
                &revision(&previous.last_source.source_commit),
            )?;
            if source.source_commit.stream_ref != previous.last_source.source_commit.stream_ref
                || source.source_commit.stream_position
                    <= previous.last_source.source_commit.stream_position
            {
                return Err(invalid(
                    "Call moderation delta does not advance its exact axis",
                ));
            }
        }
        let mut entries = previous.map(|p| p.entries.clone()).unwrap_or_default();
        match &source.value {
            CallModerationDelta::RemoveParticipant { removal } => {
                entries.retain(|entry|!matches!(&entry.value, CallModerationDelta::RemoveParticipant { removal:old } if old.actor_id==removal.actor_id && old.device_id==removal.device_id && old.action==removal.action));
                entries.push(CallModerationEntry {
                    tag_id: source.tag_id.clone(),
                    source_commit: source.source_commit.clone(),
                    value: source.value.clone(),
                });
            }
            CallModerationDelta::RestoreParticipant {
                actor_id,
                expected_revision,
                ..
            } => {
                if previous
                    .is_none_or(|p| revision(&p.last_source.source_commit) != *expected_revision)
                {
                    return Err(invalid(
                        "Call restore does not match its preceding axis revision",
                    ));
                }
                let old_len = entries.len();
                entries.retain(|entry|!matches!(&entry.value, CallModerationDelta::RemoveParticipant { removal } if removal.actor_id==*actor_id && removal.action==CallParticipantRemovalAction::Ban));
                if entries.len() == old_len {
                    return Err(invalid("Call restore target has no active ban"));
                }
            }
        }
        entries.sort_by(|a, b| a.tag_id.cmp(&b.tag_id));
        let result = Self {
            entries,
            last_source: source,
        };
        result.validate_for_axis(
            &result.last_source.source_commit.stream_ref,
            &revision(&result.last_source.source_commit),
        )?;
        Ok(result)
    }
    pub(crate) fn validate_effective_entries(&self) -> Result<()> {
        let mut identities = BTreeSet::new();
        for entry in &self.entries {
            let CallModerationDelta::RemoveParticipant { removal } = &entry.value else {
                return Err(invalid("Call moderation entry is not a removal"));
            };
            if let Some(device) = &removal.device_id {
                arkret_wire::DeviceId::new(device.clone())
                    .map_err(|error| invalid(&error.to_string()))?;
            }
            if (removal.action == CallParticipantRemovalAction::Kick) != removal.device_id.is_some()
                || !identities.insert((
                    removal.actor_id.clone(),
                    removal.device_id.clone(),
                    removal.action == CallParticipantRemovalAction::Kick,
                ))
            {
                return Err(invalid(
                    "Call moderation has an invalid or duplicate target",
                ));
            }
        }
        match &self.last_source.value {
            CallModerationDelta::RemoveParticipant { .. } => {
                let entry = self
                    .entries
                    .iter()
                    .find(|entry| entry.tag_id == self.last_source.tag_id)
                    .ok_or_else(|| invalid("Call moderation omits its latest removal"))?;
                if serde_json::to_value(&entry.value)?
                    != serde_json::to_value(&self.last_source.value)?
                {
                    return Err(invalid("Call latest moderation value differs"));
                }
            }
            CallModerationDelta::RestoreParticipant {
                actor_id,
                expected_revision,
                ..
            } => {
                if expected_revision.stream_position
                    >= self.last_source.source_commit.stream_position
                    || self.entries.iter().any(|e| {
                        e.source_commit.stream_position
                            >= self.last_source.source_commit.stream_position
                    })
                {
                    return Err(invalid(
                        "Call restore provenance does not follow its prior axis",
                    ));
                }
                if self.entries.iter().any(|entry|matches!(&entry.value, CallModerationDelta::RemoveParticipant { removal } if removal.actor_id==*actor_id && removal.action==CallParticipantRemovalAction::Ban)) {
                    return Err(invalid("Call moderation retains its restored ban"));
                }
            }
        }
        Ok(())
    }
    pub fn effective_removals(&self) -> Result<Vec<CallParticipantRemoval>> {
        self.validate_effective_entries()?;
        self.entries
            .iter()
            .map(|entry| match &entry.value {
                CallModerationDelta::RemoveParticipant { removal } => Ok(removal.clone()),
                _ => Err(invalid("Call moderation contains a non-removal entry")),
            })
            .collect()
    }
}
