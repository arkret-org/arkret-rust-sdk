//! Private exact-selector control material, never a member history feed.
use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
use arkret_wire::{
    ActorId, AuthoritySubmitOutcome, CommitStreamHead, CommitStreamRef, CommittedEventRef,
    CurrentSelector, DetachedObjectSignature, DetachedSignatureContext, Event, Hash, RealmCommit,
    RealmCommitAuthorityRef, RealmId, Result, TypedCurrentRow, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The authenticated Account Station supplies the requester, never the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRealmActorMaterialRequest {
    pub requester_account_id: arkret_wire::AccountId,
    pub request: RealmActorMaterialRequest,
}

impl PeerRealmActorMaterialRequest {
    pub fn validate_source(&self, source: &arkret_wire::DidCoreId) -> Result<()> {
        self.request.validate()?;
        if &self.requester_account_id.station_id != source {
            return Err(WireError::Protocol(
                "material requester belongs to another Station".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmActorMaterialRequest {
    Current {
        actor_id: ActorId,
        request_nonce: String,
        selectors: Vec<CurrentSelector>,
    },
    Event {
        actor_id: ActorId,
        request_nonce: String,
        target: CommittedEventRef,
    },
    Outcome {
        actor_id: ActorId,
        request_nonce: String,
        target_request_digest: Hash,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmActorMaterialPurpose {
    Current,
    Event,
    Outcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmActorMaterialCurrentEntry {
    Present {
        row: TypedCurrentRow,
        source_ref: CommittedEventRef,
    },
    NeverWritten {
        selector: CurrentSelector,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmActorOperationStatus {
    Pending,
    Unknown,
    Denied,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmActorRecoveryState {
    Pending,
    Completed,
    Cancelled,
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealmActorRecoveryOutcomeStatus {
    #[serde(rename = "recovery")]
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmActorDeviceRevokeState {
    Pending,
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealmActorDeviceRevokeOutcomeStatus {
    #[serde(rename = "device_revoke")]
    DeviceRevoke,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum RealmActorOperationOutcome {
    DeviceRevoke {
        status: RealmActorDeviceRevokeOutcomeStatus,
        proposal_ref: CommittedEventRef,
        device_id: arkret_wire::DeviceId,
        authorization_ref: CommittedEventRef,
        authorized_generation_ref: u64,
        state: RealmActorDeviceRevokeState,
        #[serde(
            serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
            deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
        )]
        decided_at: Option<DateTime<Utc>>,
    },
    Submitted(AuthoritySubmitOutcome),
    Status {
        status: RealmActorOperationStatus,
    },
    Recovery {
        status: RealmActorRecoveryOutcomeStatus,
        begin_ref: CommittedEventRef,
        state: RealmActorRecoveryState,
        #[serde(
            deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable"
        )]
        terminal_ref: Option<CommittedEventRef>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum RealmActorMaterialResult {
    Current {
        entries: Vec<RealmActorMaterialCurrentEntry>,
    },
    Event {
        event: Event,
        commit: RealmCommit,
        producer_signer_fact: HistoricalProducerSignerFact,
    },
    Outcome {
        target_request_digest: Hash,
        outcome: RealmActorOperationOutcome,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorMaterialOutcome {
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub purpose: RealmActorMaterialPurpose,
    pub request_digest: Hash,
    pub request_nonce: String,
    pub requester_actor_id: ActorId,
    pub governance_generation: u64,
    pub authority_ref: RealmCommitAuthorityRef,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub control_stream_head: Option<CommitStreamHead>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub result: RealmActorMaterialResult,
    pub signature: DetachedObjectSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorMaterialUnsigned {
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub purpose: RealmActorMaterialPurpose,
    pub request_digest: Hash,
    pub request_nonce: String,
    pub requester_actor_id: ActorId,
    pub governance_generation: u64,
    pub authority_ref: RealmCommitAuthorityRef,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub control_stream_head: Option<CommitStreamHead>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub result: RealmActorMaterialResult,
}

impl RealmActorMaterialUnsigned {
    pub fn into_signed(self, signature: DetachedObjectSignature) -> RealmActorMaterialOutcome {
        RealmActorMaterialOutcome {
            realm_id: self.realm_id,
            actor_id: self.actor_id,
            purpose: self.purpose,
            request_digest: self.request_digest,
            request_nonce: self.request_nonce,
            requester_actor_id: self.requester_actor_id,
            governance_generation: self.governance_generation,
            authority_ref: self.authority_ref,
            control_stream_head: self.control_stream_head,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            result: self.result,
            signature,
        }
    }
}

fn invalid() -> WireError {
    WireError::Protocol("Realm actor material selectors, cut or bindings are invalid".into())
}

pub fn realm_actor_selector_subject(selector: &CurrentSelector) -> Option<&ActorId> {
    match selector {
        CurrentSelector::RealmActorIdentity { actor_id }
        | CurrentSelector::RealmActorControl { actor_id }
        | CurrentSelector::RealmActorManager { actor_id }
        | CurrentSelector::RealmActorStatus { actor_id, .. }
        | CurrentSelector::RealmActorDeviceGeneration { actor_id }
        | CurrentSelector::RealmActorDeviceAuthorization { actor_id, .. }
        | CurrentSelector::RealmActorDeviceRevocationProposals { actor_id, .. }
        | CurrentSelector::RealmActorProfile { actor_id }
        | CurrentSelector::RealmActorRecovery { actor_id } => Some(actor_id),
        _ => None,
    }
}

impl RealmActorMaterialRequest {
    pub fn actor_id(&self) -> &ActorId {
        match self {
            Self::Current { actor_id, .. }
            | Self::Event { actor_id, .. }
            | Self::Outcome { actor_id, .. } => actor_id,
        }
    }
    pub fn request_nonce(&self) -> &str {
        match self {
            Self::Current { request_nonce, .. }
            | Self::Event { request_nonce, .. }
            | Self::Outcome { request_nonce, .. } => request_nonce,
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.actor_id().validate()?;
        let actor = self.actor_id().as_realm_actor_id().ok_or_else(invalid)?;
        let nonce = self.request_nonce();
        if !(22..=128).contains(&nonce.len())
            || !nonce
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        {
            return Err(invalid());
        }
        match self {
            Self::Current { selectors, .. } => {
                if !(1..=16).contains(&selectors.len()) {
                    return Err(invalid());
                }
                let mut seen = std::collections::BTreeSet::new();
                for selector in selectors {
                    if realm_actor_selector_subject(selector) != Some(self.actor_id())
                        || !seen.insert(arkret_canonical::canonical_json_bytes(selector)?)
                    {
                        return Err(invalid());
                    }
                }
            }
            Self::Event { target, .. }
                if target.stream_ref
                    != (CommitStreamRef::RealmControl {
                        realm_id: actor.realm_id.clone(),
                    }) =>
            {
                return Err(invalid());
            }
            _ => {}
        }
        Ok(())
    }
}

impl RealmActorMaterialOutcome {
    pub fn validate(&self) -> Result<()> {
        self.actor_id.validate()?;
        self.requester_actor_id.validate()?;
        if self
            .actor_id
            .as_realm_actor_id()
            .is_none_or(|actor| actor.realm_id != self.realm_id)
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > chrono::TimeDelta::seconds(60)
            || self.signature.context != DetachedSignatureContext::RealmActorMaterial
            || self.signature.created_at != self.issued_at
            || arkret_canonical::canonical_json_bytes(self)?.len() > 4_194_304
        {
            return Err(invalid());
        }
        let stream = CommitStreamRef::RealmControl {
            realm_id: self.realm_id.clone(),
        };
        if self
            .control_stream_head
            .as_ref()
            .is_some_and(|head| head.stream_ref != stream)
        {
            return Err(invalid());
        }
        match (&self.purpose, &self.result) {
            (RealmActorMaterialPurpose::Current, RealmActorMaterialResult::Current { entries }) => {
                if self.control_stream_head.is_none() || !(1..=16).contains(&entries.len()) {
                    return Err(invalid());
                }
                let mut seen = std::collections::BTreeSet::new();
                for entry in entries {
                    let selector = match entry {
                        RealmActorMaterialCurrentEntry::Present {
                            row:
                                TypedCurrentRow::Value {
                                    selector,
                                    source_stream_ref,
                                    revision,
                                    ..
                                },
                            source_ref,
                        } => {
                            if source_ref.stream_ref != *source_stream_ref
                                || source_ref.commit_id != revision.commit_id
                                || source_ref.stream_position != revision.stream_position
                                || source_stream_ref != &stream
                                || self.control_stream_head.as_ref().is_none_or(|head| {
                                    revision.stream_position > head.stream_position
                                        || (revision.stream_position == head.stream_position
                                            && revision.commit_id != head.commit_id)
                                })
                            {
                                return Err(invalid());
                            }
                            selector
                        }
                        RealmActorMaterialCurrentEntry::NeverWritten { selector } => {
                            if !matches!(
                                selector,
                                CurrentSelector::RealmActorDeviceAuthorization { .. }
                                    | CurrentSelector::RealmActorDeviceRevocationProposals { .. }
                                    | CurrentSelector::RealmActorProfile { .. }
                            ) {
                                return Err(invalid());
                            }
                            selector
                        }
                    };
                    if realm_actor_selector_subject(selector) != Some(&self.actor_id)
                        || !seen.insert(arkret_canonical::canonical_json_bytes(selector)?)
                    {
                        return Err(invalid());
                    }
                }
            }
            (
                RealmActorMaterialPurpose::Event,
                RealmActorMaterialResult::Event { event, commit, .. },
            ) => {
                if self.control_stream_head.is_none()
                    || commit.stream_ref != stream
                    || commit.event_ref != event.event_id
                    || event.realm_id != self.realm_id
                    || event.scope_ref
                        != (arkret_wire::ScopeRef::RealmControl {
                            realm_id: self.realm_id.clone(),
                        })
                    || self.control_stream_head.as_ref().is_none_or(|head| {
                        commit.stream_position > head.stream_position
                            || (commit.stream_position == head.stream_position
                                && commit.commit_id != head.commit_id)
                    })
                {
                    return Err(invalid());
                }
            }
            (
                RealmActorMaterialPurpose::Outcome,
                RealmActorMaterialResult::Outcome { outcome, .. },
            ) => {
                if let RealmActorOperationOutcome::DeviceRevoke {
                    proposal_ref,
                    authorization_ref,
                    authorized_generation_ref,
                    state,
                    decided_at,
                    ..
                } = outcome
                {
                    if (*state == RealmActorDeviceRevokeState::Pending) != decided_at.is_none()
                        || *authorized_generation_ref == 0
                        || proposal_ref.stream_ref != stream
                        || authorization_ref.stream_ref != stream
                        || authorization_ref.stream_position >= proposal_ref.stream_position
                        || authorization_ref.event_id == proposal_ref.event_id
                        || authorization_ref.commit_id == proposal_ref.commit_id
                        || decided_at.is_some_and(|at| at > self.issued_at)
                        || self.control_stream_head.as_ref().is_none_or(|head| {
                            proposal_ref.stream_position > head.stream_position
                                || (proposal_ref.stream_position == head.stream_position
                                    && proposal_ref.commit_id != head.commit_id)
                        })
                    {
                        return Err(invalid());
                    }
                }
                if let RealmActorOperationOutcome::Recovery {
                    state,
                    terminal_ref,
                    ..
                } = outcome
                {
                    if (*state == RealmActorRecoveryState::Pending) != terminal_ref.is_none() {
                        return Err(invalid());
                    }
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod revoke_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn device_revoke_requires_nullable_terminal_field_and_canonical_time() {
        let token = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB";
        let source = json!({
            "event_id":format!("ak:event:{token}"),
            "commit_id":format!("ak:realm_commit:{token}"),
            "stream_ref":{"kind":"realm_control","realm_id":format!("ak:realm:{token}")},
            "stream_position":0
        });
        let value = json!({"status":"device_revoke","proposal_ref":source,
            "device_id":"ak:device:00000000-0000-7000-8000-000000000001",
            "authorization_ref":source,"authorized_generation_ref":1,"state":"pending","decided_at":null});
        let parsed: RealmActorOperationOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
        for field in [
            "decided_at",
            "authorization_ref",
            "authorized_generation_ref",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<RealmActorOperationOutcome>(missing).is_err());
        }
        for timestamp in ["2026-10-20T00:00:00Z", "2026-10-20T00:00:00.000+00:00"] {
            let mut invalid = value.clone();
            invalid["state"] = json!("accepted");
            invalid["decided_at"] = json!(timestamp);
            assert!(serde_json::from_value::<RealmActorOperationOutcome>(invalid).is_err());
        }
        let mut terminal = value;
        terminal["state"] = json!("accepted");
        terminal["decided_at"] = json!("2026-10-20T00:00:00.000Z");
        let parsed: RealmActorOperationOutcome = serde_json::from_value(terminal.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), terminal);
    }
}

impl RealmActorMaterialOutcome {
    pub fn validate_for_request(
        &self,
        request: &RealmActorMaterialRequest,
        requester: &ActorId,
        now: DateTime<Utc>,
    ) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if &self.actor_id != request.actor_id()
            || self.request_nonce != request.request_nonce()
            || &self.requester_actor_id != requester
            || self.request_digest.as_str() != arkret_canonical::canonical_sha256(request)?
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(invalid());
        }
        match (request, &self.result) {
            (
                RealmActorMaterialRequest::Current { selectors, .. },
                RealmActorMaterialResult::Current { entries },
            ) => {
                if selectors.len() != entries.len()
                    || selectors.iter().zip(entries).any(|(requested, returned)| {
                        let actual = match returned {
                            RealmActorMaterialCurrentEntry::Present {
                                row: TypedCurrentRow::Value { selector, .. },
                                ..
                            }
                            | RealmActorMaterialCurrentEntry::NeverWritten { selector } => selector,
                        };
                        requested != actual
                    })
                {
                    return Err(invalid());
                }
            }
            (
                RealmActorMaterialRequest::Event { target, .. },
                RealmActorMaterialResult::Event { event, commit, .. },
            ) => {
                if target.event_id != event.event_id
                    || target.commit_id != commit.commit_id
                    || target.stream_ref != commit.stream_ref
                    || target.stream_position != commit.stream_position
                {
                    return Err(invalid());
                }
                let subject = match event.kind {
                    arkret_wire::EventKind::RealmActorCreate => event.payload.get("actor_id"),
                    arkret_wire::EventKind::RealmActorStatusSet
                    | arkret_wire::EventKind::RealmActorRecoverySet
                    | arkret_wire::EventKind::RealmActorRecoveryBegin
                    | arkret_wire::EventKind::RealmActorControlReset => {
                        event.payload.get("target_actor_id")
                    }
                    _ => None,
                };
                if let Some(subject) = subject {
                    if subject != &serde_json::to_value(&self.actor_id)? {
                        return Err(invalid());
                    }
                } else if event.actor_id != self.actor_id {
                    return Err(invalid());
                }
            }
            (
                RealmActorMaterialRequest::Outcome {
                    target_request_digest,
                    ..
                },
                RealmActorMaterialResult::Outcome {
                    target_request_digest: returned,
                    ..
                },
            ) if target_request_digest == returned => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

/// Check that a private selector's retained writer can actually produce that
/// selector. Cryptographic acceptance and the exact coordinate are verified
/// separately; another valid Event must never repair a missing current source.
pub fn validate_realm_actor_current_writer(
    selector: &CurrentSelector,
    event: &Event,
) -> Result<()> {
    use arkret_wire::{EventKind as K, RealmActorStatusGate, ScopeRef};
    let actor = realm_actor_selector_subject(selector).ok_or_else(invalid)?;
    let subject = actor.as_realm_actor_id().ok_or_else(invalid)?;
    let target = if event.kind == K::RealmActorCreate {
        event.payload.get("actor_id")
    } else {
        event.payload.get("target_actor_id")
    };
    if event.realm_id != subject.realm_id
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: subject.realm_id.clone(),
            })
        || target.map_or(event.actor_id != *actor, |value| {
            value != &serde_json::json!(actor)
        })
    {
        return Err(invalid());
    }
    let creates = event.kind == K::RealmActorCreate;
    let writes = match selector {
        CurrentSelector::RealmActorIdentity { .. } => creates,
        CurrentSelector::RealmActorControl { .. } => {
            creates
                || matches!(
                    event.kind,
                    K::RealmActorControlUpdate
                        | K::RealmActorManagerChange
                        | K::RealmActorControlReset
                )
        }
        CurrentSelector::RealmActorManager { .. } => {
            creates || event.kind == K::RealmActorManagerChange
        }
        CurrentSelector::RealmActorStatus { gate, .. } => {
            creates
                || (event.kind == K::RealmActorRecoveryBegin
                    && *gate == RealmActorStatusGate::Owner)
                || (event.kind == K::RealmActorStatusSet
                    && event.payload.get("gate") == Some(&serde_json::json!(gate)))
        }
        CurrentSelector::RealmActorDeviceGeneration { .. } => {
            creates
                || matches!(
                    event.kind,
                    K::RealmActorRecoveryBegin
                        | K::RealmActorDevicesReset
                        | K::RealmActorManagerChange
                )
        }
        CurrentSelector::RealmActorRecovery { .. } => {
            creates
                || matches!(
                    event.kind,
                    K::RealmActorRecoverySet
                        | K::RealmActorRecoveryBegin
                        | K::RealmActorControlReset
                )
                || (event.kind == K::RealmActorStatusSet
                    && event
                        .payload
                        .get("state")
                        .and_then(serde_json::Value::as_str)
                        == Some("retired"))
        }
        CurrentSelector::RealmActorDeviceAuthorization { device_id, .. } => {
            event.kind == K::DeviceAuthorize
                && event.payload.get("device_id") == Some(&serde_json::json!(device_id))
        }
        CurrentSelector::RealmActorDeviceRevocationProposals { device_id, .. } => {
            event.kind == K::DeviceRevoke
                && event.payload.get("device_id") == Some(&serde_json::json!(device_id))
        }
        CurrentSelector::RealmActorProfile { .. } => {
            matches!(event.kind, K::ProfileCreate | K::ProfileUpdate)
        }
        _ => false,
    };
    if !writes {
        return Err(invalid());
    }
    Ok(())
}
