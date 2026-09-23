//! Endpoint-specific authority-commit carriers.
//!
//! `/_arkret/self/events` and `/_arkret/peer/events` deliberately have
//! different closed unions.  The ordinary Event/MLS shapes remain owned by
//! `arkret-wire`; this module adds the registered aggregate and replication
//! branches without inventing a generic federation envelope.

use arkret_schema::{
    RealmBootstrapPresence, RealmBootstrapProfile, realm_bootstrap_profile_descriptor,
};
use arkret_wire::{
    ActorId, CommitStreamRef, DidCoreId, DidUrl, EventAdmissionSubmission, EventId, EventKind,
    MembershipCompensationAction, MembershipCompensationDelegationRef, MlsCommitSubmission,
    RealmCommit, RealmCommitId, RealmId, Result, UuidV7, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence;

crate::string_marker!(
    AuthorityForwardBranch,
    AuthorityForward,
    "authority_forward"
);
crate::string_marker!(
    CommittedReplicationBranch,
    CommittedReplication,
    "committed_replication"
);
crate::string_marker!(
    RegisteredAtomicUnitBranch,
    RegisteredAtomicUnit,
    "registered_atomic_unit"
);
crate::string_marker!(PerItemProcessing, PerItem, "per_item");
crate::string_marker!(
    DependencyMissingProblemType,
    DependencyMissing,
    "https://arkret.org/problems/dependency_missing"
);
crate::string_marker!(
    DependencyMissingProblemTitle,
    DependencyMissing,
    "Dependency missing"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSignature {
    pub verification_method: DidUrl,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEventSubmission {
    pub event_submission: EventAdmissionSubmission,
    pub source_commit: RealmCommit,
}

impl CommittedEventSubmission {
    pub fn validate(&self) -> Result<()> {
        self.event_submission.validate()?;
        self.source_commit.validate_shape()?;
        let event = &self.event_submission.event;
        let expected_stream =
            CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))?;
        if self.source_commit.event_ref != event.event_id
            || self.source_commit.realm_id != event.realm_id
            || self.source_commit.stream_ref != expected_stream
        {
            return Err(WireError::Protocol(
                "committed_event_submission source_commit must bind the exact submitted Event"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicationRecipientWitness {
    pub realm_id: RealmId,
    pub member_id: ActorId,
    pub membership_event_ref: EventId,
    pub recipient_service_id: DidCoreId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicatedCommittedEventSubmission {
    pub committed_event: CommittedEventSubmission,
    pub recipient_witnesses: Vec<ReplicationRecipientWitness>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrdinaryRealmBootstrapUnitKind {
    #[serde(rename = "ordinary_realm_bootstrap")]
    OrdinaryRealmBootstrap,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdinaryRealmBootstrapUnitSubmission {
    pub unit_kind: OrdinaryRealmBootstrapUnitKind,
    pub idempotency_key: UuidV7,
    pub events: Vec<EventAdmissionSubmission>,
}

impl OrdinaryRealmBootstrapUnitSubmission {
    pub fn validate(&self) -> Result<()> {
        let slots =
            realm_bootstrap_profile_descriptor(RealmBootstrapProfile::OrdinaryCollaboration)
                .ordered_slots;
        let mut events = self.events.iter().peekable();
        let first = self.events.first().ok_or_else(|| {
            WireError::Protocol(
                "ordinary Realm bootstrap requires the complete registered unit".to_owned(),
            )
        })?;
        if first.event.realm_id != RealmId::from_event_id(&first.event.event_id) {
            return Err(WireError::Protocol(
                "ordinary Realm bootstrap Realm ID must derive from its genesis Event".to_owned(),
            ));
        }
        for slot in slots {
            if events
                .peek()
                .is_some_and(|event| event.event.kind.as_str() == slot.event_kind)
            {
                events.next();
            } else if slot.presence == RealmBootstrapPresence::Required {
                return Err(WireError::Protocol(
                    "ordinary Realm bootstrap Events must follow the registered required slot order"
                        .to_owned(),
                ));
            }
        }
        if events.next().is_some() {
            return Err(WireError::Protocol(
                "ordinary Realm bootstrap contains an unregistered or out-of-order Event"
                    .to_owned(),
            ));
        }
        for event in &self.events {
            event.validate()?;
            if event.event.realm_id != first.event.realm_id
                || event.event.actor_id != first.event.actor_id
            {
                return Err(WireError::Protocol(
                    "ordinary Realm bootstrap Events must bind one Realm and one initiating actor"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl ReplicatedCommittedEventSubmission {
    pub fn validate(&self) -> Result<()> {
        self.committed_event.validate()?;
        if self.recipient_witnesses.is_empty()
            || self.recipient_witnesses.len() > 100
            || !self
                .recipient_witnesses
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(WireError::Protocol(
                "recipient_witnesses must contain 1..=100 canonical sorted unique witnesses"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationFoundingUnitSubmission {
    pub unit_kind: DirectConversationFoundingUnitKind,
    pub idempotency_key: UuidV7,
    pub events: [EventAdmissionSubmission; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectConversationFoundingUnitKind {
    #[serde(rename = "direct_conversation_founding")]
    DirectConversationFounding,
}

impl DirectConversationFoundingUnitSubmission {
    pub fn validate(&self) -> Result<()> {
        validate_direct_conversation_event_order(&self.events)
    }
}

fn validate_direct_conversation_event_order(events: &[EventAdmissionSubmission; 4]) -> Result<()> {
    let expected = [
        EventKind::RealmCreate,
        EventKind::MemberState,
        EventKind::MemberState,
        EventKind::StrandCreate,
    ];
    for (submission, kind) in events.iter().zip(expected) {
        submission.validate()?;
        if submission.event.kind != kind {
            return Err(WireError::Protocol(
                "Direct Conversation founding Events must be realm.create, member.state, member.state, strand.create"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationFoundingFederationSubmission {
    pub unit_kind: DirectConversationFoundingUnitKind,
    pub committed_events: [CommittedEventSubmission; 4],
    pub founding_authority_evidence: DirectConversationFoundingAuthorityEvidence,
}

impl DirectConversationFoundingFederationSubmission {
    pub fn validate(&self) -> Result<()> {
        let events = self
            .committed_events
            .each_ref()
            .map(|item| &item.event_submission);
        validate_direct_conversation_event_order(&events.map(Clone::clone))?;
        for item in &self.committed_events {
            item.validate()?;
        }
        self.founding_authority_evidence.validate()?;
        if !self.committed_events.windows(2).all(|pair| {
            pair[1].source_commit.stream_position
                == pair[0].source_commit.stream_position.saturating_add(1)
                && pair[1].source_commit.previous_commit_ref
                    == Some(pair[0].source_commit.commit_id.clone())
        }) {
            return Err(WireError::Protocol(
                "Direct Conversation source commits must be one consecutive chain".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationDelegationCore {
    pub admission_id: Uuid,
    pub join_event_ref: EventId,
    pub join_commit_ref: RealmCommitId,
    pub subject_id: ActorId,
    pub executor_id: ActorId,
    pub executor_service_id: DidCoreId,
    pub verification_method: DidUrl,
    pub resource_realm_id: RealmId,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub deadline: DateTime<Utc>,
    pub action: MembershipCompensationAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationDelegation {
    pub delegation_id: MembershipCompensationDelegationRef,
    pub core: MembershipCompensationDelegationCore,
    pub proof: OperationSignature,
}

impl MembershipCompensationDelegation {
    pub fn validate_content_address(&self) -> Result<()> {
        let bytes = arkret_wire::canonical::canonical_json_bytes(&self.core)?;
        let digest = arkret_wire::canonical::sha256_digest(bytes);
        let suffix = digest.strip_prefix("sha256:").unwrap_or_default();
        if self.delegation_id.as_str()
            != format!("ak:membership_compensation_delegation:sha256:{suffix}")
        {
            return Err(WireError::Protocol(
                "membership compensation delegation_id does not address core".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipCompensationTerminalStatus {
    #[serde(rename = "join_terminal_failed")]
    JoinTerminalFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationTerminalCertificate {
    pub admission_id: Uuid,
    pub delegation_id: MembershipCompensationDelegationRef,
    pub status: MembershipCompensationTerminalStatus,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub certified_at: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub proof: OperationSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationSingleUseBinding {
    pub admission_id: Uuid,
    pub delegation_id: MembershipCompensationDelegationRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationEvidence {
    pub delegation: MembershipCompensationDelegation,
    pub terminal_certificate: MembershipCompensationTerminalCertificate,
    pub single_use_binding: MembershipCompensationSingleUseBinding,
}

impl MembershipCompensationEvidence {
    pub fn validate(&self) -> Result<()> {
        self.delegation.validate_content_address()?;
        let admission_id = self.delegation.core.admission_id;
        let delegation_id = &self.delegation.delegation_id;
        if self.terminal_certificate.admission_id != admission_id
            || &self.terminal_certificate.delegation_id != delegation_id
            || self.single_use_binding.admission_id != admission_id
            || &self.single_use_binding.delegation_id != delegation_id
        {
            return Err(WireError::Protocol(
                "membership compensation evidence bindings disagree".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationUnitSubmission {
    pub unit_kind: MembershipCompensationUnitKind,
    pub event_submission: EventAdmissionSubmission,
    pub membership_compensation_evidence: MembershipCompensationEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipCompensationUnitKind {
    #[serde(rename = "membership_compensation")]
    MembershipCompensation,
}

impl MembershipCompensationUnitSubmission {
    pub fn validate(&self) -> Result<()> {
        self.event_submission.validate()?;
        self.membership_compensation_evidence.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationFederationSubmission {
    pub unit_kind: MembershipCompensationUnitKind,
    pub committed_event: CommittedEventSubmission,
    pub membership_compensation_evidence: MembershipCompensationEvidence,
}

impl MembershipCompensationFederationSubmission {
    pub fn validate(&self) -> Result<()> {
        self.committed_event.validate()?;
        self.membership_compensation_evidence.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SelfAuthoritySubmitRequest {
    Event(EventAdmissionSubmission),
    MlsCommit(MlsCommitSubmission),
    OrdinaryRealmBootstrap(OrdinaryRealmBootstrapUnitSubmission),
    DirectConversationFounding(DirectConversationFoundingUnitSubmission),
    MembershipCompensation(MembershipCompensationUnitSubmission),
}

impl SelfAuthoritySubmitRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Event(value) => value.validate(),
            Self::MlsCommit(value) => value.validate(),
            Self::OrdinaryRealmBootstrap(value) => value.validate(),
            Self::DirectConversationFounding(value) => value.validate(),
            Self::MembershipCompensation(value) => value.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerRegisteredAtomicUnit {
    DirectConversationFounding(DirectConversationFoundingFederationSubmission),
    MembershipCompensation(MembershipCompensationFederationSubmission),
}

impl PeerRegisteredAtomicUnit {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::DirectConversationFounding(value) => value.validate(),
            Self::MembershipCompensation(value) => value.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthorityForwardEventRequest {
    pub branch: AuthorityForwardBranch,
    pub event_submission: EventAdmissionSubmission,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthorityForwardMlsRequest {
    pub branch: AuthorityForwardBranch,
    pub mls_submission: MlsCommitSubmission,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCommittedReplicationRequest {
    pub branch: CommittedReplicationBranch,
    pub processing: PerItemProcessing,
    pub submissions: Vec<ReplicatedCommittedEventSubmission>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRegisteredAtomicUnitRequest {
    pub branch: RegisteredAtomicUnitBranch,
    pub unit: PeerRegisteredAtomicUnit,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerAuthoritySubmitRequest {
    AuthorityForwardEvent(PeerAuthorityForwardEventRequest),
    AuthorityForwardMls(PeerAuthorityForwardMlsRequest),
    CommittedReplication(PeerCommittedReplicationRequest),
    RegisteredAtomicUnit(PeerRegisteredAtomicUnitRequest),
}

impl PeerAuthoritySubmitRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::AuthorityForwardEvent(value) => value.event_submission.validate(),
            Self::AuthorityForwardMls(value) => value.mls_submission.validate(),
            Self::CommittedReplication(value) => {
                if value.submissions.is_empty() || value.submissions.len() > 100 {
                    return Err(WireError::Protocol(
                        "committed replication requires 1..=100 submissions".to_owned(),
                    ));
                }
                for submission in &value.submissions {
                    submission.validate()?;
                }
                Ok(())
            }
            Self::RegisteredAtomicUnit(value) => value.unit.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateAcceptanceStatus {
    Committed,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdinaryRealmBootstrapAcceptanceOutcome {
    pub unit_kind: OrdinaryRealmBootstrapUnitKind,
    pub status: AggregateAcceptanceStatus,
    pub commits: Vec<RealmCommit>,
}

impl OrdinaryRealmBootstrapAcceptanceOutcome {
    pub fn validate(&self) -> Result<()> {
        if !(7..=9).contains(&self.commits.len()) {
            return Err(WireError::Protocol(
                "ordinary Realm bootstrap outcome requires 7..=9 RealmCommits".to_owned(),
            ));
        }
        let first = &self.commits[0];
        if first.stream_position != 0
            || !matches!(
                &first.stream_ref,
                CommitStreamRef::Realm { realm_id } if realm_id == &first.realm_id
            )
        {
            return Err(WireError::Protocol(
                "ordinary Realm bootstrap must begin at position zero in its Realm stream"
                    .to_owned(),
            ));
        }
        for commit in &self.commits {
            commit.validate_shape()?;
            if commit.realm_id != first.realm_id || commit.stream_ref != first.stream_ref {
                return Err(WireError::Protocol(
                    "ordinary Realm bootstrap RealmCommits must share one Realm stream".to_owned(),
                ));
            }
        }
        if !self.commits.windows(2).all(|pair| {
            pair[1].stream_position == pair[0].stream_position.saturating_add(1)
                && pair[1].previous_commit_ref == Some(pair[0].commit_id.clone())
        }) {
            return Err(WireError::Protocol(
                "ordinary Realm bootstrap RealmCommits must be consecutive".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationFoundingAcceptanceOutcome {
    pub unit_kind: DirectConversationFoundingUnitKind,
    pub status: AggregateAcceptanceStatus,
    pub commits: [RealmCommit; 4],
}

impl DirectConversationFoundingAcceptanceOutcome {
    pub fn validate(&self) -> Result<()> {
        for commit in &self.commits {
            commit.validate_shape()?;
        }
        if !self.commits.windows(2).all(|pair| {
            pair[1].stream_position == pair[0].stream_position.saturating_add(1)
                && pair[1].previous_commit_ref == Some(pair[0].commit_id.clone())
        }) {
            return Err(WireError::Protocol(
                "Direct Conversation outcome commits must be one consecutive chain".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCompensationAcceptanceOutcome {
    pub unit_kind: MembershipCompensationUnitKind,
    pub status: AggregateAcceptanceStatus,
    pub commit: RealmCommit,
}

impl MembershipCompensationAcceptanceOutcome {
    pub fn validate(&self) -> Result<()> {
        self.commit.validate_shape()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SelfAuthoritySubmitOutcome {
    Ordinary(arkret_wire::AuthoritySubmitOutcome),
    OrdinaryRealmBootstrap(OrdinaryRealmBootstrapAcceptanceOutcome),
    DirectConversationFounding(DirectConversationFoundingAcceptanceOutcome),
    MembershipCompensation(MembershipCompensationAcceptanceOutcome),
}

impl SelfAuthoritySubmitOutcome {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Ordinary(value) => value.validate_shape(),
            Self::OrdinaryRealmBootstrap(value) => value.validate(),
            Self::DirectConversationFounding(value) => value.validate(),
            Self::MembershipCompensation(value) => value.validate(),
        }
    }

    pub fn validate_for_request(&self, request: &SelfAuthoritySubmitRequest) -> Result<()> {
        request.validate()?;
        self.validate()?;
        let branch_matches = matches!(
            (request, self),
            (
                SelfAuthoritySubmitRequest::Event(_) | SelfAuthoritySubmitRequest::MlsCommit(_),
                Self::Ordinary(_)
            ) | (
                SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(_),
                Self::OrdinaryRealmBootstrap(_)
            ) | (
                SelfAuthoritySubmitRequest::DirectConversationFounding(_),
                Self::DirectConversationFounding(_)
            ) | (
                SelfAuthoritySubmitRequest::MembershipCompensation(_),
                Self::MembershipCompensation(_)
            )
        );
        if branch_matches {
            if let (
                SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(request),
                Self::OrdinaryRealmBootstrap(outcome),
            ) = (request, self)
            {
                if request.events.len() != outcome.commits.len()
                    || !request
                        .events
                        .iter()
                        .zip(&outcome.commits)
                        .all(|(event, commit)| event.event.event_id == commit.event_ref)
                {
                    return Err(WireError::Protocol(
                        "ordinary Realm bootstrap outcome must commit each submitted Event in order"
                            .to_owned(),
                    ));
                }
            }
            Ok(())
        } else {
            Err(WireError::Protocol(
                "self submit response branch does not match request branch".to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerCommittedReplicationRecord {
    Stored {
        index: u8,
        committed_ref: arkret_wire::CommittedEventRef,
    },
    Duplicate {
        index: u8,
        committed_ref: arkret_wire::CommittedEventRef,
    },
    Rejected {
        index: u8,
        committed_ref: arkret_wire::CommittedEventRef,
        reason_code: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthorityForwardOutcome {
    pub branch: AuthorityForwardBranch,
    pub outcome: arkret_wire::AuthoritySubmitOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCommittedReplicationOutcome {
    pub branch: CommittedReplicationBranch,
    pub results: Vec<PeerCommittedReplicationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredAtomicUnitRejection {
    pub unit_kind: RegisteredAtomicUnitKind,
    pub status: RegisteredAtomicUnitRejectionStatus,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<DirectConversationFoundingMissingDependencyList>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisteredAtomicUnitKind {
    DirectConversationFounding,
    MembershipCompensation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisteredAtomicUnitRejectionStatus {
    #[serde(rename = "rejected")]
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerRegisteredAtomicUnitOutcomeValue {
    DirectConversationFounding(DirectConversationFoundingAcceptanceOutcome),
    MembershipCompensation(MembershipCompensationAcceptanceOutcome),
    Rejected(RegisteredAtomicUnitRejection),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRegisteredAtomicUnitOutcome {
    pub branch: RegisteredAtomicUnitBranch,
    pub outcome: PeerRegisteredAtomicUnitOutcomeValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerAuthoritySubmitOutcome {
    AuthorityForward(PeerAuthorityForwardOutcome),
    CommittedReplication(PeerCommittedReplicationOutcome),
    RegisteredAtomicUnit(PeerRegisteredAtomicUnitOutcome),
}

impl PeerAuthoritySubmitOutcome {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::AuthorityForward(value) => value.outcome.validate_shape(),
            Self::CommittedReplication(value) => {
                if value.results.is_empty() || value.results.len() > 100 {
                    return Err(WireError::Protocol(
                        "committed replication outcome requires 1..=100 results".to_owned(),
                    ));
                }
                for (expected_index, result) in value.results.iter().enumerate() {
                    let (index, reason_code) = match result {
                        PeerCommittedReplicationRecord::Stored { index, .. }
                        | PeerCommittedReplicationRecord::Duplicate { index, .. } => (*index, None),
                        PeerCommittedReplicationRecord::Rejected {
                            index, reason_code, ..
                        } => (*index, Some(reason_code.as_str())),
                    };
                    if usize::from(index) != expected_index {
                        return Err(WireError::Protocol(
                            "committed replication result indices must equal their array positions"
                                .to_owned(),
                        ));
                    }
                    if let Some(reason_code) = reason_code {
                        validate_reason_code(reason_code)?;
                    }
                }
                Ok(())
            }
            Self::RegisteredAtomicUnit(value) => match &value.outcome {
                PeerRegisteredAtomicUnitOutcomeValue::DirectConversationFounding(value) => {
                    value.validate()
                }
                PeerRegisteredAtomicUnitOutcomeValue::MembershipCompensation(value) => {
                    value.validate()
                }
                PeerRegisteredAtomicUnitOutcomeValue::Rejected(value) => {
                    validate_reason_code(&value.reason_code)?;
                    if let Some(details) = &value.details {
                        details.validate()?;
                    }
                    Ok(())
                }
            },
        }
    }

    pub fn validate_for_request(&self, request: &PeerAuthoritySubmitRequest) -> Result<()> {
        request.validate()?;
        self.validate()?;
        match (request, self) {
            (
                PeerAuthoritySubmitRequest::AuthorityForwardEvent(_)
                | PeerAuthoritySubmitRequest::AuthorityForwardMls(_),
                Self::AuthorityForward(_),
            ) => Ok(()),
            (
                PeerAuthoritySubmitRequest::CommittedReplication(request),
                Self::CommittedReplication(outcome),
            ) => {
                if request.submissions.len() != outcome.results.len() {
                    return Err(WireError::Protocol(
                        "replication outcome must contain one result per submission".to_owned(),
                    ));
                }
                for (submission, result) in request.submissions.iter().zip(&outcome.results) {
                    let committed_ref = match result {
                        PeerCommittedReplicationRecord::Stored { committed_ref, .. }
                        | PeerCommittedReplicationRecord::Duplicate { committed_ref, .. }
                        | PeerCommittedReplicationRecord::Rejected { committed_ref, .. } => {
                            committed_ref
                        }
                    };
                    let source = &submission.committed_event.source_commit;
                    if committed_ref.event_id != source.event_ref
                        || committed_ref.commit_id != source.commit_id
                        || committed_ref.stream_ref != source.stream_ref
                        || committed_ref.stream_position != source.stream_position
                    {
                        return Err(WireError::Protocol(
                            "replication result must name the exact same-order source commit"
                                .to_owned(),
                        ));
                    }
                }
                Ok(())
            }
            (
                PeerAuthoritySubmitRequest::RegisteredAtomicUnit(request),
                Self::RegisteredAtomicUnit(outcome),
            ) => {
                let request_kind = match request.unit {
                    PeerRegisteredAtomicUnit::DirectConversationFounding(_) => {
                        RegisteredAtomicUnitKind::DirectConversationFounding
                    }
                    PeerRegisteredAtomicUnit::MembershipCompensation(_) => {
                        RegisteredAtomicUnitKind::MembershipCompensation
                    }
                };
                let outcome_kind = match &outcome.outcome {
                    PeerRegisteredAtomicUnitOutcomeValue::DirectConversationFounding(_) => {
                        RegisteredAtomicUnitKind::DirectConversationFounding
                    }
                    PeerRegisteredAtomicUnitOutcomeValue::MembershipCompensation(_) => {
                        RegisteredAtomicUnitKind::MembershipCompensation
                    }
                    PeerRegisteredAtomicUnitOutcomeValue::Rejected(value) => value.unit_kind,
                };
                if request_kind == outcome_kind {
                    Ok(())
                } else {
                    Err(WireError::Protocol(
                        "registered unit outcome unit_kind does not match request".to_owned(),
                    ))
                }
            }
            _ => Err(WireError::Protocol(
                "peer submit response branch does not match request branch".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectConversationFoundingMissingDependency {
    CommittedEvent { event_id: EventId },
    RealmCommit { commit_id: RealmCommitId },
    ContactRoundEvidence { source_event_ref: EventId },
    AgentProvisionRef { source_event_ref: EventId },
    ServiceVerificationMethod { verification_method: DidUrl },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationFoundingMissingDependencyList {
    pub missing_dependencies: Vec<DirectConversationFoundingMissingDependency>,
}

impl DirectConversationFoundingMissingDependencyList {
    pub fn validate(&self) -> Result<()> {
        if self.missing_dependencies.is_empty()
            || self.missing_dependencies.len() > 16
            || !self
                .missing_dependencies
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(WireError::Protocol(
                "missing_dependencies must contain 1..=16 canonical sorted unique entries"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationFoundingDependencyMissingProblem {
    #[serde(rename = "type")]
    pub problem_type: DependencyMissingProblemType,
    pub title: DependencyMissingProblemTitle,
    pub status: u16,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    pub details: DirectConversationFoundingMissingDependencyList,
}

impl DirectConversationFoundingDependencyMissingProblem {
    pub fn validate(&self) -> Result<()> {
        if self.status != 409 || self.detail.is_empty() || self.detail.len() > 4096 {
            return Err(WireError::Protocol(
                "dependency_missing problem requires status 409 and a bounded non-empty detail"
                    .to_owned(),
            ));
        }
        if self
            .instance
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 512)
        {
            return Err(WireError::Protocol(
                "dependency_missing problem instance is outside its bounds".to_owned(),
            ));
        }
        self.details.validate()
    }
}

pub fn validate_reason_code(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(WireError::Protocol(
            "reason_code must match ^[a-z][a-z0-9_]{0,63}$".to_owned(),
        ))
    }
}
