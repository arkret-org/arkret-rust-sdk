//! Endpoint-specific authority-commit carriers.
//!
//! `/_arkret/self/events` and `/_arkret/peer/events` deliberately have
//! different closed unions.  The ordinary Event/MLS shapes remain owned by
//! `arkret-wire`; this module adds the registered aggregate and replication
//! branches without inventing a generic federation envelope.

use arkret_models_identity::{
    AgentProducerEvidence, ForwardAccountDeviceSignerEvidence, ResolvedSignerKey,
};
use arkret_schema::{
    RealmBootstrapPresence, RealmBootstrapProfile, realm_bootstrap_profile_descriptor,
};
use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, DetachedSignatureContext, DidCoreId, DidUrl,
    ErrorCode, Event, EventAdmissionSubmission, EventId, EventKind, Hash, HumanDeviceProducer,
    MembershipCompensationAction, MembershipCompensationDelegationRef, MlsCommitSubmission,
    MlsWelcomeDelivery, RealmAuthorityBundle, RealmAuthorityHandoff, RealmCommit, RealmCommitId,
    RealmId, RealmStateSnapshot, Result, UuidV7, WireError, detached_signature_service_id,
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

/// Immutable authorization source, with no target Commit coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanHistoricalSignerFact {
    pub event_id: EventId,
    #[serde(deserialize_with = "deserialize_signing_account_actor")]
    pub actor: ActorId,
    pub device_id: arkret_wire::DeviceId,
    pub verification_method: DidUrl,
    pub key: ResolvedSignerKey,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

fn deserialize_signing_account_actor<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<ActorId, D::Error> {
    let actor = ActorId::deserialize(deserializer)?;
    if actor.as_account_id().is_none() {
        return Err(serde::de::Error::custom(
            "Human signer fact requires a complete Account actor",
        ));
    }
    Ok(actor)
}

impl HumanHistoricalSignerFact {
    pub fn digest(&self) -> Result<Hash> {
        self.key.validate()?;
        if self.actor.as_account_id().is_none() {
            return Err(WireError::Protocol(
                "Human signer fact requires an Account actor".into(),
            ));
        }
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }

    /// Byte-local source binding. This does not establish admission or Event Ed verification.
    pub fn validate_event_binding(
        &self,
        event: &Event,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.key.validate()?;
        event.verify_producer_proof_self_consistency(suite)?;
        let producer = event.human_device_producer()?.ok_or_else(|| {
            WireError::Protocol("Human signer fact is forbidden for non-device producers".into())
        })?;
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| WireError::Protocol("Human Event lacks producer proof".into()))?;
        if self.event_id != event.event_id
            || self.actor != *event.actual_signer()
            || self.actor.as_account_id() != Some(&producer.account_id)
            || self.device_id != producer.device_id
            || self.verification_method != proof.verification_method
        {
            return Err(WireError::Protocol(
                "Human signer fact does not bind the exact Event producer".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_commit_binding(
        &self,
        full: &arkret_wire::CommittedEventFullView,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        full.validate_shape()?;
        full.commit.verify_commit_id_matches_content()?;
        self.validate_event_binding(&full.event, suite)?;
        if full.commit.producer_signer_fact_digest.as_ref() != Some(&self.digest()?) {
            return Err(WireError::Protocol(
                "original governance Commit does not bind this exact Human signer fact".into(),
            ));
        }
        Ok(())
    }
}

/// Minimal Service installation and signing key frozen at acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHistoricalSignerFact {
    pub event_id: EventId,
    pub actor: ActorId,
    pub verification_method: DidUrl,
    pub key: arkret_models_identity::ServiceHistoricalSigningKey,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

impl ServiceHistoricalSignerFact {
    pub fn digest(&self) -> Result<Hash> {
        self.key.validate()?;
        if !matches!(&self.actor, ActorId::Service { .. }) {
            return Err(WireError::Protocol(
                "Service fact requires a Service actor".into(),
            ));
        }
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }
    pub fn validate_event_binding(
        &self,
        event: &Event,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.digest()?;
        event.verify_producer_proof_self_consistency(suite)?;
        if self.event_id != event.event_id
            || &self.actor != event.actual_signer()
            || event.applet_id.as_ref() != Some(&self.key.applet_id)
            || event
                .authorization_ref
                .as_ref()
                .map(|reference| reference.as_str())
                != Some(
                    arkret_wire::GrantId::from_event_id(&self.key.authorization_ref.event_id)
                        .as_str(),
                )
            || event.scope_ref != self.key.effective_scope
            || event
                .producer_proof
                .as_ref()
                .map(|p| &p.verification_method)
                != Some(&self.verification_method)
        {
            return Err(WireError::Protocol(
                "Service fact does not bind the exact Event producer and installation".into(),
            ));
        }
        Ok(())
    }
    pub fn validate_commit_binding(
        &self,
        full: &arkret_wire::CommittedEventFullView,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        full.validate_shape()?;
        full.commit.verify_commit_id_matches_content()?;
        self.validate_event_binding(&full.event, suite)?;
        if full.commit.producer_signer_fact_digest.as_ref() != Some(&self.digest()?)
            || self.accepted_at != full.commit.committed_at
        {
            return Err(WireError::Protocol(
                "original governance Commit does not bind this Service fact".into(),
            ));
        }
        for reference in [&self.key.registration_ref, &self.key.authorization_ref] {
            if reference.stream_ref.realm_id() != &full.commit.realm_id {
                return Err(WireError::Protocol(
                    "Service installation source belongs to another Realm".into(),
                ));
            }
            if reference.stream_ref == full.commit.stream_ref
                && reference.stream_position >= full.commit.stream_position
            {
                return Err(WireError::Protocol(
                    "Service installation source is not prior to its Event".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HistoricalProducerSignerFact {
    Human(HumanHistoricalSignerFact),
    Service(ServiceHistoricalSignerFact),
}
impl From<HumanHistoricalSignerFact> for HistoricalProducerSignerFact {
    fn from(fact: HumanHistoricalSignerFact) -> Self {
        Self::Human(fact)
    }
}
impl From<ServiceHistoricalSignerFact> for HistoricalProducerSignerFact {
    fn from(fact: ServiceHistoricalSignerFact) -> Self {
        Self::Service(fact)
    }
}
impl HistoricalProducerSignerFact {
    pub fn event_id(&self) -> &EventId {
        match self {
            Self::Human(f) => &f.event_id,
            Self::Service(f) => &f.event_id,
        }
    }
    pub fn as_human(&self) -> Option<&HumanHistoricalSignerFact> {
        if let Self::Human(f) = self {
            Some(f)
        } else {
            None
        }
    }
    pub fn as_human_mut(&mut self) -> Option<&mut HumanHistoricalSignerFact> {
        match self {
            Self::Human(fact) => Some(fact),
            Self::Service(_) => None,
        }
    }
    pub fn digest(&self) -> Result<Hash> {
        match self {
            Self::Human(f) => f.digest(),
            Self::Service(f) => f.digest(),
        }
    }
    pub fn validate_event_binding(
        &self,
        event: &Event,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        match self {
            Self::Human(f) => f.validate_event_binding(event, suite),
            Self::Service(f) => f.validate_event_binding(event, suite),
        }
    }
    pub fn validate_commit_binding(
        &self,
        full: &arkret_wire::CommittedEventFullView,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        match self {
            Self::Human(f) => f.validate_commit_binding(full, suite),
            Self::Service(f) => f.validate_commit_binding(full, suite),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalProducerSignerFactEntry {
    pub target: arkret_wire::CommittedEventRef,
    pub producer_signer_fact: HistoricalProducerSignerFact,
}

impl HistoricalProducerSignerFactEntry {
    pub fn validate_target(&self, full: &arkret_wire::CommittedEventFullView) -> Result<()> {
        if self.target.event_id != full.commit.event_ref
            || self.target.commit_id != full.commit.commit_id
            || self.target.stream_ref != full.commit.stream_ref
            || self.target.stream_position != full.commit.stream_position
        {
            return Err(WireError::Protocol(
                "Human signer inventory names another exact Commit".into(),
            ));
        }
        let suite = arkret_canonical::canonical::digest_suite(
            full.event.event_id.digest_suite_code().as_str(),
        )?;
        self.producer_signer_fact
            .validate_commit_binding(full, suite)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStreamScanOutcome {
    pub committed_events: Vec<arkret_wire::CommittedEventView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable_floor: Option<arkret_wire::ReadableFloor>,
    pub truncated: bool,
    pub producer_signer_facts: Vec<HistoricalProducerSignerFactEntry>,
}

impl PeerStreamScanOutcome {
    pub fn validate_for_request(&self, request: &arkret_wire::StreamScanRequest) -> Result<()> {
        arkret_wire::StreamScanOutcome {
            committed_events: self.committed_events.clone(),
            readable_floor: self.readable_floor.clone(),
            truncated: self.truncated,
        }
        .validate_for_request(request)?;
        if self.producer_signer_facts.len() > 1000 {
            return Err(WireError::Protocol(
                "peer scan signer fact limit exceeded".into(),
            ));
        }
        let mut facts = self.producer_signer_facts.iter();
        for row in &self.committed_events {
            if let arkret_wire::CommittedEventView::Full(full) = row
                && full.commit.producer_signer_fact_digest.is_some()
            {
                facts
                    .next()
                    .ok_or_else(|| {
                        WireError::Protocol("peer Full row lacks original Human signer fact".into())
                    })?
                    .validate_target(full)?;
            }
        }
        if facts.next().is_some() {
            return Err(WireError::Protocol(
                "peer scan contains extra or unordered Human signer facts".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEventSubmission {
    pub event_submission: EventAdmissionSubmission,
    pub source_commit: RealmCommit,
    /// Exact accepted Genesis of an MLS Commit's effective scope and group,
    /// frozen by governance and carried in the authenticated peer body.
    /// Required for MLS Commit replication and forbidden for every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_event_ref: Option<EventId>,
    /// Welcomes of an `ak.mls.commit` whose recipients the destination
    /// Station hosts, in submission order; absent for every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcomes: Option<Vec<MlsWelcomeDelivery>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub producer_signer_fact: Option<HistoricalProducerSignerFact>,
}

impl CommittedEventSubmission {
    /// Build a member-Station replica from an accepted source submission.
    /// Approval evidence stays in the governance Station's private audit;
    /// the exact canonical Event and source Commit are the replica proof.
    #[must_use]
    pub fn from_source_submission(
        source: &EventAdmissionSubmission,
        source_commit: RealmCommit,
        producer_signer_fact: Option<HistoricalProducerSignerFact>,
        genesis_event_ref: Option<EventId>,
        welcomes: Option<Vec<MlsWelcomeDelivery>>,
    ) -> Self {
        Self {
            event_submission: EventAdmissionSubmission::new(source.event.clone()),
            source_commit,
            producer_signer_fact,
            genesis_event_ref,
            welcomes,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.event_submission.validate()?;
        if self.event_submission.approval_signatures.is_some() {
            return Err(WireError::ProtocolCode {
                code: ErrorCode::SchemaViolation,
                message: "committed replication must omit private approval_signatures".to_owned(),
            });
        }
        self.source_commit.validate_shape()?;
        match (
            &self.source_commit.producer_signer_fact_digest,
            &self.producer_signer_fact,
        ) {
            (Some(_), Some(fact)) => {
                let full = arkret_wire::CommittedEventFullView {
                    event: self.event_submission.event.clone(),
                    commit: self.source_commit.clone(),
                };
                let suite = arkret_canonical::canonical::digest_suite(
                    full.event.event_id.digest_suite_code().as_str(),
                )?;
                fact.validate_commit_binding(&full, suite)?;
            }
            (None, None) => {}
            _ => {
                return Err(WireError::Protocol(
                    "replication signer fact and original Commit digest must be present together"
                        .into(),
                ));
            }
        }
        let event = &self.event_submission.event;
        if (event.kind == EventKind::MlsCommit) != self.genesis_event_ref.is_some() {
            return Err(WireError::ProtocolCode {
                code: ErrorCode::SchemaViolation,
                message:
                    "committed replication genesis_event_ref is required only for ak.mls.commit"
                        .to_owned(),
            });
        }
        if let Some(welcomes) = &self.welcomes {
            if event.kind != EventKind::MlsCommit {
                return Err(WireError::ProtocolCode {
                    code: ErrorCode::SchemaViolation,
                    message: "committed replication welcomes are allowed only for ak.mls.commit"
                        .to_owned(),
                });
            }
            if welcomes.is_empty() {
                return Err(WireError::ProtocolCode {
                    code: ErrorCode::SchemaViolation,
                    message: "committed replication welcomes must be omitted rather than empty"
                        .to_owned(),
                });
            }
            if !welcomes
                .windows(2)
                .all(|pair| pair[0].welcome_id < pair[1].welcome_id)
            {
                return Err(WireError::Protocol(
                    "replicated MLS Welcome deliveries must keep submission order and be unique"
                        .to_owned(),
                ));
            }
            for welcome in welcomes {
                welcome.validate_shape()?;
                if welcome.realm_id != event.realm_id
                    || welcome.effective_scope != event.scope_ref
                    || welcome.commit_event_ref != event.event_id
                {
                    return Err(WireError::Protocol(
                        "replicated MLS Welcome delivery must bind the exact replicated commit Event"
                            .to_owned(),
                    ));
                }
            }
        }
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
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
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
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
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

/// Enforce the Event-determined presence of `producer_device_evidence`.
///
/// The member is not optional in the protocol sense: it MUST be present
/// exactly when the Event's actual signer is a human Account device
/// ([`Event::human_device_producer`]) and MUST be absent otherwise. A missing
/// or superfluous member is a `schema_violation`. Returns the human-device
/// producer that the carried evidence has to be verified against.
pub fn validate_producer_device_evidence_presence(
    event: &Event,
    producer_device_evidence: Option<&ForwardAccountDeviceSignerEvidence>,
) -> Result<Option<HumanDeviceProducer>> {
    let producer = event.human_device_producer()?;
    match (&producer, producer_device_evidence) {
        (Some(_), Some(_)) | (None, None) => Ok(producer),
        (Some(_), None) => Err(WireError::ProtocolCode {
            code: ErrorCode::SchemaViolation,
            message: "authority_forward of a human-device producer requires producer_device_evidence"
                .to_owned(),
        }),
        (None, Some(_)) => Err(WireError::ProtocolCode {
            code: ErrorCode::SchemaViolation,
            message: "producer_device_evidence is forbidden unless the producer is a human Account device"
                .to_owned(),
        }),
    }
}

/// Account producers with a non-device method require the independently
/// verified Agent sibling; an unknown account method is never a service fallback.
pub fn validate_producer_agent_evidence_presence(
    event: &Event,
    evidence: Option<&AgentProducerEvidence>,
) -> Result<()> {
    let producer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    let required = producer.as_account_id().is_some() && event.human_device_producer()?.is_none();
    if required != evidence.is_some() {
        return Err(WireError::ProtocolCode {
            code: ErrorCode::SchemaViolation,
            message: "producer_agent_evidence is required exactly for an Agent runtime producer"
                .into(),
        });
    }
    Ok(())
}

/// Largest decoded size of one Genesis Blob: the bytes whose unpadded
/// base64url fills `MLS_GENESIS_MATERIAL_MAX_ENCODED_CHARS`. Two such Blobs
/// together are exactly the `ak.peer.mls.read.group_state_material.v1`
/// response bound, so the carrier has no aggregate bound of its own.
pub const MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES: usize = 4_194_304;
const MLS_GENESIS_MATERIAL_MAX_ENCODED_CHARS: usize = 5_592_406;

/// Raw epoch-0 public material of one forwarded `ak.mls.genesis`
/// (`authority-commit-operations.schema.json#/$defs/mls_genesis_material`).
/// The signed Genesis refs are the only digest carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGenesisMaterial {
    pub group_info_bytes_b64: String,
    pub ratchet_tree_bytes_b64: String,
}

impl MlsGenesisMaterial {
    #[must_use]
    pub fn from_bytes(group_info: &[u8], ratchet_tree: &[u8]) -> Self {
        Self {
            group_info_bytes_b64: arkret_wire::base64url::base64url_encode(group_info),
            ratchet_tree_bytes_b64: arkret_wire::base64url::base64url_encode(ratchet_tree),
        }
    }

    /// Decoded GroupInfo and ratchet_tree bytes after the shape checks; every
    /// failure is `schema_violation`.
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((
            decode_genesis_blob("group_info_bytes_b64", &self.group_info_bytes_b64)?,
            decode_genesis_blob("ratchet_tree_bytes_b64", &self.ratchet_tree_bytes_b64)?,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        self.decode().map(drop)
    }
}

fn decode_genesis_blob(field: &str, encoded: &str) -> Result<Vec<u8>> {
    let schema_violation = || WireError::ProtocolCode {
        code: ErrorCode::SchemaViolation,
        message: format!("mls_genesis_material.{field} must be canonical unpadded base64url"),
    };
    if encoded.is_empty() || encoded.len() > MLS_GENESIS_MATERIAL_MAX_ENCODED_CHARS {
        return Err(schema_violation());
    }
    let bytes =
        arkret_wire::base64url::base64url_decode(encoded).map_err(|_| schema_violation())?;
    if arkret_wire::base64url::base64url_encode(&bytes) != encoded {
        return Err(schema_violation());
    }
    Ok(bytes)
}

// Field order is byte-for-byte the authority_forward branch order of
// authority-commit-operations.schema.json#/$defs/peer_submit_request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthorityForwardEventRequest {
    pub branch: AuthorityForwardBranch,
    pub event_submission: EventAdmissionSubmission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_genesis_material: Option<MlsGenesisMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_device_evidence: Option<ForwardAccountDeviceSignerEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_agent_evidence: Option<AgentProducerEvidence>,
}

impl PeerAuthorityForwardEventRequest {
    pub fn new_agent(
        event_submission: EventAdmissionSubmission,
        mls_genesis_material: Option<MlsGenesisMaterial>,
        producer_agent_evidence: AgentProducerEvidence,
    ) -> Result<Self> {
        let request = Self {
            branch: AuthorityForwardBranch::AuthorityForward,
            event_submission,
            mls_genesis_material,
            producer_device_evidence: None,
            producer_agent_evidence: Some(producer_agent_evidence),
        };
        request.validate()?;
        Ok(request)
    }
    /// Build a validated forward. `mls_genesis_material` carries the two
    /// referenced Blobs of an `ak.mls.genesis` and is `None` for every other
    /// kind; `producer_device_evidence` is the freshly signed evidence for a
    /// human-device producer and `None` otherwise.
    pub fn new(
        event_submission: EventAdmissionSubmission,
        mls_genesis_material: Option<MlsGenesisMaterial>,
        producer_device_evidence: Option<ForwardAccountDeviceSignerEvidence>,
    ) -> Result<Self> {
        let request = Self {
            branch: AuthorityForwardBranch::AuthorityForward,
            event_submission,
            mls_genesis_material,
            producer_device_evidence,
            producer_agent_evidence: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        self.event_submission.validate()?;
        let genesis = self.event_submission.event.kind == EventKind::MlsGenesis;
        match (&self.mls_genesis_material, genesis) {
            (Some(material), true) => material.validate()?,
            (None, false) => {}
            (None, true) => {
                return Err(WireError::ProtocolCode {
                    code: ErrorCode::SchemaViolation,
                    message: "authority_forward of ak.mls.genesis requires mls_genesis_material"
                        .to_owned(),
                });
            }
            (Some(_), false) => {
                return Err(WireError::ProtocolCode {
                    code: ErrorCode::SchemaViolation,
                    message: "mls_genesis_material is forbidden unless the Event is ak.mls.genesis"
                        .to_owned(),
                });
            }
        }
        validate_producer_agent_evidence_presence(
            &self.event_submission.event,
            self.producer_agent_evidence.as_ref(),
        )?;
        self.human_device_producer().map(drop)
    }

    /// Human-device producer of the forwarded Event, after enforcing the
    /// presence rule for `producer_device_evidence`.
    pub fn human_device_producer(&self) -> Result<Option<HumanDeviceProducer>> {
        validate_producer_device_evidence_presence(
            &self.event_submission.event,
            self.producer_device_evidence.as_ref(),
        )
    }
}

// Field order is byte-for-byte the authority_forward branch order of
// authority-commit-operations.schema.json#/$defs/peer_submit_request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthorityForwardMlsRequest {
    pub branch: AuthorityForwardBranch,
    pub mls_submission: MlsCommitSubmission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_device_evidence: Option<ForwardAccountDeviceSignerEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_agent_evidence: Option<AgentProducerEvidence>,
}

impl PeerAuthorityForwardMlsRequest {
    pub fn new_agent(
        mls_submission: MlsCommitSubmission,
        producer_agent_evidence: AgentProducerEvidence,
    ) -> Result<Self> {
        let request = Self {
            branch: AuthorityForwardBranch::AuthorityForward,
            mls_submission,
            producer_device_evidence: None,
            producer_agent_evidence: Some(producer_agent_evidence),
        };
        request.validate()?;
        Ok(request)
    }
    /// Build a validated MLS forward. The Commit Event's producer decides
    /// whether `producer_device_evidence` is required or forbidden.
    pub fn new(
        mls_submission: MlsCommitSubmission,
        producer_device_evidence: Option<ForwardAccountDeviceSignerEvidence>,
    ) -> Result<Self> {
        let request = Self {
            branch: AuthorityForwardBranch::AuthorityForward,
            mls_submission,
            producer_device_evidence,
            producer_agent_evidence: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        self.mls_submission.validate()?;
        validate_producer_agent_evidence_presence(
            &self.mls_submission.commit_event,
            self.producer_agent_evidence.as_ref(),
        )?;
        self.human_device_producer().map(drop)
    }

    /// Human-device producer of the Commit Event, after enforcing the
    /// presence rule for `producer_device_evidence`.
    pub fn human_device_producer(&self) -> Result<Option<HumanDeviceProducer>> {
        validate_producer_device_evidence_presence(
            &self.mls_submission.commit_event,
            self.producer_device_evidence.as_ref(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCommittedReplicationRequest {
    pub branch: CommittedReplicationBranch,
    pub replications: Vec<CommittedEventSubmission>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRegisteredAtomicUnitRequest {
    pub branch: RegisteredAtomicUnitBranch,
    pub unit: PeerRegisteredAtomicUnit,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
pub enum PeerAuthoritySubmitRequest {
    AuthorityForwardEvent(PeerAuthorityForwardEventRequest),
    AuthorityForwardMls(PeerAuthorityForwardMlsRequest),
    CommittedReplication(PeerCommittedReplicationRequest),
    RegisteredAtomicUnit(PeerRegisteredAtomicUnitRequest),
}

impl PeerAuthoritySubmitRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::AuthorityForwardEvent(value) => value.validate(),
            Self::AuthorityForwardMls(value) => value.validate(),
            Self::CommittedReplication(value) => {
                if value.replications.is_empty() || value.replications.len() > 100 {
                    return Err(WireError::Protocol(
                        "committed replication requires 1..=100 replications".to_owned(),
                    ));
                }
                for replication in &value.replications {
                    replication.validate()?;
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
        let first = &self.commits[0];
        if first.stream_position != 0
            || first.previous_commit_ref.is_some()
            || self.commits.iter().any(|commit| {
                commit.realm_id != first.realm_id
                    || commit.stream_ref
                        != CommitStreamRef::Realm {
                            realm_id: first.realm_id.clone(),
                        }
            })
        {
            return Err(WireError::Protocol(
                "Direct Conversation founding must begin at zero in one Realm stream".to_owned(),
            ));
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
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
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
                SelfAuthoritySubmitRequest::DirectConversationFounding(request),
                Self::DirectConversationFounding(outcome),
            ) = (request, self)
            {
                for (submission, commit) in request.events.iter().zip(&outcome.commits) {
                    arkret_wire::CommittedEventFullView {
                        event: submission.event.clone(),
                        commit: commit.clone(),
                    }
                    .validate_shape()?;
                }
            }
            if let (
                SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(request),
                Self::OrdinaryRealmBootstrap(outcome),
            ) = (request, self)
                && (request.events.len() != outcome.commits.len()
                    || !request
                        .events
                        .iter()
                        .zip(&outcome.commits)
                        .all(|(event, commit)| event.event.event_id == commit.event_ref))
            {
                return Err(WireError::Protocol(
                    "ordinary Realm bootstrap outcome must commit each submitted Event in order"
                        .to_owned(),
                ));
            }
            Ok(())
        } else {
            Err(WireError::Protocol(
                "self submit response branch does not match request branch".to_owned(),
            ))
        }
    }
}

/// One same-order row of `replication_outcomes[]`; its array position is the
/// only link to the request replication, so no index or coordinates are echoed.
/// `Stored {}` / `Duplicate {}` are braced on purpose: serde ignores extra
/// members on internally tagged unit variants, so only struct variants keep
/// `deny_unknown_fields` closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerCommittedReplicationOutcomeRecord {
    Stored {},
    Duplicate {},
    Rejected { reason_code: String },
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
    pub replication_outcomes: Vec<PeerCommittedReplicationOutcomeRecord>,
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
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
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
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
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
                if value.replication_outcomes.is_empty() || value.replication_outcomes.len() > 100 {
                    return Err(WireError::Protocol(
                        "committed replication outcome requires 1..=100 replication_outcomes"
                            .to_owned(),
                    ));
                }
                for record in &value.replication_outcomes {
                    if let PeerCommittedReplicationOutcomeRecord::Rejected { reason_code } = record
                    {
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
                if request.replications.len() == outcome.replication_outcomes.len() {
                    Ok(())
                } else {
                    Err(WireError::Protocol(
                        "replication_outcomes must contain one same-order row per replication"
                            .to_owned(),
                    ))
                }
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHandoffRequest {
    pub handoff: RealmAuthorityHandoff,
    /// Private complete manifest. It is transferred only old-authority to
    /// new-authority and is never embedded in the public bundle.
    pub final_stream_heads: Vec<CommitStreamHead>,
    pub snapshot: RealmStateSnapshot,
    pub authority_bundle: RealmAuthorityBundle,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub historical_signer_facts: Option<Vec<HistoricalProducerSignerFactEntry>>,
}

impl AuthorityHandoffRequest {
    pub fn validate_shape(&self) -> Result<()> {
        self.handoff.validate_shape()?;
        let unsigned_snapshot = arkret_canonical::canonical::unsigned_value(
            &self.snapshot,
            &["snapshot_id", "signature"],
        )?;
        if self.snapshot.snapshot_id
            != arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
                &arkret_canonical::canonical_json_bytes(&unsigned_snapshot)?,
            ))
        {
            return Err(WireError::Protocol(
                "handoff snapshot content address mismatch".into(),
            ));
        }
        match (
            &self.handoff.historical_signer_facts_digest,
            &self.historical_signer_facts,
        ) {
            (Some(digest), Some(entries))
                if digest == &historical_signer_facts_digest(entries)? => {}
            (None, None) => {}
            _ => {
                return Err(WireError::Protocol(
                    "handoff inventory and original signed digest mismatch".into(),
                ));
            }
        }
        if self
            .historical_signer_facts
            .as_ref()
            .is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry.target.stream_ref.realm_id() != &self.handoff.realm_id)
            })
        {
            return Err(WireError::Protocol(
                "handoff signer inventory belongs to another Realm".into(),
            ));
        }
        self.authority_bundle.validate_shape()?;
        if self.final_stream_heads.is_empty()
            || !self
                .final_stream_heads
                .windows(2)
                .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
            || self
                .final_stream_heads
                .iter()
                .any(|head| head.stream_ref.realm_id() != &self.handoff.realm_id)
        {
            return Err(WireError::Protocol(
                "authority handoff final stream heads must be non-empty, sorted, unique, and same-Realm"
                    .to_owned(),
            ));
        }
        let heads_digest = Hash::new(arkret_canonical::canonical_sha256(
            &self.final_stream_heads,
        )?)?;
        let realm_stream_ref = CommitStreamRef::Realm {
            realm_id: self.handoff.realm_id.clone(),
        };
        let final_realm_head = self
            .final_stream_heads
            .iter()
            .find(|head| head.stream_ref == realm_stream_ref)
            .ok_or_else(|| {
                WireError::Protocol(
                    "authority handoff manifest must include the Realm stream head".to_owned(),
                )
            })?;
        if heads_digest != self.handoff.final_stream_heads_digest
            || final_realm_head.commit_id != self.handoff.change_commit_id
            || self.snapshot.snapshot_id != self.handoff.snapshot_ref
            || self.snapshot.realm_id != self.handoff.realm_id
            || self.snapshot.governance_generation != self.handoff.from_generation
            || self.snapshot.visible_stream_heads != self.final_stream_heads
            || self.snapshot.signature.context != DetachedSignatureContext::RealmSnapshot
            || detached_signature_service_id(&self.snapshot.signature)?
                != self.handoff.from_service_id
            || self.authority_bundle.realm_id != self.handoff.realm_id
            || self.authority_bundle.current_generation != self.handoff.to_generation
            || self.authority_bundle.current_service_id != self.handoff.to_service_id
            || self.authority_bundle.realm_stream_head != *final_realm_head
            || self
                .authority_bundle
                .authority_transitions
                .last()
                .map(|transition| &transition.handoff)
                != Some(&self.handoff)
            || self.authority_bundle.current_assertion.last_handoff_ref
                != Some(self.handoff.handoff_id.clone())
        {
            return Err(WireError::Protocol(
                "authority handoff manifest, snapshot, and current bundle binding mismatch"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Fixed-SHA256 inventory digest. Callers must independently prove the exact imported target set.
pub fn historical_signer_facts_digest(
    entries: &[HistoricalProducerSignerFactEntry],
) -> Result<Hash> {
    let sort_key = |entry: &HistoricalProducerSignerFactEntry| -> Result<_> {
        Ok((
            arkret_canonical::canonical_json_bytes(&entry.target.stream_ref)?,
            entry.target.stream_position,
            entry.target.event_id.as_str().as_bytes().to_vec(),
            entry.target.commit_id.as_str().as_bytes().to_vec(),
        ))
    };
    let mut previous = None;
    for entry in entries {
        entry.producer_signer_fact.digest()?;
        if &entry.target.event_id != entry.producer_signer_fact.event_id() {
            return Err(WireError::Protocol(
                "handoff signer inventory Event binding mismatch".into(),
            ));
        }
        let next = sort_key(entry)?;
        if previous.as_ref().is_some_and(|previous| previous >= &next) {
            return Err(WireError::Protocol(
                "handoff signer inventory must use canonical unique target order".into(),
            ));
        }
        previous = Some(next);
    }
    Ok(Hash::new(arkret_canonical::canonical_sha256(&entries)?)?)
}

impl AuthorityHandoffRequest {
    /// Compare the inventory against all imported digest-bearing Full originals, not a member
    /// floor.
    pub fn validate_imported_signer_facts(
        &self,
        imported: &[arkret_wire::CommittedEventFullView],
    ) -> Result<()> {
        self.validate_shape()?;
        for full in imported {
            full.validate_shape()?;
            let head = self
                .final_stream_heads
                .iter()
                .find(|head| head.stream_ref == full.commit.stream_ref)
                .ok_or_else(|| {
                    WireError::Protocol(
                        "imported original is outside the frozen handoff streams".into(),
                    )
                })?;
            if full.commit.realm_id != self.handoff.realm_id
                || full.commit.governance_generation > self.handoff.from_generation
                || full.commit.stream_position > head.stream_position
                || (full.commit.stream_position == head.stream_position
                    && full.commit.commit_id != head.commit_id)
            {
                return Err(WireError::Protocol(
                    "imported original is outside the exact frozen handoff cut".into(),
                ));
            }
        }
        validate_historical_signer_fact_inventory(
            self.historical_signer_facts.as_deref().unwrap_or(&[]),
            imported,
        )
    }
}

/// The canonical peer body excludes only the evidence that signs this digest.
pub fn authority_forward_body_digest<T: Serialize>(body: &T) -> Result<Hash> {
    let mut unsigned = serde_json::to_value(body)?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| WireError::Protocol("authority forward body must be an object".into()))?
        .remove("producer_device_evidence");
    Ok(Hash::new(arkret_canonical::canonical_sha256(&unsigned)?)?)
}

/// New admission is distinct from decoding an exact legacy accepted original.
pub fn validate_new_human_admission_fact(
    event: &Event,
    fact: Option<&HumanHistoricalSignerFact>,
    suite: arkret_canonical::DigestSuite,
) -> Result<()> {
    let source = fact.cloned().map(HistoricalProducerSignerFact::Human);
    validate_new_producer_admission_fact(event, source.as_ref(), suite)
}

pub fn validate_new_producer_admission_fact(
    event: &Event,
    fact: Option<&HistoricalProducerSignerFact>,
    suite: arkret_canonical::DigestSuite,
) -> Result<()> {
    match (event.human_device_producer()?, fact) {
        (Some(_), Some(HistoricalProducerSignerFact::Human(fact))) => {
            fact.validate_event_binding(event, suite)
        }
        (None, Some(HistoricalProducerSignerFact::Service(fact))) => {
            fact.validate_event_binding(event, suite)
        }
        (None, None) if event.applet_id.is_none() || !matches!(event.actual_signer(), ActorId::Service { .. }) => Ok(()),
        _ => Err(WireError::Protocol(
            "new ordinary admission requires the immutable fact of its actual Human or Applet Service producer"
                .into(),
        )),
    }
}

impl AuthorityHandoffRequest {
    pub fn validate_new_handoff(&self) -> Result<()> {
        if self.handoff.historical_signer_facts_digest.is_none()
            || self.historical_signer_facts.is_none()
        {
            return Err(WireError::Protocol("new authority handoff requires the complete signer inventory, including an empty inventory".into()));
        }
        self.validate_shape()
    }
}

/// Complete equality against all imported digest-bearing Full originals.
pub fn validate_historical_signer_fact_inventory(
    entries: &[HistoricalProducerSignerFactEntry],
    imported: &[arkret_wire::CommittedEventFullView],
) -> Result<()> {
    historical_signer_facts_digest(entries)?;
    let mut expected = imported
        .iter()
        .filter(|full| full.commit.producer_signer_fact_digest.is_some())
        .collect::<Vec<_>>();
    let mut keyed = expected
        .drain(..)
        .map(|full| {
            Ok((
                (
                    arkret_canonical::canonical_json_bytes(&full.commit.stream_ref)?,
                    full.commit.stream_position,
                    full.event.event_id.to_string(),
                    full.commit.commit_id.to_string(),
                ),
                full,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    expected = keyed.into_iter().map(|(_, full)| full).collect();
    if expected.len() != entries.len() {
        return Err(WireError::Protocol(
            "handoff signer inventory is not the complete imported Full target set".into(),
        ));
    }
    for (entry, full) in entries.iter().zip(expected) {
        entry.validate_target(full)?;
    }
    Ok(())
}

/// Native control Realms retain their own admission proof family even when a controller device
/// signs.
pub fn validate_new_human_admission_fact_for_purpose(
    event: &Event,
    purpose: crate::events_payloads::RealmPurpose,
    fact: Option<&HistoricalProducerSignerFact>,
    suite: arkret_canonical::DigestSuite,
) -> Result<()> {
    match purpose {
        crate::events_payloads::RealmPurpose::Collaboration
        | crate::events_payloads::RealmPurpose::DirectConversation => {
            validate_new_producer_admission_fact(event, fact, suite)
        }
        crate::events_payloads::RealmPurpose::PrincipalControl
        | crate::events_payloads::RealmPurpose::AgentControl
        | crate::events_payloads::RealmPurpose::AppletManagedControl => {
            if fact.is_some() {
                return Err(WireError::Protocol(
                    "native control Realm admission must not use ordinary Human signer facts"
                        .into(),
                ));
            }
            Ok(())
        }
    }
}
