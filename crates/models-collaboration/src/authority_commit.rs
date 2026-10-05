//! Endpoint-specific authority-commit carriers.
//!
//! `/_arkret/self/events` and `/_arkret/peer/events` deliberately have
//! different closed unions.  The ordinary Event/MLS shapes remain owned by
//! `arkret-wire`; this module adds the registered aggregate and replication
//! branches without inventing a generic federation envelope.

use arkret_models_identity::{AccountDeviceSignerEvidence, AgentProducerEvidence};
use arkret_schema::{
    RealmBootstrapPresence, RealmBootstrapProfile, realm_bootstrap_profile_descriptor,
};
use arkret_wire::{
    ActorId, CommitStreamRef, DidCoreId, DidUrl, ErrorCode, Event, EventAdmissionSubmission,
    EventId, EventKind, HumanDeviceProducer, MembershipCompensationAction,
    MembershipCompensationDelegationRef, MlsCommitSubmission, MlsWelcomeDelivery, RealmCommit,
    RealmCommitId, RealmId, Result, UuidV7, WireError,
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
}

impl CommittedEventSubmission {
    /// Build a member-Station replica from an accepted source submission.
    /// Approval evidence stays in the governance Station's private audit;
    /// the exact canonical Event and source Commit are the replica proof.
    #[must_use]
    pub fn from_source_submission(
        source: &EventAdmissionSubmission,
        source_commit: RealmCommit,
        genesis_event_ref: Option<EventId>,
        welcomes: Option<Vec<MlsWelcomeDelivery>>,
    ) -> Self {
        Self {
            event_submission: EventAdmissionSubmission::new(source.event.clone()),
            source_commit,
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

/// Enforce the Event-determined presence of `producer_device_evidence`.
///
/// The member is not optional in the protocol sense: it MUST be present
/// exactly when the Event's actual signer is a human Account device
/// ([`Event::human_device_producer`]) and MUST be absent otherwise. A missing
/// or superfluous member is a `schema_violation`. Returns the human-device
/// producer that the carried evidence has to be verified against.
pub fn validate_producer_device_evidence_presence(
    event: &Event,
    producer_device_evidence: Option<&AccountDeviceSignerEvidence>,
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
    pub producer_device_evidence: Option<AccountDeviceSignerEvidence>,
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
        producer_device_evidence: Option<AccountDeviceSignerEvidence>,
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
    pub producer_device_evidence: Option<AccountDeviceSignerEvidence>,
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
        producer_device_evidence: Option<AccountDeviceSignerEvidence>,
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
