//! Single-authority commit-log wire types.
//!
//! A Realm, each Circle, and each Sidecar own separate linear streams. There
//! is deliberately no Realm-global position or ordering across those streams.

use arkret_identifiers::{
    ActorProfileId, AppletId, CallId, CircleId, Did, DidCoreId, EventId, GrantId, Hash, InviteId,
    KeypackageClaimId, MessageId, MlsWelcomeDeliveryId, PolicyId, RealmAuthorityHandoffId,
    RealmCommitId, RealmId, RealmSnapshotId, SidecarId, SpaceId, StrandId,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    AccountId, AccountabilityScopeSet, ActorId, AgentKeyId, Base64UrlString, CapabilityActionId,
    DeviceId, DidUrl, Event, HistoryAccess, MimiRoomUri, Result, ScopeRef, WireError,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CommitStreamRef {
    Realm {
        realm_id: RealmId,
    },
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
    Sidecar {
        realm_id: RealmId,
        sidecar_id: SidecarId,
    },
}

impl CommitStreamRef {
    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Realm { realm_id }
            | Self::Circle { realm_id, .. }
            | Self::Sidecar { realm_id, .. } => realm_id,
        }
    }

    pub fn from_scope(scope: &ScopeRef, genesis_realm_id: Option<RealmId>) -> Result<Self> {
        match scope {
            ScopeRef::RealmGenesis => genesis_realm_id
                .map(|realm_id| Self::Realm { realm_id })
                .ok_or_else(|| {
                    WireError::Protocol(
                        "realm genesis stream derivation requires the derived realm_id".to_owned(),
                    )
                }),
            ScopeRef::Realm { realm_id } => Ok(Self::Realm {
                realm_id: realm_id.clone(),
            }),
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => Ok(Self::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            }),
            ScopeRef::Sidecar {
                realm_id,
                sidecar_id,
            } => Ok(Self::Sidecar {
                realm_id: realm_id.clone(),
                sidecar_id: sidecar_id.clone(),
            }),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetachedSignatureContext {
    #[serde(rename = "ak.realm_commit_signature.v1")]
    RealmCommit,
    #[serde(rename = "ak.realm_authority_handoff_old_signature.v1")]
    RealmAuthorityHandoffOld,
    #[serde(rename = "ak.realm_authority_handoff_new_acceptance_signature.v1")]
    RealmAuthorityHandoffNewAcceptance,
    #[serde(rename = "ak.realm_authority_current_assertion_signature.v1")]
    RealmAuthorityCurrentAssertion,
    #[serde(rename = "ak.realm_snapshot_signature.v1")]
    RealmSnapshot,
    #[serde(rename = "ak.mls_welcome_delivery_signature.v1")]
    MlsWelcomeDelivery,
}

impl DetachedSignatureContext {
    /// The wire string this context serializes to. It is also the domain
    /// separation label of the signature transcript, so a signature made for
    /// one context can never verify under another.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::RealmCommit => "ak.realm_commit_signature.v1",
            Self::RealmAuthorityHandoffOld => "ak.realm_authority_handoff_old_signature.v1",
            Self::RealmAuthorityHandoffNewAcceptance => {
                "ak.realm_authority_handoff_new_acceptance_signature.v1"
            }
            Self::RealmAuthorityCurrentAssertion => {
                "ak.realm_authority_current_assertion_signature.v1"
            }
            Self::RealmSnapshot => "ak.realm_snapshot_signature.v1",
            Self::MlsWelcomeDelivery => "ak.mls_welcome_delivery_signature.v1",
        }
    }

    /// Every context the closed enum admits, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::RealmCommit,
        Self::RealmAuthorityHandoffOld,
        Self::RealmAuthorityHandoffNewAcceptance,
        Self::RealmAuthorityCurrentAssertion,
        Self::RealmSnapshot,
        Self::MlsWelcomeDelivery,
    ];
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedObjectSignature {
    pub context: DetachedSignatureContext,
    pub signature_algorithm: DetachedSignatureAlgorithm,
    pub verification_method: DidUrl,
    pub signed_digest: Hash,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub sig: Base64UrlString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetachedSignatureAlgorithm {
    Ed25519,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmCommitAuthorityRef {
    GenesisOrChangeEvent(EventId),
    Handoff(RealmAuthorityHandoffId),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCommit {
    pub commit_id: RealmCommitId,
    pub realm_id: RealmId,
    pub stream_ref: CommitStreamRef,
    pub stream_position: u64,
    pub previous_commit_ref: Option<RealmCommitId>,
    pub event_ref: EventId,
    pub governance_generation: u64,
    pub authority_ref: RealmCommitAuthorityRef,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
    pub signature: DetachedObjectSignature,
}

impl RealmCommit {
    pub fn validate_shape(&self) -> Result<()> {
        if &self.realm_id != self.stream_ref.realm_id() {
            return Err(WireError::Protocol(
                "RealmCommit realm_id must equal stream_ref.realm_id".to_owned(),
            ));
        }
        if self.stream_position == 0 && self.previous_commit_ref.is_some() {
            return Err(WireError::Protocol(
                "stream position 0 must have a null previous_commit_ref".to_owned(),
            ));
        }
        if self.stream_position > 0 && self.previous_commit_ref.is_none() {
            return Err(WireError::Protocol(
                "non-genesis stream position requires previous_commit_ref".to_owned(),
            ));
        }
        if self.signature.context != DetachedSignatureContext::RealmCommit {
            return Err(WireError::Protocol(
                "RealmCommit requires the realm commit signature context".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_successor_of(&self, previous: &Self) -> Result<()> {
        self.validate_shape()?;
        previous.validate_shape()?;
        if self.stream_ref != previous.stream_ref {
            return Err(WireError::Protocol(
                "RealmCommit predecessor must be in the same independent stream".to_owned(),
            ));
        }
        if self.stream_position != previous.stream_position.saturating_add(1) {
            return Err(WireError::Protocol(
                "RealmCommit stream_position must increase by exactly one".to_owned(),
            ));
        }
        if self.previous_commit_ref.as_ref() != Some(&previous.commit_id) {
            return Err(WireError::Protocol(
                "RealmCommit previous_commit_ref does not name the previous stream head".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitStreamHead {
    pub stream_ref: CommitStreamRef,
    pub stream_position: u64,
    pub commit_id: RealmCommitId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityHandoff {
    pub handoff_id: RealmAuthorityHandoffId,
    pub realm_id: RealmId,
    pub from_generation: u64,
    pub to_generation: u64,
    pub from_service_id: DidCoreId,
    pub to_service_id: DidCoreId,
    pub final_stream_heads_digest: Hash,
    pub snapshot_ref: RealmSnapshotId,
    pub snapshot_digest: Hash,
    pub change_event_ref: EventId,
    pub change_commit_id: RealmCommitId,
    pub old_authority_signature: DetachedObjectSignature,
    pub new_authority_acceptance_signature: DetachedObjectSignature,
}

impl RealmAuthorityHandoff {
    pub fn validate_shape(&self) -> Result<()> {
        if self.to_generation != self.from_generation.saturating_add(1) {
            return Err(WireError::Protocol(
                "authority handoff generations must be consecutive".to_owned(),
            ));
        }
        if self.old_authority_signature.context
            != DetachedSignatureContext::RealmAuthorityHandoffOld
            || self.new_authority_acceptance_signature.context
                != DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance
        {
            return Err(WireError::Protocol(
                "authority handoff signatures use the wrong domain context".to_owned(),
            ));
        }
        if detached_signature_service_id(&self.old_authority_signature)? != self.from_service_id
            || detached_signature_service_id(&self.new_authority_acceptance_signature)?
                != self.to_service_id
        {
            return Err(WireError::Protocol(
                "authority handoff signatures do not belong to the declared services".to_owned(),
            ));
        }
        Ok(())
    }
}

fn detached_signature_service_id(signature: &DetachedObjectSignature) -> Result<DidCoreId> {
    let controller = signature
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            WireError::Protocol(
                "authority signature verification_method needs a fragment".to_owned(),
            )
        })?;
    Ok(crate::project_did_to_core_id(&Did::new(
        controller.to_owned(),
    )?)?)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityTransition {
    pub change_event: Event,
    pub change_commit: RealmCommit,
    pub handoff: RealmAuthorityHandoff,
}

impl RealmAuthorityTransition {
    pub fn validate_shape(&self) -> Result<()> {
        self.change_commit.validate_shape()?;
        self.handoff.validate_shape()?;
        if self.change_event.realm_id != self.handoff.realm_id
            || self.change_commit.realm_id != self.handoff.realm_id
            || self.change_commit.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: self.handoff.realm_id.clone(),
                })
            || self.change_commit.event_ref != self.change_event.event_id
            || self.handoff.change_event_ref != self.change_event.event_id
            || self.handoff.change_commit_id != self.change_commit.commit_id
            || self.change_commit.governance_generation != self.handoff.from_generation
        {
            return Err(WireError::Protocol(
                "authority transition change Event, RealmCommit, and handoff disagree".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityCurrentAssertion {
    pub realm_id: RealmId,
    pub current_generation: u64,
    pub current_service_id: DidCoreId,
    pub last_handoff_ref: Option<RealmAuthorityHandoffId>,
    pub realm_stream_head: CommitStreamHead,
    pub nonce: Base64UrlString,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: DetachedObjectSignature,
}

impl RealmAuthorityCurrentAssertion {
    pub fn validate_shape(&self) -> Result<()> {
        let nonce_len = self.nonce.as_str().len();
        if self.realm_stream_head.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: self.realm_id.clone(),
            })
            || self.signature.context != DetachedSignatureContext::RealmAuthorityCurrentAssertion
            || !(22..=128).contains(&nonce_len)
        {
            return Err(WireError::Protocol(
                "current authority assertion has an invalid Realm stream or signature context"
                    .to_owned(),
            ));
        }
        if detached_signature_service_id(&self.signature)? != self.current_service_id {
            return Err(WireError::Protocol(
                "current authority assertion signature does not belong to current_service_id"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityBundle {
    pub realm_id: RealmId,
    pub genesis_event: Event,
    pub genesis_commit: RealmCommit,
    pub authority_transitions: Vec<RealmAuthorityTransition>,
    pub current_generation: u64,
    pub current_service_id: DidCoreId,
    /// Authenticated service resolution is owned by `arkret-models-identity`;
    /// this wire crate preserves its closed JSON carrier without adding a
    /// reverse dependency.
    pub current_route_record: Value,
    pub realm_stream_head: CommitStreamHead,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub bundle_issued_at: DateTime<Utc>,
    pub current_assertion: RealmAuthorityCurrentAssertion,
}

impl RealmAuthorityBundle {
    /// Validate the closed public handoff chain and the nonce-bound current
    /// assertion shape. Cryptographic verification and freshness are caller
    /// responsibilities and must fail closed.
    pub fn validate_shape(&self) -> Result<()> {
        self.genesis_commit.validate_shape()?;
        self.current_assertion.validate_shape()?;
        if self.genesis_event.realm_id != self.realm_id
            || self.genesis_commit.realm_id != self.realm_id
            || self.genesis_commit.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: self.realm_id.clone(),
                })
            || self.genesis_commit.stream_position != 0
            || self.genesis_commit.event_ref != self.genesis_event.event_id
            || self.genesis_commit.governance_generation != 0
            || self.genesis_commit.authority_ref
                != RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    self.genesis_event.event_id.clone(),
                )
            || self.realm_stream_head.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: self.realm_id.clone(),
                })
            || self.current_assertion.realm_id != self.realm_id
            || self.current_assertion.current_generation != self.current_generation
            || self.current_assertion.current_service_id != self.current_service_id
            || self.current_assertion.realm_stream_head != self.realm_stream_head
            || self.bundle_issued_at >= self.current_assertion.expires_at
        {
            return Err(WireError::Protocol(
                "authority bundle genesis, current head, or assertion binding mismatch".to_owned(),
            ));
        }

        let mut expected_generation = 0;
        let mut expected_service = Some(detached_signature_service_id(
            &self.genesis_commit.signature,
        )?);
        let mut last_handoff = None;
        for transition in &self.authority_transitions {
            transition.validate_shape()?;
            if transition.handoff.realm_id != self.realm_id
                || transition.handoff.from_generation != expected_generation
                || expected_service.as_ref() != Some(&transition.handoff.from_service_id)
            {
                return Err(WireError::Protocol(
                    "authority bundle handoff chain is not contiguous".to_owned(),
                ));
            }
            expected_generation = transition.handoff.to_generation;
            expected_service = Some(transition.handoff.to_service_id.clone());
            last_handoff = Some(transition.handoff.handoff_id.clone());
        }
        if self.current_generation != expected_generation
            || expected_service.as_ref() != Some(&self.current_service_id)
            || self.current_assertion.last_handoff_ref != last_handoff
        {
            return Err(WireError::Protocol(
                "authority bundle current authority does not match its handoff chain".to_owned(),
            ));
        }
        Ok(())
    }

    /// Bind the public chain to the caller's nonce and an online freshness
    /// check. A cached valid prefix is not evidence that no later handoff
    /// exists, so expired or future-issued assertions fail closed.
    pub fn validate_for_request(
        &self,
        request: &AuthorityBundleRequest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        request.validate()?;
        self.validate_shape()?;
        if self.realm_id != request.realm_id
            || self.current_assertion.nonce != request.nonce
            || self.bundle_issued_at > now
            || self.current_assertion.expires_at <= now
        {
            return Err(WireError::Protocol(
                "authority bundle does not satisfy the requested Realm, nonce, or freshness"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHistoryFloor {
    pub stream_ref: CommitStreamRef,
    pub oldest_position: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionAndHistoryFloor {
    pub history_access: HistoryAccess,
    pub stream_floors: Vec<StreamHistoryFloor>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStateSnapshot {
    pub snapshot_id: RealmSnapshotId,
    pub realm_id: RealmId,
    pub governance_generation: u64,
    pub visible_stream_heads: Vec<CommitStreamHead>,
    pub current_state_entries: Vec<TypedCurrentResult>,
    pub retention_and_history_floor: RetentionAndHistoryFloor,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub signature: DetachedObjectSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsWelcomeRecipientEndpoint {
    Device { device_id: DeviceId },
    AgentRuntime { verification_method: DidUrl },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomeDelivery {
    pub welcome_id: MlsWelcomeDeliveryId,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub commit_event_ref: EventId,
    pub recipient_actor_id: ActorId,
    pub recipient_endpoint: MlsWelcomeRecipientEndpoint,
    pub keypackage_claim_ref: KeypackageClaimId,
    pub ciphertext_b64: Base64UrlString,
    pub producer_proof: DetachedObjectSignature,
}

impl MlsWelcomeDelivery {
    /// `recipient_mls_durable_receipt.welcome_digest`: SHA-256 over the JCS
    /// bytes of the complete delivery, `producer_proof` included. The claim
    /// destination records the same value on the claim ledger when it
    /// enqueues the delivery (device-lifecycle §9, §9.2.3).
    pub fn durable_receipt_digest(&self) -> Result<Hash> {
        Ok(Hash::new(crate::canonical::canonical_sha256(self)?)?)
    }

    pub fn validate_shape(&self) -> Result<()> {
        let ciphertext =
            crate::base64url::base64url_decode(self.ciphertext_b64.as_str()).map_err(|_| {
                WireError::Protocol("MLS Welcome ciphertext is not base64url".to_owned())
            })?;
        if ciphertext.is_empty()
            || crate::base64url::base64url_encode(&ciphertext) != self.ciphertext_b64.as_str()
        {
            return Err(WireError::Protocol(
                "MLS Welcome ciphertext must be canonical unpadded base64url".to_owned(),
            ));
        }
        if self.effective_scope == ScopeRef::RealmGenesis
            || self.effective_scope.realm_id_opt() != Some(&self.realm_id)
        {
            return Err(WireError::Protocol(
                "MLS Welcome effective_scope must belong to realm_id".to_owned(),
            ));
        }
        if self.producer_proof.context != DetachedSignatureContext::MlsWelcomeDelivery {
            return Err(WireError::Protocol(
                "MLS Welcome delivery requires its dedicated signature context".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventAdmissionSubmission {
    pub event: Event,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_signatures: Option<Vec<ApprovalSignature>>,
}

impl EventAdmissionSubmission {
    #[must_use]
    pub fn new(event: Event) -> Self {
        Self {
            event,
            approval_signatures: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.event.validate_for_submit_structural()?;
        if self.approval_signatures.as_ref().is_some_and(Vec::is_empty) {
            return Err(WireError::Protocol(
                "approval_signatures must be omitted or non-empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Request of `ak.self.actor_private_events.command.submit.v1`: one
/// caller-signed actor-private Event that has no dedicated submit operation.
///
/// Spec: `service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitRequestBody`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorPrivateEventSubmitRequestBody {
    pub event: Event,
}

impl ActorPrivateEventSubmitRequestBody {
    /// The only kinds this operation admits. `ak.account_data.set` and
    /// `ak.read_cursor.advance` keep their dedicated operations.
    pub const SUBMIT_KINDS: [crate::EventKind; 4] = [
        crate::EventKind::AgentActionReject,
        crate::EventKind::AgentActionRequest,
        crate::EventKind::AgentDraftPropose,
        crate::EventKind::DevicePushRoute,
    ];

    #[must_use]
    pub fn new(event: Event) -> Self {
        Self { event }
    }

    pub fn validate(&self) -> Result<()> {
        if !Self::SUBMIT_KINDS.contains(&self.event.kind) {
            return Err(WireError::Protocol(format!(
                "{} is not submitted through the actor-private Event operation",
                self.event.kind.as_str()
            )));
        }
        self.event.validate_for_submit_structural()
    }
}

/// Outcome of `ak.self.actor_private_events.command.submit.v1`, discriminated
/// by `event_kind`. An exact retry returns the first stored outcome; no
/// RealmCommit exists for these writes.
///
/// Spec: `service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitOutcome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_kind", deny_unknown_fields)]
pub enum ActorPrivateEventSubmitOutcome {
    #[serde(rename = "ak.agent.action_reject")]
    AgentActionReject { accepted_event_id: EventId },
    #[serde(rename = "ak.agent.action_request")]
    AgentActionRequest { accepted_event_id: EventId },
    #[serde(rename = "ak.agent.draft.propose")]
    AgentDraftPropose { accepted_event_id: EventId },
    /// `revision` is what the next write of this route names as
    /// `expected_server_revision`.
    #[serde(rename = "ak.device.push_route")]
    DevicePushRoute {
        accepted_event_id: EventId,
        revision: u64,
    },
}

impl ActorPrivateEventSubmitOutcome {
    #[must_use]
    pub fn accepted_event_id(&self) -> &EventId {
        match self {
            Self::AgentActionReject { accepted_event_id }
            | Self::AgentActionRequest { accepted_event_id }
            | Self::AgentDraftPropose { accepted_event_id }
            | Self::DevicePushRoute {
                accepted_event_id, ..
            } => accepted_event_id,
        }
    }

    #[must_use]
    pub fn event_kind(&self) -> crate::EventKind {
        match self {
            Self::AgentActionReject { .. } => crate::EventKind::AgentActionReject,
            Self::AgentActionRequest { .. } => crate::EventKind::AgentActionRequest,
            Self::AgentDraftPropose { .. } => crate::EventKind::AgentDraftPropose,
            Self::DevicePushRoute { .. } => crate::EventKind::DevicePushRoute,
        }
    }

    /// Shape check plus the binding to the exact submitted Event.
    pub fn validate_for_request(&self, request: &ActorPrivateEventSubmitRequestBody) -> Result<()> {
        if let Self::DevicePushRoute { revision: 0, .. } = self {
            return Err(WireError::Protocol(
                "push route outcome revision must be at least 1".to_owned(),
            ));
        }
        if self.event_kind() != request.event.kind
            || self.accepted_event_id() != &request.event.event_id
        {
            return Err(WireError::Protocol(
                "actor-private submit outcome does not bind the submitted Event".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "context_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalContext {
    Grant {
        grant_id: GrantId,
    },
    RealmGovernance {},
    /// A separate one-vote requirement of the exact target List's WIP policy.
    /// The revision is the List metadata current result at the authority cut.
    ListWip {
        list_space_id: SpaceId,
        list_policy_revision: CurrentRevision,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalTarget {
    Event { event_id: EventId },
    Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSignatureInput {
    pub approval_context: ApprovalContext,
    pub approval_target: ApprovalTarget,
    pub request_canonical_digest: Hash,
    pub operation: String,
    pub action: CapabilityActionId,
    pub realm_id: RealmId,
    pub initiating_actor_id: ActorId,
    pub approver_did: Did,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub approved_at: DateTime<Utc>,
    pub nonce: String,
}

impl ApprovalSignatureInput {
    /// Validate the registry-owned future-only bound for `approved_at`.
    ///
    /// Grant-specific lower bounds (`issued_at` and a temporal constraint's
    /// `not_before`) require the authoritative grant projection and therefore
    /// remain the governing Station reducer's responsibility.
    pub fn validate_approved_at(&self, verification_time: DateTime<Utc>) -> Result<()> {
        validate_approval_timestamp(self.approved_at, verification_time)
    }

    /// Check the signed List WIP context against an exact move and the
    /// authority-read List metadata revision. Signature, digest, approver
    /// capability and nonce verification still belong to the governing unit.
    pub fn validate_list_wip_binding(
        &self,
        event: &Event,
        operation: &str,
        list_space_id: &SpaceId,
        list_policy_revision: &CurrentRevision,
    ) -> Result<()> {
        if !matches!(
            &self.approval_context,
            ApprovalContext::ListWip {
                list_space_id: signed_list,
                list_policy_revision: signed_revision,
            } if signed_list == list_space_id && signed_revision == list_policy_revision
        ) || !matches!(
            &self.approval_target,
            ApprovalTarget::Event { event_id } if event_id == &event.event_id
        ) || self.action != CapabilityActionId::StrandMove
            || event.kind != crate::EventKind::StrandMove
            || self.operation != operation
            || self.realm_id != event.realm_id
            || self.initiating_actor_id != event.actor_id
            || event.payload.get("target_space_id")
                != Some(&Value::String(list_space_id.as_str().to_owned()))
        {
            return Err(WireError::Protocol(
                "List WIP approval does not bind the exact move and List revision".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Apply the canonical `ak.time_tolerance.approval_approved_at.v1` scenario.
/// Past timestamps are not rejected by this future-only guard.
pub fn validate_approval_timestamp(
    approved_at: DateTime<Utc>,
    verification_time: DateTime<Utc>,
) -> Result<()> {
    use arkret_identifiers::{
        ProtocolTimeToleranceDirection, ProtocolTimeToleranceScenario,
        protocol_time_tolerance_scenario_descriptor,
    };

    let scenario = protocol_time_tolerance_scenario_descriptor(
        ProtocolTimeToleranceScenario::ApprovalApprovedAt,
    );
    debug_assert_eq!(
        scenario.direction,
        ProtocolTimeToleranceDirection::FutureOnly
    );
    let latest = verification_time
        .checked_add_signed(TimeDelta::milliseconds(scenario.tolerance_ms()))
        .ok_or_else(|| {
            WireError::Protocol(
                "approval verification time cannot represent the registered future bound"
                    .to_owned(),
            )
        })?;
    if approved_at > latest {
        return Err(WireError::Protocol(format!(
            "approval approved_at exceeds the registered future-only bound for {}",
            scenario.scenario_id
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalSignatureProofKind {
    #[serde(rename = "detached_jws")]
    DetachedJws,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSignatureProof {
    pub kind: ApprovalSignatureProofKind,
    pub verification_method: DidUrl,
    pub jws: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSignature {
    pub input: ApprovalSignatureInput,
    pub proof: ApprovalSignatureProof,
}

/// Exact ordered, atomic PCR genesis unit: an identity-root signed
/// `ak.realm.create` followed by a founding-device signed
/// `ak.device.authorize`. These Events are replayable only inside this complete
/// unit and its accepted receipt closure, never as standalone shared-history
/// Events, and no partial acceptance is permitted.
// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/pcr_genesis_unit.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrGenesisUnit {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub events: [Event; 2],
}

impl PcrGenesisUnit {
    pub fn new(create: Event, founding_authorize: Event) -> Result<Self> {
        let unit = Self {
            events: [create, founding_authorize],
        };
        unit.validate_ordered_envelopes()?;
        Ok(unit)
    }

    #[must_use]
    pub fn create(&self) -> &Event {
        &self.events[0]
    }

    #[must_use]
    pub fn founding_authorize(&self) -> &Event {
        &self.events[1]
    }

    pub fn validate_ordered_envelopes(&self) -> Result<()> {
        let create = self.create();
        let authorize = self.founding_authorize();
        if create.kind != crate::EventKind::RealmCreate
            || authorize.kind != crate::EventKind::DeviceAuthorize
            || create.actor_id != authorize.actor_id
            || create.realm_id != authorize.realm_id
            || create.realm_id != RealmId::from_event_id(&create.event_id)
            || create.event_id == authorize.event_id
        {
            return Err(WireError::Protocol(
                "PCR genesis unit must be the exact ordered create/authorize pair".to_owned(),
            ));
        }
        for event in &self.events {
            event.validate_for_submit_structural()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCommitSubmission {
    pub commit_event: Event,
    pub welcomes: Vec<MlsWelcomeDelivery>,
    pub idempotency_key: UuidV7,
}

impl MlsCommitSubmission {
    pub fn validate(&self) -> Result<()> {
        self.commit_event.validate_for_submit_structural()?;
        if self.commit_event.kind != crate::EventKind::MlsCommit {
            return Err(WireError::Protocol(
                "MLS commit submission requires ak.mls.commit".to_owned(),
            ));
        }
        if self.welcomes.len() > 1000 {
            return Err(WireError::Protocol(
                "MLS commit submission exceeds 1000 Welcome deliveries".to_owned(),
            ));
        }
        if !self
            .welcomes
            .windows(2)
            .all(|pair| pair[0].welcome_id < pair[1].welcome_id)
        {
            return Err(WireError::Protocol(
                "MLS Welcome deliveries must be sorted and unique by welcome_id".to_owned(),
            ));
        }
        for welcome in &self.welcomes {
            welcome.validate_shape()?;
            if welcome.realm_id != self.commit_event.realm_id
                || welcome.effective_scope != self.commit_event.scope_ref
                || welcome.commit_event_ref != self.commit_event.event_id
            {
                return Err(WireError::Protocol(
                    "MLS Welcome delivery must bind the exact submitted commit Event and scope"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Bare UUIDv7 used by HTTP idempotency contracts that intentionally do not
/// allocate an `ak:*` protocol identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct UuidV7(Uuid);

impl UuidV7 {
    pub fn new(value: Uuid) -> Result<Self> {
        if value.get_version_num() != 7 {
            return Err(WireError::Protocol(
                "idempotency_key must be a canonical UUIDv7".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl<'de> Deserialize<'de> for UuidV7 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let uuid = Uuid::parse_str(&raw).map_err(serde::de::Error::custom)?;
        if uuid.to_string() != raw || uuid.get_version_num() != 7 {
            return Err(serde::de::Error::custom(
                "idempotency_key must be lowercase canonical UUIDv7",
            ));
        }
        Ok(Self(uuid))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRevision {
    pub commit_id: RealmCommitId,
    pub stream_position: u64,
}

/// Registered discriminator of a Realm's organization endorsement current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationRelationship {
    Owner,
    Governance,
    Sponsor,
    DirectoryCertifier,
}

/// The sole v1 full MemberIdentity replacement segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MemberIdentitySegment {
    MemberIdentity,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentSelector {
    RealmGenesis,
    AppletRegistration {
        applet_id: AppletId,
    },
    RealmOrganization {
        organization_id: DidCoreId,
        relationship: RealmOrganizationRelationship,
    },
    RealmAuthorityRoot,
    RealmProfile,
    RealmPolicyBundle,
    RealmJoinRule,
    RealmHistoryAccess,
    RealmDiscovery,
    RealmAlias,
    RealmPlaintextVisibleServices,
    RealmSetDefaultStrand,
    Policy {
        policy_id: PolicyId,
    },
    PolicyAction {
        #[serde(flatten)]
        subject: PolicyActionSelector,
    },
    DeviceAuthorization {
        device_id: DeviceId,
    },
    DeviceGeneration,
    DeviceRevocationProposals {
        device_id: DeviceId,
    },
    MemberState {
        actor_id: ActorId,
    },
    MemberIdentityUpdates {
        member_id: ActorId,
        segment: MemberIdentitySegment,
    },
    /// One canonical Direct Conversation binding inside its own Realm.
    DirectConversationBinding {
        pair_key: Hash,
    },
    AgentKey {
        agent_id: DidCoreId,
        agent_key_id: AgentKeyId,
    },
    AgentStatus {
        agent_id: DidCoreId,
    },
    MimiRoomBinding {
        mimi_room_uri: MimiRoomUri,
    },
    Strand {
        strand_id: StrandId,
    },
    /// One Calendar event occurrence and responder's complete RSVP entry.
    Rsvp {
        event_ref: StrandId,
        occurrence: Option<String>,
        responder_actor_id: ActorId,
    },
    /// The registered watch cell is keyed by the complete watcher Actor.
    StrandWatch {
        strand_id: StrandId,
        watcher_actor_id: ActorId,
    },
    StrandPosition {
        board_space_id: SpaceId,
        strand_id: StrandId,
    },
    /// Registered Space metadata current result.
    Space {
        space_id: SpaceId,
    },
    /// Registered structural parent of one Space.
    SpaceParent {
        space_id: SpaceId,
    },
    /// Registered child placement policy of one Space.
    SpaceChildScopePolicy {
        space_id: SpaceId,
    },
    /// The registered Circle object current, keyed by its create-derived id.
    Circle {
        circle_id: CircleId,
    },
    /// One Circle's exact member Actor current, including its effective time.
    CircleMemberState {
        circle_id: CircleId,
        member_actor_id: ActorId,
    },
    MessageRevision {
        message_id: MessageId,
    },
    MessageReactions {
        event_id: EventId,
    },
    CallState {
        call_id: CallId,
    },
    /// The accepted `ak.self.moderation.report` Event's own id
    /// (`typed-current-result.schema.json#/$defs/moderation_report_result`).
    ModerationReport {
        event_id: EventId,
    },
    /// The encrypted target Event identity, not the proof carrier Event.
    ModerationFrankingProof {
        event_id: EventId,
    },
    /// The moderated target of `ak.moderation.decision` and its lift
    /// (`typed-current-result.schema.json#/$defs/moderation_state_result`).
    ModerationState {
        target_ref: crate::ObjectRef,
    },
    /// The redacted target of `ak.message.redact` (its `message_id`) or of
    /// `ak.redaction` (its `target_ref`), spelled verbatim
    /// (`typed-current-result.schema.json#/$defs/object_redaction_result`).
    ObjectRedaction {
        target_ref: crate::ObjectRef,
    },
    MlsGroup {
        scope_ref: ScopeRef,
    },
    /// One Capability Grant's complete projection, keyed by its
    /// create-derived id
    /// (`typed-current-result.schema.json#/$defs/capability_grant_result`).
    CapabilityGrant {
        grant_id: GrantId,
    },
    /// One Invite's process-state register
    /// (`typed-current-result.schema.json#/$defs/invite_lifecycle_result`).
    InviteLifecycle {
        invite_id: InviteId,
    },
    /// One invitee account's live directed-invite slot inside the Realm; the
    /// Realm is the envelope's, so it is not a subject member
    /// (`typed-current-result.schema.json#/$defs/invite_live_target_result`).
    InviteLiveTarget {
        invitee_account_id: AccountId,
    },
    /// One directed Invite's create-locked invitee
    /// (`typed-current-result.schema.json#/$defs/invite_directed_invitee_result`).
    InviteDirectedInvitee {
        invite_id: InviteId,
    },
    /// One global Actor Profile, keyed by its create-derived id
    /// (`typed-current-result.schema.json#/$defs/actor_profile_result`).
    ActorProfile {
        actor_profile_id: ActorProfileId,
    },
    /// One accountability endorsement. The Realm is the result's scope, so it
    /// is not a subject member; the scope set is the normalized exact set its
    /// composite subject digests
    /// (`typed-current-result.schema.json#/$defs/identity_accountability_result`).
    IdentityAccountability {
        issuer_id: DidCoreId,
        subject_id: DidCoreId,
        accountability_scope: AccountabilityScopeSet,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FlatCurrentSelector {
    RealmGenesis,
    AppletRegistration {
        applet_id: AppletId,
    },
    RealmOrganization {
        organization_id: DidCoreId,
        relationship: RealmOrganizationRelationship,
    },
    RealmAuthorityRoot,
    RealmProfile,
    RealmPolicyBundle,
    RealmJoinRule,
    RealmHistoryAccess,
    RealmDiscovery,
    RealmAlias,
    RealmPlaintextVisibleServices,
    RealmSetDefaultStrand,
    DeviceAuthorization {
        device_id: DeviceId,
    },
    DeviceRevocationProposals {
        device_id: DeviceId,
    },
    MemberState {
        actor_id: ActorId,
    },
    MemberIdentityUpdates {
        member_id: ActorId,
        segment: MemberIdentitySegment,
    },
    DirectConversationBinding {
        pair_key: Hash,
    },
    AgentKey {
        agent_id: DidCoreId,
        agent_key_id: AgentKeyId,
    },
    AgentStatus {
        agent_id: DidCoreId,
    },
    MimiRoomBinding {
        mimi_room_uri: MimiRoomUri,
    },
    Strand {
        strand_id: StrandId,
    },
    Rsvp {
        event_ref: StrandId,
        occurrence: Option<String>,
        responder_actor_id: ActorId,
    },
    StrandWatch {
        strand_id: StrandId,
        watcher_actor_id: ActorId,
    },
    StrandPosition {
        board_space_id: SpaceId,
        strand_id: StrandId,
    },
    Space {
        space_id: SpaceId,
    },
    SpaceParent {
        space_id: SpaceId,
    },
    SpaceChildScopePolicy {
        space_id: SpaceId,
    },
    Circle {
        circle_id: CircleId,
    },
    CircleMemberState {
        circle_id: CircleId,
        member_actor_id: ActorId,
    },
    MessageRevision {
        message_id: MessageId,
    },
    MessageReactions {
        event_id: EventId,
    },
    CallState {
        call_id: CallId,
    },
    /// The accepted `ak.self.moderation.report` Event's own id
    /// (`typed-current-result.schema.json#/$defs/moderation_report_result`).
    ModerationReport {
        event_id: EventId,
    },
    ModerationFrankingProof {
        event_id: EventId,
    },
    /// The moderated target of `ak.moderation.decision` and its lift
    /// (`typed-current-result.schema.json#/$defs/moderation_state_result`).
    ModerationState {
        target_ref: crate::ObjectRef,
    },
    /// The redacted target of `ak.message.redact` (its `message_id`) or of
    /// `ak.redaction` (its `target_ref`), spelled verbatim
    /// (`typed-current-result.schema.json#/$defs/object_redaction_result`).
    ObjectRedaction {
        target_ref: crate::ObjectRef,
    },
    MlsGroup {
        scope_ref: ScopeRef,
    },
    /// One Capability Grant's complete projection, keyed by its
    /// create-derived id
    /// (`typed-current-result.schema.json#/$defs/capability_grant_result`).
    CapabilityGrant {
        grant_id: GrantId,
    },
    /// One Invite's process-state register
    /// (`typed-current-result.schema.json#/$defs/invite_lifecycle_result`).
    InviteLifecycle {
        invite_id: InviteId,
    },
    /// One invitee account's live directed-invite slot inside the Realm; the
    /// Realm is the envelope's, so it is not a subject member
    /// (`typed-current-result.schema.json#/$defs/invite_live_target_result`).
    InviteLiveTarget {
        invitee_account_id: AccountId,
    },
    /// One directed Invite's create-locked invitee
    /// (`typed-current-result.schema.json#/$defs/invite_directed_invitee_result`).
    InviteDirectedInvitee {
        invite_id: InviteId,
    },
    /// One global Actor Profile, keyed by its create-derived id
    /// (`typed-current-result.schema.json#/$defs/actor_profile_result`).
    ActorProfile {
        actor_profile_id: ActorProfileId,
    },
    /// One accountability endorsement. The Realm is the result's scope, so it
    /// is not a subject member; the scope set is the normalized exact set its
    /// composite subject digests
    /// (`typed-current-result.schema.json#/$defs/identity_accountability_result`).
    IdentityAccountability {
        issuer_id: DidCoreId,
        subject_id: DidCoreId,
        accountability_scope: AccountabilityScopeSet,
    },
}

impl<'de> Deserialize<'de> for CurrentSelector {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut wire = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        match wire.get("kind").and_then(Value::as_str) {
            Some("policy") => {
                wire.remove("kind");
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct PolicySubject {
                    policy_id: PolicyId,
                }
                let subject = serde_json::from_value::<PolicySubject>(Value::Object(wire))
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Policy {
                    policy_id: subject.policy_id,
                })
            }
            Some("policy_action") => {
                wire.remove("kind");
                let subject = serde_json::from_value::<PolicyActionSelector>(Value::Object(wire))
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::PolicyAction { subject })
            }
            Some("device_generation") => {
                if wire.len() != 1 {
                    return Err(serde::de::Error::custom(
                        "device_generation selector has no subject fields",
                    ));
                }
                Ok(Self::DeviceGeneration)
            }
            Some("rsvp") if !wire.contains_key("occurrence") => Err(serde::de::Error::custom(
                "rsvp selector requires occurrence, including null",
            )),
            Some(
                kind @ ("realm_genesis"
                | "realm_authority_root"
                | "realm_profile"
                | "realm_policy_bundle"
                | "realm_join_rule"
                | "realm_history_access"
                | "realm_discovery"
                | "realm_alias"
                | "realm_plaintext_visible_services"
                | "realm_set_default_strand"),
            ) => {
                if wire.len() != 1 {
                    return Err(serde::de::Error::custom(format!(
                        "{kind} selector has no subject fields"
                    )));
                }
                Ok(match kind {
                    "realm_genesis" => Self::RealmGenesis,
                    "realm_authority_root" => Self::RealmAuthorityRoot,
                    "realm_profile" => Self::RealmProfile,
                    "realm_policy_bundle" => Self::RealmPolicyBundle,
                    "realm_join_rule" => Self::RealmJoinRule,
                    "realm_history_access" => Self::RealmHistoryAccess,
                    "realm_discovery" => Self::RealmDiscovery,
                    "realm_alias" => Self::RealmAlias,
                    "realm_plaintext_visible_services" => Self::RealmPlaintextVisibleServices,
                    "realm_set_default_strand" => Self::RealmSetDefaultStrand,
                    _ => unreachable!(),
                })
            }
            _ => {
                let flat = serde_json::from_value::<FlatCurrentSelector>(Value::Object(wire))
                    .map_err(serde::de::Error::custom)?;
                Ok(match flat {
                    FlatCurrentSelector::RealmGenesis => Self::RealmGenesis,
                    FlatCurrentSelector::AppletRegistration { applet_id } => {
                        Self::AppletRegistration { applet_id }
                    }
                    FlatCurrentSelector::RealmOrganization {
                        organization_id,
                        relationship,
                    } => Self::RealmOrganization {
                        organization_id,
                        relationship,
                    },
                    FlatCurrentSelector::RealmAuthorityRoot => Self::RealmAuthorityRoot,
                    FlatCurrentSelector::RealmProfile => Self::RealmProfile,
                    FlatCurrentSelector::RealmPolicyBundle => Self::RealmPolicyBundle,
                    FlatCurrentSelector::RealmJoinRule => Self::RealmJoinRule,
                    FlatCurrentSelector::RealmHistoryAccess => Self::RealmHistoryAccess,
                    FlatCurrentSelector::RealmDiscovery => Self::RealmDiscovery,
                    FlatCurrentSelector::RealmAlias => Self::RealmAlias,
                    FlatCurrentSelector::RealmPlaintextVisibleServices => {
                        Self::RealmPlaintextVisibleServices
                    }
                    FlatCurrentSelector::RealmSetDefaultStrand => Self::RealmSetDefaultStrand,
                    FlatCurrentSelector::DeviceAuthorization { device_id } => {
                        Self::DeviceAuthorization { device_id }
                    }
                    FlatCurrentSelector::DeviceRevocationProposals { device_id } => {
                        Self::DeviceRevocationProposals { device_id }
                    }
                    FlatCurrentSelector::MemberState { actor_id } => Self::MemberState { actor_id },
                    FlatCurrentSelector::MemberIdentityUpdates { member_id, segment } => {
                        Self::MemberIdentityUpdates { member_id, segment }
                    }
                    FlatCurrentSelector::DirectConversationBinding { pair_key } => {
                        Self::DirectConversationBinding { pair_key }
                    }
                    FlatCurrentSelector::AgentKey {
                        agent_id,
                        agent_key_id,
                    } => Self::AgentKey {
                        agent_id,
                        agent_key_id,
                    },
                    FlatCurrentSelector::AgentStatus { agent_id } => Self::AgentStatus { agent_id },
                    FlatCurrentSelector::MimiRoomBinding { mimi_room_uri } => {
                        Self::MimiRoomBinding { mimi_room_uri }
                    }
                    FlatCurrentSelector::Strand { strand_id } => Self::Strand { strand_id },
                    FlatCurrentSelector::Rsvp {
                        event_ref,
                        occurrence,
                        responder_actor_id,
                    } => Self::Rsvp {
                        event_ref,
                        occurrence,
                        responder_actor_id,
                    },
                    FlatCurrentSelector::StrandWatch {
                        strand_id,
                        watcher_actor_id,
                    } => Self::StrandWatch {
                        strand_id,
                        watcher_actor_id,
                    },
                    FlatCurrentSelector::StrandPosition {
                        board_space_id,
                        strand_id,
                    } => Self::StrandPosition {
                        board_space_id,
                        strand_id,
                    },
                    FlatCurrentSelector::Space { space_id } => Self::Space { space_id },
                    FlatCurrentSelector::SpaceParent { space_id } => Self::SpaceParent { space_id },
                    FlatCurrentSelector::SpaceChildScopePolicy { space_id } => {
                        Self::SpaceChildScopePolicy { space_id }
                    }
                    FlatCurrentSelector::Circle { circle_id } => Self::Circle { circle_id },
                    FlatCurrentSelector::CircleMemberState {
                        circle_id,
                        member_actor_id,
                    } => Self::CircleMemberState {
                        circle_id,
                        member_actor_id,
                    },
                    FlatCurrentSelector::MessageRevision { message_id } => {
                        Self::MessageRevision { message_id }
                    }
                    FlatCurrentSelector::MessageReactions { event_id } => {
                        Self::MessageReactions { event_id }
                    }
                    FlatCurrentSelector::CallState { call_id } => Self::CallState { call_id },
                    FlatCurrentSelector::ModerationReport { event_id } => {
                        Self::ModerationReport { event_id }
                    }
                    FlatCurrentSelector::ModerationFrankingProof { event_id } => {
                        Self::ModerationFrankingProof { event_id }
                    }
                    FlatCurrentSelector::ModerationState { target_ref } => {
                        Self::ModerationState { target_ref }
                    }
                    FlatCurrentSelector::ObjectRedaction { target_ref } => {
                        Self::ObjectRedaction { target_ref }
                    }
                    FlatCurrentSelector::MlsGroup { scope_ref } => Self::MlsGroup { scope_ref },
                    FlatCurrentSelector::CapabilityGrant { grant_id } => {
                        Self::CapabilityGrant { grant_id }
                    }
                    FlatCurrentSelector::InviteLifecycle { invite_id } => {
                        Self::InviteLifecycle { invite_id }
                    }
                    FlatCurrentSelector::InviteLiveTarget { invitee_account_id } => {
                        Self::InviteLiveTarget { invitee_account_id }
                    }
                    FlatCurrentSelector::InviteDirectedInvitee { invite_id } => {
                        Self::InviteDirectedInvitee { invite_id }
                    }
                    FlatCurrentSelector::ActorProfile { actor_profile_id } => {
                        Self::ActorProfile { actor_profile_id }
                    }
                    FlatCurrentSelector::IdentityAccountability {
                        issuer_id,
                        subject_id,
                        accountability_scope,
                    } => Self::IdentityAccountability {
                        issuer_id,
                        subject_id,
                        accountability_scope,
                    },
                })
            }
        }
    }
}

/// The two `policy_action` subject namespaces cannot share one optional-field
/// shape: a Policy's action token and a Realm-local action id have different
/// identities and never coalesce.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "branch", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyActionSelector {
    PolicyRef {
        policy_id: PolicyId,
        action: PolicyActionName,
    },
    RealmAction {
        action_id: RealmPolicyActionId,
    },
}

/// The action token grammar of `policy_action_document.action`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PolicyActionName(String);

impl PolicyActionName {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, &'static str> {
        let value = value.into();
        let Some(rest) = value.strip_prefix("ak.") else {
            return Err("policy action must start with ak.");
        };
        if rest.split('.').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        }) {
            return Err("policy action has an invalid segment");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PolicyActionName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A Realm-local configuration name, explicitly outside the `ak:` typed-id
/// namespace as required by `non_typed_identifier_floor`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RealmPolicyActionId(String);

impl RealmPolicyActionId {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.starts_with("ak:") {
            return Err("realm action id must be non-empty and outside ak: namespace");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RealmPolicyActionId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Join,
    Knock,
    Leave,
    Ban,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberStateCurrent {
    pub membership: MembershipState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_helpers::optional_canonical_timestamp"
    )]
    pub joined_at: Option<DateTime<Utc>>,
}

/// The existing `circle_member_state_value` schema's complete current value.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleMemberStateCurrent {
    pub membership: MembershipState,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionCurrent {
    pub actor_id: ActorId,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGroupCurrent {
    pub effective_scope: ScopeRef,
    pub genesis_event_ref: EventId,
    pub current_mls_commit_event_ref: EventId,
    pub epoch: u64,
    pub current_key_access_revision: u64,
    pub covered_key_access_revision: u64,
    pub public_tree_ref: crate::BlobRef,
}

/// Closed selector union for snapshot/current reads. Complex domain values
/// remain their canonical schema JSON until their owning model crates expose a
/// dependency-safe shared representation.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypedCurrentResult {
    Value {
        selector: CurrentSelector,
        source_stream_ref: CommitStreamRef,
        revision: CurrentRevision,
        value: Value,
    },
    MessageReactions {
        selector: CurrentSelector,
        source_stream_ref: CommitStreamRef,
        revision: CurrentRevision,
        reactions: Vec<ReactionCurrent>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthoritySubmitRequest {
    Event(EventAdmissionSubmission),
    MlsCommit(MlsCommitSubmission),
}

impl AuthoritySubmitRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Event(submission) => submission.validate(),
            Self::MlsCommit(submission) => submission.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCommitStatus {
    Committed,
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRejectionStatus {
    Rejected,
    RetryableUnavailable,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AuthoritySubmitOutcome {
    Accepted {
        status: AuthorityCommitStatus,
        commit: RealmCommit,
    },
    Rejected {
        status: AuthorityRejectionStatus,
        reason_code: String,
    },
}

impl AuthoritySubmitOutcome {
    pub fn validate_shape(&self) -> Result<()> {
        match self {
            Self::Accepted { commit, .. } => commit.validate_shape(),
            Self::Rejected { reason_code, .. } if !reason_code.is_empty() => Ok(()),
            Self::Rejected { .. } => Err(WireError::Protocol(
                "authority rejection requires a non-empty reason_code".to_owned(),
            )),
        }
    }

    pub fn validate_for_request(&self, request: &AuthoritySubmitRequest) -> Result<()> {
        request.validate()?;
        self.validate_shape()?;
        let event = match request {
            AuthoritySubmitRequest::Event(submission) => &submission.event,
            AuthoritySubmitRequest::MlsCommit(submission) => &submission.commit_event,
        };
        if let Self::Accepted { commit, .. } = self {
            let expected_stream =
                CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))?;
            if commit.realm_id != event.realm_id
                || commit.stream_ref != expected_stream
                || commit.event_ref != event.event_id
            {
                return Err(WireError::Protocol(
                    "authority submit outcome does not commit the submitted Event in its scope stream"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamScanRequest {
    pub realm_id: RealmId,
    pub stream_ref: CommitStreamRef,
    pub direction: StreamScanDirection,
    pub limit: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamScanDirection {
    After(Option<u64>),
    Before(Option<u64>),
}

impl Serialize for StreamScanRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("realm_id", &self.realm_id)?;
        map.serialize_entry("stream_ref", &self.stream_ref)?;
        match self.direction {
            StreamScanDirection::After(position) => {
                map.serialize_entry("after_position", &position)?
            }
            StreamScanDirection::Before(position) => {
                map.serialize_entry("before_position", &position)?
            }
        }
        map.serialize_entry("limit", &self.limit)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for StreamScanRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            realm_id: RealmId,
            stream_ref: CommitStreamRef,
            #[serde(default)]
            after_position: Option<Value>,
            #[serde(default)]
            before_position: Option<Value>,
            limit: u16,
        }
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("stream scan request must be an object"))?;
        let has_after = object.contains_key("after_position");
        let has_before = object.contains_key("before_position");
        if has_after == has_before {
            return Err(D::Error::custom(
                "stream scan requires exactly one position direction",
            ));
        }
        let raw: Raw = serde_json::from_value(value).map_err(D::Error::custom)?;
        let parse_position = |value: Option<Value>| -> std::result::Result<Option<u64>, D::Error> {
            match value {
                None | Some(Value::Null) => Ok(None),
                Some(value) => serde_json::from_value::<u64>(value)
                    .map(Some)
                    .map_err(D::Error::custom),
            }
        };
        let direction = if has_after {
            StreamScanDirection::After(parse_position(raw.after_position)?)
        } else {
            StreamScanDirection::Before(parse_position(raw.before_position)?)
        };
        Ok(Self {
            realm_id: raw.realm_id,
            stream_ref: raw.stream_ref,
            direction,
            limit: raw.limit,
        })
    }
}

impl StreamScanRequest {
    pub fn validate(&self) -> Result<()> {
        if &self.realm_id != self.stream_ref.realm_id() {
            return Err(WireError::Protocol(
                "stream scan realm_id must equal stream_ref.realm_id".to_owned(),
            ));
        }
        if !(1..=1000).contains(&self.limit) {
            return Err(WireError::Protocol(
                "stream scan limit must be in 1..=1000".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEventFullView {
    pub commit: RealmCommit,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
}

impl CommittedEventFullView {
    pub fn validate_shape(&self) -> Result<()> {
        self.commit.validate_shape()?;
        let expected_stream =
            CommitStreamRef::from_scope(&self.event.scope_ref, Some(self.event.realm_id.clone()))?;
        if self.commit.realm_id != self.event.realm_id
            || self.commit.stream_ref != expected_stream
            || self.commit.event_ref != self.event.event_id
        {
            return Err(WireError::Protocol(
                "committed Event view must bind the exact Event and its independent scope stream"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventDisclosureStatus {
    Withheld,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDisclosure {
    pub status: EventDisclosureStatus,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEventWithheldView {
    pub commit: RealmCommit,
    pub event_disclosure: EventDisclosure,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum CommittedEventView {
    Full(CommittedEventFullView),
    Withheld(CommittedEventWithheldView),
}

impl CommittedEventView {
    pub fn validate_shape(&self) -> Result<()> {
        match self {
            Self::Full(view) => view.validate_shape(),
            Self::Withheld(view) => view.commit.validate_shape(),
        }
    }

    #[must_use]
    pub fn commit(&self) -> &RealmCommit {
        match self {
            Self::Full(view) => &view.commit,
            Self::Withheld(view) => &view.commit,
        }
    }

    #[must_use]
    pub fn reducer_input(&self) -> Option<&Event> {
        match self {
            Self::Full(view) => Some(&view.event),
            Self::Withheld(_) => None,
        }
    }
}

/// Closed reference used when another service must verify an exact committed
/// Event without scanning or trusting a caller-supplied Event alone.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CommittedEventRef {
    pub event_id: EventId,
    pub commit_id: RealmCommitId,
    pub stream_ref: CommitStreamRef,
    pub stream_position: u64,
}

impl CommittedEventRef {
    pub fn matches(&self, item: &CommittedEventView) -> bool {
        let commit = item.commit();
        item.validate_shape().is_ok()
            && self.event_id == commit.event_ref
            && self.commit_id == commit.commit_id
            && self.stream_ref == commit.stream_ref
            && self.stream_position == commit.stream_position
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamScanOutcome {
    pub committed_events: Vec<CommittedEventView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable_floor: Option<ReadableFloor>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadableFloorReason {
    StreamStart,
    MembershipJoin,
    HistoryAccessPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadableFloor {
    pub oldest_position: u64,
    pub floor_commit_id: RealmCommitId,
    pub floor_reason: ReadableFloorReason,
}

impl StreamScanOutcome {
    pub fn validate_for_request(&self, request: &StreamScanRequest) -> Result<()> {
        request.validate()?;
        if self.committed_events.len() > usize::from(request.limit) {
            return Err(WireError::Protocol(
                "stream scan returned more items than requested".to_owned(),
            ));
        }
        if self.committed_events.is_empty() && self.truncated {
            return Err(WireError::Protocol(
                "empty stream scan cannot be truncated".to_owned(),
            ));
        }
        if self.readable_floor.as_ref().is_some_and(|floor| {
            (floor.floor_reason == ReadableFloorReason::StreamStart) != (floor.oldest_position == 0)
        }) {
            return Err(WireError::Protocol(
                "stream scan floor reason does not match its position".to_owned(),
            ));
        }
        for item in &self.committed_events {
            item.validate_shape()?;
            if item.commit().realm_id != request.realm_id
                || item.commit().stream_ref != request.stream_ref
            {
                return Err(WireError::Protocol(
                    "stream scan item does not belong to the requested stream".to_owned(),
                ));
            }
        }
        if let Some(first) = self.committed_events.first() {
            match request.direction {
                StreamScanDirection::After(Some(position)) => {
                    let next = position.checked_add(1);
                    let starts_at_floor = self.readable_floor.as_ref().is_some_and(|floor| {
                        position < floor.oldest_position
                            && first.commit().stream_position == floor.oldest_position
                    });
                    if next != Some(first.commit().stream_position) && !starts_at_floor {
                        return Err(WireError::Protocol(
                            "after_position scan skipped or repeated a readable position"
                                .to_owned(),
                        ));
                    }
                }
                StreamScanDirection::Before(Some(position))
                    if first.commit().stream_position >= position =>
                {
                    return Err(WireError::Protocol(
                        "before_position scan returned a newer position".to_owned(),
                    ));
                }
                StreamScanDirection::After(None)
                    if self.readable_floor.as_ref().is_none_or(|floor| {
                        first.commit().stream_position != floor.oldest_position
                    }) =>
                {
                    return Err(WireError::Protocol(
                        "after_position null scan must start at readable floor".to_owned(),
                    ));
                }
                _ => {}
            }
        }
        for pair in self.committed_events.windows(2) {
            match request.direction {
                StreamScanDirection::After(_) => {
                    pair[1].commit().validate_successor_of(pair[0].commit())?
                }
                StreamScanDirection::Before(_) => {
                    pair[0].commit().validate_successor_of(pair[1].commit())?
                }
            }
        }
        if let Some(floor) = &self.readable_floor {
            for item in &self.committed_events {
                let commit = item.commit();
                if commit.stream_position < floor.oldest_position
                    || (commit.stream_position == floor.oldest_position
                        && commit.commit_id != floor.floor_commit_id)
                {
                    return Err(WireError::Protocol(
                        "stream scan row conflicts with readable floor".to_owned(),
                    ));
                }
            }
        }
        if let StreamScanDirection::Before(_) = request.direction {
            if let Some(last) = self.committed_events.last() {
                if self.truncated
                    && self
                        .readable_floor
                        .as_ref()
                        .is_some_and(|floor| last.commit().stream_position == floor.oldest_position)
                {
                    return Err(WireError::Protocol(
                        "before_position scan cannot truncate at readable floor".to_owned(),
                    ));
                }
                if !self.truncated
                    && self
                        .readable_floor
                        .as_ref()
                        .is_none_or(|floor| last.commit().stream_position != floor.oldest_position)
                {
                    return Err(WireError::Protocol(
                        "before_position scan reached floor without its anchor".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Maximum rows in one `ak.self.realm.read.streams.v1` page.
pub const REALM_STREAM_LIST_MAX_ITEMS: usize = 500;

/// One established authority stream the caller may know exists
/// (`realm-read-operations.schema.json#/$defs/realm_stream_row`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStreamRow {
    pub stream_ref: CommitStreamRef,
    pub head_commit_ref: RealmCommitId,
    pub next_position: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable_floor: Option<ReadableFloor>,
}

/// ACL-filtered stream enumeration page
/// (`realm-read-operations.schema.json#/$defs/realm_stream_list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStreamList {
    pub realm_id: RealmId,
    pub streams: Vec<RealmStreamRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

impl RealmStreamList {
    /// Check the page invariants of the closed schema and its operation:
    /// rows belong to the Realm, are strictly ordered by the unsigned bytes of
    /// RFC 8785 JCS(stream_ref), carry an established head, and `has_more`
    /// agrees with the continuation cursor.
    pub fn validate(&self) -> Result<()> {
        if self.streams.len() > REALM_STREAM_LIST_MAX_ITEMS {
            return Err(WireError::Protocol(format!(
                "realm stream list carries more than {REALM_STREAM_LIST_MAX_ITEMS} rows"
            )));
        }
        if self.has_more != self.next_cursor.is_some() {
            return Err(WireError::Protocol(
                "realm stream list has_more must agree with next_cursor".to_owned(),
            ));
        }
        if let Some(cursor) = &self.next_cursor {
            let handle = cursor.strip_prefix("ak:cursor:").unwrap_or_default();
            if handle.is_empty()
                || !handle
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            {
                return Err(WireError::Protocol(
                    "realm stream list next_cursor is not an opaque ak:cursor token".to_owned(),
                ));
            }
        }
        let mut previous: Option<Vec<u8>> = None;
        for row in &self.streams {
            if row.stream_ref.realm_id() != &self.realm_id {
                return Err(WireError::Protocol(
                    "realm stream list row belongs to another Realm".to_owned(),
                ));
            }
            if row.next_position == 0 {
                return Err(WireError::Protocol(
                    "realm stream list row has no established Commit chain".to_owned(),
                ));
            }
            if let Some(floor) = &row.readable_floor
                && ((floor.floor_reason == ReadableFloorReason::StreamStart)
                    != (floor.oldest_position == 0)
                    || floor.oldest_position >= row.next_position)
            {
                return Err(WireError::Protocol(
                    "realm stream list readable_floor is outside the stream".to_owned(),
                ));
            }
            let key = arkret_canonical::canonical::canonical_json_bytes(&row.stream_ref)?;
            if previous.as_ref().is_some_and(|previous| previous >= &key) {
                return Err(WireError::Protocol(
                    "realm stream list rows must be strictly ordered by JCS(stream_ref)".to_owned(),
                ));
            }
            previous = Some(key);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBundleRequest {
    pub realm_id: RealmId,
    pub nonce: Base64UrlString,
}

impl AuthorityBundleRequest {
    pub fn validate(&self) -> Result<()> {
        if !(22..=128).contains(&self.nonce.as_str().len()) {
            return Err(WireError::Protocol(
                "authority bundle nonce must contain 22..=128 base64url characters".to_owned(),
            ));
        }
        Ok(())
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
}

impl AuthorityHandoffRequest {
    pub fn validate_shape(&self) -> Result<()> {
        self.handoff.validate_shape()?;
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
        let heads_digest = Hash::new(crate::canonical::canonical_sha256(
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
            || self.snapshot.signature.signed_digest != self.handoff.snapshot_digest
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

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::{DidCoreId, EventKind, test_support};

    #[test]
    fn actor_private_submit_outcome_is_closed_per_event_kind() {
        let event_id = "ak:event:AXrw54_r8iPVFSBGJhTZduzx5vRg62wu8bdDrUhCm9hR";
        let push: ActorPrivateEventSubmitOutcome = serde_json::from_value(json!({
            "event_kind": "ak.device.push_route",
            "accepted_event_id": event_id,
            "revision": 3
        }))
        .unwrap();
        assert_eq!(push.event_kind(), EventKind::DevicePushRoute);
        assert_eq!(
            serde_json::to_value(&push).unwrap(),
            json!({
                "event_kind": "ak.device.push_route",
                "accepted_event_id": event_id,
                "revision": 3
            })
        );
        let draft: ActorPrivateEventSubmitOutcome = serde_json::from_value(json!({
            "event_kind": "ak.agent.draft.propose",
            "accepted_event_id": event_id
        }))
        .unwrap();
        assert_eq!(draft.event_kind(), EventKind::AgentDraftPropose);
        for rejected in [
            json!({"event_kind": "ak.device.push_route", "accepted_event_id": event_id}),
            json!({"event_kind": "ak.agent.action_request", "accepted_event_id": event_id, "revision": 1}),
            json!({"event_kind": "ak.read_cursor.advance", "accepted_event_id": event_id}),
            json!({"event_kind": "ak.account.blocklist", "accepted_event_id": event_id}),
        ] {
            assert!(
                serde_json::from_value::<ActorPrivateEventSubmitOutcome>(rejected.clone()).is_err(),
                "{rejected}"
            );
        }
    }

    #[test]
    fn ordinary_realm_bootstrap_current_selectors_match_closed_result_shapes() {
        for (selector, kind) in [
            (CurrentSelector::RealmGenesis, "realm_genesis"),
            (CurrentSelector::RealmAuthorityRoot, "realm_authority_root"),
            (CurrentSelector::RealmProfile, "realm_profile"),
            (CurrentSelector::RealmPolicyBundle, "realm_policy_bundle"),
            (CurrentSelector::RealmJoinRule, "realm_join_rule"),
            (CurrentSelector::RealmHistoryAccess, "realm_history_access"),
            (CurrentSelector::RealmDiscovery, "realm_discovery"),
            (CurrentSelector::RealmAlias, "realm_alias"),
            (
                CurrentSelector::RealmPlaintextVisibleServices,
                "realm_plaintext_visible_services",
            ),
        ] {
            let wire = json!({"kind": kind});
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
            assert!(
                serde_json::from_value::<CurrentSelector>(
                    json!({"kind": kind, "unexpected": true}),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn realm_set_default_strand_selector_is_exact_singleton() {
        let selector = CurrentSelector::RealmSetDefaultStrand;
        let wire = json!({"kind":"realm_set_default_strand"});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        assert!(
            serde_json::from_value::<CurrentSelector>(
                json!({"kind":"realm_set_default_strand","strand_id":"ak:strand:forged"})
            )
            .is_err()
        );
    }

    #[test]
    fn message_revision_selector_is_exact_derived_identity() {
        let event_id = EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"message revision selector"),
        );
        let message_id = MessageId::from_event_id(&event_id);
        let selector = CurrentSelector::MessageRevision {
            message_id: message_id.clone(),
        };
        let wire = json!({"kind":"message_revision","message_id":message_id});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        assert!(
            serde_json::from_value::<CurrentSelector>(
                json!({"kind":"message_revision","message_id":message_id,"strand_id":"forged"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<CurrentSelector>(json!({"kind":"message_revision"})).is_err()
        );
    }

    #[test]
    fn moderation_report_selector_is_the_report_event_identity() {
        let event_id = EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"moderation report selector"),
        );
        let selector = CurrentSelector::ModerationReport {
            event_id: event_id.clone(),
        };
        let wire = json!({"kind":"moderation_report","event_id":event_id});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        for invalid in [
            json!({"kind":"moderation_report"}),
            json!({"kind":"moderation_report","event_id":event_id,"report_id":"forged"}),
            json!({"kind":"moderation_report","event_id":MessageId::from_event_id(&event_id)}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[test]
    fn franking_selector_is_the_encrypted_target_event_identity() {
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [43; 32]);
        let selector = CurrentSelector::ModerationFrankingProof {
            event_id: event_id.clone(),
        };
        let wire = json!({"kind":"moderation_franking_proof","event_id":event_id});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        for invalid in [
            json!({"kind":"moderation_franking_proof"}),
            json!({"kind":"moderation_franking_proof","event_id":event_id,"proof_event_id":event_id}),
            json!({"kind":"moderation_franking_proof","event_id":MessageId::from_event_id(&event_id)}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[test]
    fn organization_selector_binds_the_existing_relationship_cell() {
        let organization = DidCoreId::new("ak:did_core:web:organization.example").unwrap();
        for relationship in [
            RealmOrganizationRelationship::Owner,
            RealmOrganizationRelationship::Governance,
            RealmOrganizationRelationship::Sponsor,
            RealmOrganizationRelationship::DirectoryCertifier,
        ] {
            let selector = CurrentSelector::RealmOrganization {
                organization_id: organization.clone(),
                relationship,
            };
            let wire = serde_json::to_value(&selector).unwrap();
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
        for invalid in [
            json!({"kind":"realm_organization","organization_id":organization}),
            json!({"kind":"realm_organization","organization_id":organization,"relationship":"moderation_policy"}),
            json!({"kind":"realm_organization","organization_id":organization,"relationship":"owner","realm_id":"forged"}),
            json!({"kind":"realm_organization","organization_id":"did:web:organization.example","relationship":"owner"}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[test]
    fn moderation_state_selector_is_the_moderated_target() {
        let event_id = EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"moderation state selector"),
        );
        let selector = CurrentSelector::ModerationState {
            target_ref: event_id.to_string(),
        };
        let wire = json!({"kind":"moderation_state","target_ref":event_id});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        for invalid in [
            json!({"kind":"moderation_state"}),
            json!({"kind":"moderation_state","target_ref":event_id,"event_id":event_id}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[test]
    fn object_redaction_selector_is_the_verbatim_redaction_target() {
        let event_id = EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"object redaction selector"),
        );
        let message_id = MessageId::from_event_id(&event_id);
        for target_ref in [message_id.to_string(), event_id.to_string()] {
            let selector = CurrentSelector::ObjectRedaction {
                target_ref: target_ref.clone(),
            };
            let wire = json!({"kind":"object_redaction","target_ref":target_ref});
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
        for invalid in [
            json!({"kind":"object_redaction"}),
            json!({"kind":"object_redaction","message_id":message_id}),
            json!({"kind":"object_redaction","target_ref":message_id,"realm_id":"ak:realm:x"}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[test]
    fn policy_current_selectors_round_trip_exact_closed_branches() {
        let policy_id = PolicyId::new("ak:policy:01904100-0000-7000-8000-000000000001").unwrap();
        let cases = [
            (
                CurrentSelector::Policy {
                    policy_id: policy_id.clone(),
                },
                json!({"kind":"policy","policy_id":policy_id}),
            ),
            (
                CurrentSelector::PolicyAction {
                    subject: PolicyActionSelector::PolicyRef {
                        policy_id: policy_id.clone(),
                        action: PolicyActionName::new("ak.message.send").unwrap(),
                    },
                },
                json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy_id,"action":"ak.message.send"}),
            ),
            (
                CurrentSelector::PolicyAction {
                    subject: PolicyActionSelector::RealmAction {
                        action_id: RealmPolicyActionId::new("local_approval").unwrap(),
                    },
                },
                json!({"kind":"policy_action","branch":"realm_action","action_id":"local_approval"}),
            ),
        ];
        for (selector, wire) in cases {
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
    }

    #[test]
    fn policy_current_selectors_reject_missing_mixed_and_unknown_fields() {
        let policy = "ak:policy:01904100-0000-7000-8000-000000000001";
        for invalid in [
            json!({"kind":"policy"}),
            json!({"kind":"policy","policy_id":policy,"action":"ak.message.send"}),
            json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy}),
            json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy,"action":"ak.message.send","action_id":"local_approval"}),
            json!({"kind":"policy_action","branch":"realm_action","action_id":"local_approval","policy_id":policy}),
            json!({"kind":"policy_action","branch":"realm_action","action_id":"local_approval","action":"ak.message.send"}),
            json!({"kind":"policy_action","branch":"realm_action","action_id":"ak:policy:typed"}),
            json!({"kind":"policy_action","branch":"realm_action","action_id":""}),
            json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy,"action":"ak.Message.Send"}),
            json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy,"action":"ak.message..send"}),
            json!({"kind":"policy_action","branch":"other","action_id":"local_approval"}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn device_current_selectors_round_trip_exact_closed_shapes() {
        let device_id = DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000001").unwrap();
        for (selector, wire) in [
            (
                CurrentSelector::DeviceAuthorization {
                    device_id: device_id.clone(),
                },
                json!({"kind":"device_authorization","device_id":device_id}),
            ),
            (
                CurrentSelector::DeviceGeneration,
                json!({"kind":"device_generation"}),
            ),
            (
                CurrentSelector::DeviceRevocationProposals {
                    device_id: device_id.clone(),
                },
                json!({"kind":"device_revocation_proposals","device_id":device_id}),
            ),
        ] {
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
    }

    #[test]
    fn device_current_selectors_reject_missing_mirrored_and_unknown_fields() {
        let device = "ak:device:019a0000-0000-7000-8000-000000000001";
        for invalid in [
            json!({"kind":"device_authorization"}),
            json!({"kind":"device_authorization","device_id":device,"account_id":"extra"}),
            json!({"kind":"device_authorization","device_id":"not-a-device"}),
            json!({"kind":"device_generation","device_id":device}),
            json!({"kind":"device_generation","device_generation_status":"active"}),
            json!({"kind":"device_revocation_proposals"}),
            json!({"kind":"device_revocation_proposals","device_id":device,"principal_id":"extra"}),
            json!({"kind":"device_revocation_proposals","device_id":null}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn capability_grant_selector_round_trips_and_rejects_foreign_subjects() {
        let grant_id =
            GrantId::new("ak:grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let selector = CurrentSelector::CapabilityGrant {
            grant_id: grant_id.clone(),
        };
        let wire = json!({"kind":"capability_grant","grant_id":grant_id});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        let realm = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
        for invalid in [
            json!({"kind":"capability_grant"}),
            json!({"kind":"capability_grant","grant_id":"ak:capability:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
            json!({"kind":"capability_grant","grant_id":grant_id,"realm_id":realm}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn strand_position_selector_validates_both_typed_components() {
        let board = SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let strand =
            StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let selector = CurrentSelector::StrandPosition {
            board_space_id: board.clone(),
            strand_id: strand.clone(),
        };
        let wire = json!({"kind":"strand_position","board_space_id":board,"strand_id":strand});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        for invalid in [
            json!({"kind":"strand_position","strand_id":strand}),
            json!({"kind":"strand_position","board_space_id":board}),
            json!({"kind":"strand_position","board_space_id":strand,"strand_id":strand}),
            json!({"kind":"strand_position","board_space_id":board,"strand_id":board}),
            json!({"kind":"strand_position","board_space_id":"AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7","strand_id":strand}),
            json!({"kind":"strand_position","board_space_id":board,"strand_id":strand,"subject":"hash"}),
            json!({"kind":"strand_position","subject":"AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rsvp_current_selector_round_trips_the_closed_subject() {
        let event_ref =
            StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let responder_actor_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:member.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        for occurrence in [None, Some("2026-09-28".to_owned())] {
            let selector = CurrentSelector::Rsvp {
                event_ref: event_ref.clone(),
                occurrence: occurrence.clone(),
                responder_actor_id: responder_actor_id.clone(),
            };
            let wire = json!({
                "kind": "rsvp",
                "event_ref": event_ref,
                "occurrence": occurrence,
                "responder_actor_id": responder_actor_id,
            });
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
        for invalid in [
            json!({"kind":"rsvp","event_ref":event_ref,"responder_actor_id":responder_actor_id}),
            json!({"kind":"rsvp","event_ref":event_ref,"occurrence":null}),
            json!({"kind":"rsvp","event_ref":event_ref,"occurrence":null,"responder_actor_id":responder_actor_id,"extra":true}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn registered_space_current_selectors_round_trip_closed_shapes() {
        let space_id =
            SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        for (selector, kind) in [
            (
                CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                "space",
            ),
            (
                CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                "space_parent",
            ),
            (
                CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                "space_child_scope_policy",
            ),
        ] {
            let wire = json!({"kind":kind,"space_id":space_id});
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
            for invalid in [
                json!({"kind":kind}),
                json!({"kind":kind,"space_id":space_id,"realm_id":"ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
                json!({"kind":kind,"space_id":"ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
            ] {
                assert!(
                    serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                    "{invalid}"
                );
            }
        }
    }

    #[test]
    fn invite_current_selectors_round_trip_and_reject_foreign_subjects() {
        let invite_id =
            InviteId::new("ak:invite:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let invitee = AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        for (selector, wire) in [
            (
                CurrentSelector::InviteLifecycle {
                    invite_id: invite_id.clone(),
                },
                json!({"kind":"invite_lifecycle","invite_id":invite_id}),
            ),
            (
                CurrentSelector::InviteLiveTarget {
                    invitee_account_id: invitee.clone(),
                },
                json!({"kind":"invite_live_target","invitee_account_id":invitee}),
            ),
            (
                CurrentSelector::InviteDirectedInvitee {
                    invite_id: invite_id.clone(),
                },
                json!({"kind":"invite_directed_invitee","invite_id":invite_id}),
            ),
        ] {
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
        let realm = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
        for invalid in [
            json!({"kind":"invite_lifecycle"}),
            json!({"kind":"invite_lifecycle","invite_id":"ak:event:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
            json!({"kind":"invite_live_target","invitee_account_id":invitee,"realm_id":realm}),
            json!({"kind":"invite_live_target","invitee_account_id":"ak:did_core:web:bob.example"}),
            json!({"kind":"invite_directed_invitee","invite_id":invite_id,"invitee_account_id":invitee}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn profile_and_accountability_selectors_round_trip_closed_shapes() {
        let profile_id =
            ActorProfileId::new("ak:actor_profile:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-")
                .unwrap();
        let issuer = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let subject = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let scope = AccountabilityScopeSet::normalize([
            crate::AccountabilityScopeKind::Employment,
            crate::AccountabilityScopeKind::AgentOperator,
        ])
        .unwrap();
        for (selector, wire) in [
            (
                CurrentSelector::ActorProfile {
                    actor_profile_id: profile_id.clone(),
                },
                json!({"kind":"actor_profile","actor_profile_id":profile_id}),
            ),
            (
                CurrentSelector::IdentityAccountability {
                    issuer_id: issuer.clone(),
                    subject_id: subject.clone(),
                    accountability_scope: scope,
                },
                json!({
                    "kind":"identity_accountability",
                    "issuer_id":issuer,
                    "subject_id":subject,
                    "accountability_scope":["agent_operator","employment"]
                }),
            ),
        ] {
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
        let realm = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
        for invalid in [
            json!({"kind":"actor_profile"}),
            json!({"kind":"actor_profile","actor_profile_id":profile_id,"realm_id":realm}),
            json!({"kind":"actor_profile","actor_profile_id":"ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-"}),
            json!({"kind":"identity_accountability","issuer_id":issuer,"subject_id":subject,"accountability_scope":"employment"}),
            json!({"kind":"identity_accountability","issuer_id":issuer,"subject_id":subject,"accountability_scope":["employment","agent_operator"]}),
            json!({"kind":"identity_accountability","issuer_id":issuer,"subject_id":subject,"accountability_scope":["employment"],"realm_id":realm}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn agent_current_selectors_round_trip_closed_shapes() {
        let agent_id = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let agent_key_id = AgentKeyId::new("runtime_key-1").unwrap();
        for (selector, wire) in [
            (
                CurrentSelector::AgentKey {
                    agent_id: agent_id.clone(),
                    agent_key_id: agent_key_id.clone(),
                },
                json!({"kind":"agent_key","agent_id":agent_id,"agent_key_id":agent_key_id}),
            ),
            (
                CurrentSelector::AgentStatus {
                    agent_id: agent_id.clone(),
                },
                json!({"kind":"agent_status","agent_id":agent_id}),
            ),
        ] {
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
        for invalid in [
            json!({"kind":"agent_key","agent_id":agent_id}),
            json!({"kind":"agent_key","agent_id":agent_id,"agent_key_id":""}),
            json!({"kind":"agent_key","agent_id":agent_id,"agent_key_id":"runtime_key-1","account_id":"extra"}),
            json!({"kind":"agent_status"}),
            json!({"kind":"agent_status","agent_id":agent_id,"agent_key_id":"runtime_key-1"}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn circle_currents_reject_foreign_subjects_and_noncanonical_effective_time() {
        let circle_id = CircleId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [42; 32],
        ));
        let member_actor_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:member.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        for (selector, wire) in [
            (
                CurrentSelector::Circle {
                    circle_id: circle_id.clone(),
                },
                json!({"kind":"circle","circle_id":circle_id}),
            ),
            (
                CurrentSelector::CircleMemberState {
                    circle_id: circle_id.clone(),
                    member_actor_id: member_actor_id.clone(),
                },
                json!({"kind":"circle_member_state","circle_id":circle_id,"member_actor_id":member_actor_id}),
            ),
        ] {
            assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CurrentSelector>(wire).unwrap(),
                selector
            );
        }
        for invalid in [
            json!({"kind":"circle"}),
            json!({"kind":"circle","circle_id":member_actor_id}),
            json!({"kind":"circle","circle_id":circle_id,"member_actor_id":member_actor_id}),
            json!({"kind":"circle_member_state","circle_id":circle_id}),
            json!({"kind":"circle_member_state","circle_id":circle_id,"member_actor_id":member_actor_id,"realm_id":"extra"}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
        let current = json!({"membership":"join","effective_at":"2026-09-27T12:00:00.000Z"});
        let parsed = serde_json::from_value::<CircleMemberStateCurrent>(current.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), current);
        for invalid in [
            json!({"membership":"join"}),
            json!({"membership":"join","effective_at":"2026-09-27T12:00:00Z"}),
            json!({"membership":"join","effective_at":"2026-09-27T12:00:00.000Z","revision":1}),
        ] {
            assert!(
                serde_json::from_value::<CircleMemberStateCurrent>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn call_current_selector_requires_the_create_derived_call_identity() {
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [43; 32]);
        let call_id = CallId::from_event_id(&event);
        let value = json!({"kind":"call_state","call_id":call_id});
        let selector: CurrentSelector = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            selector,
            CurrentSelector::CallState {
                call_id: call_id.clone()
            }
        );
        assert_eq!(serde_json::to_value(selector).unwrap(), value);
        for invalid in [
            json!({"kind":"call_state"}),
            json!({"kind":"call_state","call_id":event}),
            json!({"kind":"call_state","call_id":call_id,"realm_id":"extra"}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[test]
    fn applet_registration_selector_has_one_closed_subject() {
        let wire = json!({"kind":"applet_registration","applet_id":"ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d"});
        let selector: CurrentSelector = serde_json::from_value(wire.clone()).unwrap();
        assert!(matches!(
            selector,
            CurrentSelector::AppletRegistration { .. }
        ));
        assert_eq!(serde_json::to_value(selector).unwrap(), wire);
        for invalid in [
            json!({"kind":"applet_registration"}),
            json!({"kind":"applet_registration","applet_id":"ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d","realm_id":"extra"}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[test]
    fn direct_conversation_binding_selector_has_only_pair_key() {
        let pair_key = Hash::new(format!("sha256:{}", "42".repeat(32))).unwrap();
        let selector = CurrentSelector::DirectConversationBinding {
            pair_key: pair_key.clone(),
        };
        let wire = json!({"kind":"direct_conversation_binding","pair_key":pair_key});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire.clone()).unwrap(),
            selector
        );
        for invalid in [
            json!({"kind":"direct_conversation_binding"}),
            json!({"kind":"direct_conversation_binding","pair_key":pair_key,"realm_id":"extra"}),
        ] {
            assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
        }
    }

    #[cfg(feature = "openapi")]
    #[test]
    fn current_selector_openapi_shape_uses_flat_branch_fields() {
        let mut components = salvo_oapi::Components::new();
        let schema = <CurrentSelector as salvo_oapi::ToSchema>::to_schema(&mut components);
        let rendered = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            rendered["$ref"],
            "#/components/schemas/arkret_wire.authority_commit.CurrentSelector"
        );
        let components = serde_json::to_value(components).unwrap();
        let selector = &components["schemas"]["arkret_wire.authority_commit.CurrentSelector"];
        let branches = selector["oneOf"].as_array().unwrap();
        let action = branches
            .iter()
            .find(|branch| branch["allOf"][2]["properties"]["kind"]["enum"][0] == "policy_action")
            .expect("policy_action selector branch");
        assert!(action.to_string().contains("PolicyActionSelector"));
        assert!(!action.to_string().contains("subject"));
        let action_branches =
            &components["schemas"]["arkret_wire.authority_commit.PolicyActionSelector"]["oneOf"];
        assert_eq!(
            action_branches[0]["properties"]["branch"]["enum"][0],
            "policy_ref"
        );
        assert_eq!(
            action_branches[1]["properties"]["branch"]["enum"][0],
            "realm_action"
        );
        for (kind, fields) in [
            ("device_authorization", 2),
            ("device_generation", 1),
            ("device_revocation_proposals", 2),
            ("invite_lifecycle", 2),
            ("invite_live_target", 2),
            ("invite_directed_invitee", 2),
            ("capability_grant", 2),
        ] {
            let branch = branches
                .iter()
                .find(|branch| branch["properties"]["kind"]["enum"][0] == kind)
                .unwrap_or_else(|| panic!("{kind} selector branch"));
            assert_eq!(branch["required"].as_array().unwrap().len(), fields);
            assert!(branch["properties"].get("account_id").is_none());
            assert!(branch["properties"].get("device_status").is_none());
        }
    }

    fn realm(seed: u8) -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [seed; 32],
        ))
    }

    fn signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
        DetachedObjectSignature {
            context,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new("did:web:station.example#key-1").unwrap(),
            signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            sig: Base64UrlString::new("AQ").unwrap(),
        }
    }

    fn circle_item(realm_id: RealmId, stream_position: u64) -> CommittedEventFullView {
        let circle_id = CircleId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x22; 32],
        ));
        let stream_ref = CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id,
        };
        let event = test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            match &stream_ref {
                CommitStreamRef::Circle {
                    realm_id,
                    circle_id,
                } => ScopeRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle_id.clone(),
                },
                _ => unreachable!(),
            },
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({}),
            Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        )
        .unwrap();
        CommittedEventFullView {
            commit: RealmCommit {
                commit_id: RealmCommitId::from_digest([stream_position as u8 + 1; 32]),
                realm_id,
                stream_ref,
                stream_position,
                previous_commit_ref: (stream_position > 0)
                    .then(|| RealmCommitId::from_digest([stream_position as u8; 32])),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x33; 32],
                )),
                committed_at: Utc.timestamp_opt(1_800_000_001, 0).unwrap(),
                signature: signature(DetachedSignatureContext::RealmCommit),
            },
            event,
        }
    }

    #[test]
    fn stream_row_rejects_a_commit_bound_to_another_independent_stream() {
        let realm_id = realm(0x10);
        let mut item = circle_item(realm_id.clone(), 0);
        item.commit.stream_ref = CommitStreamRef::Realm { realm_id };
        assert!(item.validate_shape().is_err());
    }

    #[test]
    fn scan_without_after_position_starts_at_that_streams_genesis() {
        let realm_id = realm(0x10);
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: circle_item(realm_id.clone(), 0).commit.stream_ref,
            direction: StreamScanDirection::After(None),
            limit: 10,
        };
        let outcome = StreamScanOutcome {
            committed_events: vec![CommittedEventView::Full(circle_item(realm_id, 1))],
            readable_floor: None,
            truncated: false,
        };
        assert!(outcome.validate_for_request(&request).is_err());
    }

    #[test]
    fn scan_request_has_exactly_one_present_direction_even_when_null() {
        let realm_id = realm(0x10);
        let stream_ref = circle_item(realm_id.clone(), 0).commit.stream_ref;
        for direction in [
            StreamScanDirection::After(None),
            StreamScanDirection::Before(None),
        ] {
            let request = StreamScanRequest {
                realm_id: realm_id.clone(),
                stream_ref: stream_ref.clone(),
                direction,
                limit: 3,
            };
            let wire = serde_json::to_value(&request).unwrap();
            assert_eq!(
                wire.get("after_position").is_some(),
                matches!(direction, StreamScanDirection::After(_))
            );
            assert_eq!(
                wire.get("before_position").is_some(),
                matches!(direction, StreamScanDirection::Before(_))
            );
            assert_eq!(
                serde_json::from_value::<StreamScanRequest>(wire).unwrap(),
                request
            );
        }
        let base = serde_json::to_value(StreamScanRequest {
            realm_id,
            stream_ref,
            direction: StreamScanDirection::After(None),
            limit: 3,
        })
        .unwrap();
        let mut both = base.clone();
        both["before_position"] = Value::Null;
        assert!(serde_json::from_value::<StreamScanRequest>(both).is_err());
        let mut neither = base.clone();
        neither.as_object_mut().unwrap().remove("after_position");
        assert!(serde_json::from_value::<StreamScanRequest>(neither).is_err());
        let mut unknown = base.clone();
        unknown["direction"] = serde_json::json!("after");
        assert!(serde_json::from_value::<StreamScanRequest>(unknown).is_err());
        let mut negative = base;
        negative["after_position"] = serde_json::json!(-1);
        assert!(serde_json::from_value::<StreamScanRequest>(negative).is_err());
    }

    #[test]
    fn before_scan_requires_descending_chain_and_verifiable_floor() {
        let realm_id = realm(0x10);
        let rows = [6, 5, 4]
            .map(|position| CommittedEventView::Full(circle_item(realm_id.clone(), position)));
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: rows[0].commit().stream_ref.clone(),
            direction: StreamScanDirection::Before(None),
            limit: 3,
        };
        let floor = ReadableFloor {
            oldest_position: 4,
            floor_commit_id: rows[2].commit().commit_id.clone(),
            floor_reason: ReadableFloorReason::MembershipJoin,
        };
        let outcome = StreamScanOutcome {
            committed_events: rows.to_vec(),
            readable_floor: Some(floor.clone()),
            truncated: false,
        };
        outcome.validate_for_request(&request).unwrap();
        let mut missing_floor = outcome.clone();
        missing_floor.readable_floor = None;
        assert!(missing_floor.validate_for_request(&request).is_err());
        let mut bad_anchor = outcome.clone();
        bad_anchor.readable_floor.as_mut().unwrap().floor_commit_id =
            rows[0].commit().commit_id.clone();
        assert!(bad_anchor.validate_for_request(&request).is_err());
        let mut false_truncation = outcome.clone();
        false_truncation.truncated = true;
        assert!(false_truncation.validate_for_request(&request).is_err());
        let mut ascending = outcome;
        ascending.committed_events.reverse();
        assert!(ascending.validate_for_request(&request).is_err());
        let forward = StreamScanRequest {
            direction: StreamScanDirection::After(None),
            ..request
        };
        let forward_page = StreamScanOutcome {
            committed_events: rows.into_iter().rev().collect(),
            readable_floor: Some(floor),
            truncated: true,
        };
        forward_page.validate_for_request(&forward).unwrap();
        let skipped = StreamScanRequest {
            direction: StreamScanDirection::After(Some(4)),
            ..forward
        };
        assert!(forward_page.validate_for_request(&skipped).is_err());
    }

    #[test]
    fn committed_event_view_has_only_full_and_withheld_wire_branches() {
        let full = circle_item(realm(0x10), 0);
        let full_value = serde_json::to_value(CommittedEventView::Full(full.clone())).unwrap();
        assert!(full_value.get("event").is_some());
        assert!(full_value.get("event_disclosure").is_none());

        let withheld = CommittedEventView::Withheld(CommittedEventWithheldView {
            commit: full.commit,
            event_disclosure: EventDisclosure {
                status: EventDisclosureStatus::Withheld,
            },
        });
        let withheld_value = serde_json::to_value(withheld).unwrap();
        assert_eq!(withheld_value["event_disclosure"]["status"], "withheld");
        assert!(withheld_value.get("event").is_none());

        let mut mixed = full_value;
        mixed["event_disclosure"] = json!({"status": "withheld"});
        assert!(serde_json::from_value::<CommittedEventView>(mixed).is_err());
        assert!(
            serde_json::from_value::<CommittedEventView>(json!({
                "commit": withheld_value["commit"].clone(),
                "redacted": true
            }))
            .is_err()
        );
    }

    /// The domain label and the serialized wire string are the same fact. If
    /// they ever diverge, a signature made over the label would not cover the
    /// context the object actually carries.
    #[test]
    fn every_signature_context_label_is_its_own_wire_string() {
        for context in DetachedSignatureContext::ALL {
            let encoded = serde_json::to_value(context).unwrap();
            assert_eq!(encoded.as_str().unwrap(), context.as_wire_str());
            let decoded: DetachedSignatureContext =
                serde_json::from_value(serde_json::json!(context.as_wire_str())).unwrap();
            assert_eq!(decoded, context);
        }
    }

    #[test]
    fn approval_time_uses_the_generated_future_only_boundary() {
        let verification_time = Utc.timestamp_millis_opt(1_800_000_000_000).unwrap();
        let tolerance = arkret_identifiers::protocol_time_tolerance_scenario_descriptor(
            arkret_identifiers::ProtocolTimeToleranceScenario::ApprovalApprovedAt,
        )
        .tolerance_ms();
        let boundary = verification_time + TimeDelta::milliseconds(tolerance);

        validate_approval_timestamp(boundary, verification_time).unwrap();
        validate_approval_timestamp(boundary - TimeDelta::milliseconds(1), verification_time)
            .unwrap();
        assert!(
            validate_approval_timestamp(boundary + TimeDelta::milliseconds(1), verification_time)
                .is_err()
        );

        // This scenario is future-only: it must not accidentally inherit the
        // symmetric expiry lower bound used by temporal constraints.
        validate_approval_timestamp(verification_time - TimeDelta::days(365), verification_time)
            .unwrap();
    }

    #[test]
    fn realm_stream_list_enforces_order_floor_and_continuation() {
        let realm_id: RealmId = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
            .parse()
            .unwrap();
        let head: RealmCommitId = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
            .parse()
            .unwrap();
        let realm_row = RealmStreamRow {
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            head_commit_ref: head.clone(),
            next_position: 3,
            readable_floor: Some(ReadableFloor {
                oldest_position: 0,
                floor_commit_id: head.clone(),
                floor_reason: ReadableFloorReason::StreamStart,
            }),
        };
        let page = RealmStreamList {
            realm_id: realm_id.clone(),
            streams: vec![realm_row.clone()],
            next_cursor: None,
            has_more: false,
        };
        page.validate().unwrap();
        let wire = serde_json::to_value(&page).unwrap();
        assert!(wire.get("next_cursor").is_none());
        assert_eq!(
            serde_json::from_value::<RealmStreamList>(wire.clone()).unwrap(),
            page
        );
        let mut unknown = wire;
        unknown["unexpected"] = json!(true);
        assert!(serde_json::from_value::<RealmStreamList>(unknown).is_err());

        let mut dangling = page.clone();
        dangling.has_more = true;
        assert!(dangling.validate().is_err());
        dangling.next_cursor = Some("ak:cursor:AAAAAAAAAAAAAAAAAAAAAA".to_owned());
        dangling.validate().unwrap();
        dangling.next_cursor = Some("cursor".to_owned());
        assert!(dangling.validate().is_err());

        let mut empty_chain = page.clone();
        empty_chain.streams[0].next_position = 0;
        assert!(empty_chain.validate().is_err());

        let mut floor_past_head = page.clone();
        floor_past_head.streams[0].readable_floor = Some(ReadableFloor {
            oldest_position: 3,
            floor_commit_id: head.clone(),
            floor_reason: ReadableFloorReason::MembershipJoin,
        });
        assert!(floor_past_head.validate().is_err());

        let circle_row = RealmStreamRow {
            stream_ref: CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: "ak:circle:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                    .parse()
                    .unwrap(),
            },
            head_commit_ref: head,
            next_position: 1,
            readable_floor: None,
        };
        let mut ordered = page.clone();
        ordered.streams = vec![circle_row.clone(), realm_row.clone()];
        let first = canonical_json_bytes_for_test(&ordered.streams[0].stream_ref);
        let second = canonical_json_bytes_for_test(&ordered.streams[1].stream_ref);
        if first > second {
            ordered.streams.reverse();
        }
        ordered.validate().unwrap();
        let mut reversed = ordered.clone();
        reversed.streams.reverse();
        assert!(reversed.validate().is_err());
        let mut duplicated = page.clone();
        duplicated.streams = vec![realm_row.clone(), realm_row];
        assert!(duplicated.validate().is_err());

        let mut foreign = page;
        foreign.realm_id = "ak:realm:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
            .parse()
            .unwrap();
        assert!(foreign.validate().is_err());
    }

    fn canonical_json_bytes_for_test(value: &CommitStreamRef) -> Vec<u8> {
        arkret_canonical::canonical::canonical_json_bytes(value).unwrap()
    }

    #[test]
    fn list_wip_approval_context_is_closed_and_revision_bound() {
        let list = SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let revision = CurrentRevision {
            commit_id: RealmCommitId::from_digest([7; 32]),
            stream_position: 9,
        };
        let context = ApprovalContext::ListWip {
            list_space_id: list.clone(),
            list_policy_revision: revision.clone(),
        };
        let wire =
            json!({"context_kind":"list_wip","list_space_id":list,"list_policy_revision":revision});
        assert_eq!(serde_json::to_value(&context).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<ApprovalContext>(wire.clone()).unwrap(),
            context
        );
        for invalid in [
            json!({"context_kind":"list_wip","list_space_id":list}),
            json!({"context_kind":"list_wip","list_space_id":list,"list_policy_revision":revision,"grant_id":"ak:grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
            json!({"context_kind":"realm_governance","list_space_id":list,"list_policy_revision":revision}),
        ] {
            assert!(
                serde_json::from_value::<ApprovalContext>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }

        let realm = RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let event = test_support::raw_event_at(
            EventKind::StrandMove.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({"target_space_id":list}),
            at,
        )
        .unwrap();
        let input = ApprovalSignatureInput {
            approval_context: context,
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            operation: "ak.self.events.command.submit.v1".to_owned(),
            action: CapabilityActionId::StrandMove,
            realm_id: realm,
            initiating_actor_id: event.actor_id.clone(),
            approver_did: Did::new("did:web:manager.example".to_owned()).unwrap(),
            approved_at: at,
            nonce: "ABCDEFGHIJKLMNOPQRSTUV".to_owned(),
        };
        assert!(
            input
                .validate_list_wip_binding(
                    &event,
                    "ak.self.events.command.submit.v1",
                    &list,
                    &revision
                )
                .is_ok()
        );
        assert!(
            input
                .validate_list_wip_binding(
                    &event,
                    "ak.self.events.command.submit.v1",
                    &list,
                    &CurrentRevision {
                        stream_position: 10,
                        ..revision
                    }
                )
                .is_err()
        );
    }
}
