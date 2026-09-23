//! Single-authority commit-log wire types.
//!
//! A Realm, each Circle, and each Sidecar own separate linear streams. There
//! is deliberately no Realm-global position or ordering across those streams.

use arkret_identifiers::{
    CircleId, Did, DidCoreId, EventId, GrantId, Hash, KeypackageClaimId, MlsWelcomeDeliveryId,
    PolicyId, RealmAuthorityHandoffId, RealmCommitId, RealmId, RealmSnapshotId, SidecarId,
    StrandId,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    ActorId, AgentKeyId, Base64UrlString, CapabilityActionId, DeviceId, DidUrl, Event,
    HistoryAccess, MimiRoomUri, Result, ScopeRef, WireError,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "context_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalContext {
    Grant { grant_id: GrantId },
    RealmGovernance,
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
        D: serde::Deserializer<'de>,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentSelector {
    RealmProfile,
    RealmPolicy,
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
    MessageReactions {
        event_id: EventId,
    },
    MlsGroup {
        scope_ref: ScopeRef,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FlatCurrentSelector {
    RealmProfile,
    RealmPolicy,
    DeviceAuthorization {
        device_id: DeviceId,
    },
    DeviceRevocationProposals {
        device_id: DeviceId,
    },
    MemberState {
        actor_id: ActorId,
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
    MessageReactions {
        event_id: EventId,
    },
    MlsGroup {
        scope_ref: ScopeRef,
    },
}

impl<'de> Deserialize<'de> for CurrentSelector {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
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
            _ => {
                let flat = serde_json::from_value::<FlatCurrentSelector>(Value::Object(wire))
                    .map_err(serde::de::Error::custom)?;
                Ok(match flat {
                    FlatCurrentSelector::RealmProfile => Self::RealmProfile,
                    FlatCurrentSelector::RealmPolicy => Self::RealmPolicy,
                    FlatCurrentSelector::DeviceAuthorization { device_id } => {
                        Self::DeviceAuthorization { device_id }
                    }
                    FlatCurrentSelector::DeviceRevocationProposals { device_id } => {
                        Self::DeviceRevocationProposals { device_id }
                    }
                    FlatCurrentSelector::MemberState { actor_id } => Self::MemberState { actor_id },
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
                    FlatCurrentSelector::MessageReactions { event_id } => {
                        Self::MessageReactions { event_id }
                    }
                    FlatCurrentSelector::MlsGroup { scope_ref } => Self::MlsGroup { scope_ref },
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
        D: serde::Deserializer<'de>,
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
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

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
        revision: CurrentRevision,
        value: Value,
    },
    MessageReactions {
        selector: CurrentSelector,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamScanRequest {
    pub realm_id: RealmId,
    pub stream_ref: CommitStreamRef,
    pub after_position: Option<u64>,
    pub limit: u16,
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
    pub truncated: bool,
}

impl StreamScanOutcome {
    pub fn validate_for_request(&self, request: &StreamScanRequest) -> Result<()> {
        request.validate()?;
        if self.committed_events.len() > usize::from(request.limit) {
            return Err(WireError::Protocol(
                "stream scan returned more items than requested".to_owned(),
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
            let expected_first_position = request
                .after_position
                .map_or(0, |position| position.saturating_add(1));
            if first.commit().stream_position != expected_first_position {
                return Err(WireError::Protocol(
                    "stream scan did not start at genesis or immediately after after_position"
                        .to_owned(),
                ));
            }
        }
        for pair in self.committed_events.windows(2) {
            pair[1].commit().validate_successor_of(pair[0].commit())?;
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
        let action = &selector["oneOf"][3];
        assert_eq!(
            action["allOf"][2]["properties"]["kind"]["enum"][0],
            "policy_action"
        );
        assert!(action.to_string().contains("PolicyActionSelector"));
        assert!(!action.to_string().contains("subject"));
        let branches =
            &components["schemas"]["arkret_wire.authority_commit.PolicyActionSelector"]["oneOf"];
        assert_eq!(branches[0]["properties"]["branch"]["enum"][0], "policy_ref");
        assert_eq!(
            branches[1]["properties"]["branch"]["enum"][0],
            "realm_action"
        );
        for (index, kind, fields) in [
            (4, "device_authorization", 2),
            (5, "device_generation", 1),
            (6, "device_revocation_proposals", 2),
        ] {
            let branch = &selector["oneOf"][index];
            assert_eq!(branch["properties"]["kind"]["enum"][0], kind);
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
            after_position: None,
            limit: 10,
        };
        let outcome = StreamScanOutcome {
            committed_events: vec![CommittedEventView::Full(circle_item(realm_id, 1))],
            truncated: false,
        };
        assert!(outcome.validate_for_request(&request).is_err());
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
}
