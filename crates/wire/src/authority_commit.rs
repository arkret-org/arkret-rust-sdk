//! Single-authority commit-log wire types.
//!
//! A Realm, each Circle, and each Sidecar own separate linear streams. There
//! is deliberately no Realm-global position or ordering across those streams.

use arkret_identifiers::{
    ActorProfileId, AppletId, CallId, CircleId, Did, DidCoreId, EventId, GrantId, Hash, InviteId,
    KeypackageClaimId, MessageId, MlsWelcomeDeliveryId, PolicyId, RealmAuthorityHandoffId,
    RealmCommitId, RealmId, RealmSnapshotId, RelationId, SidecarId, SpaceId, StrandId,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

/// A Pin projection home; this does not define a security boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinScope {
    Strand { id: StrandId },
    Realm { id: RealmId },
    Circle { id: CircleId },
    Space { id: SpaceId },
}

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
    RealmControl {
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
            | Self::RealmControl { realm_id }
            | Self::Circle { realm_id, .. }
            | Self::Sidecar { realm_id, .. } => realm_id,
        }
    }

    /// The resource scope of this independent stream. Authenticate the
    /// accepted stream source before using this structural projection.
    pub fn scope_ref(&self) -> ScopeRef {
        match self {
            Self::Realm { realm_id } => ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            Self::RealmControl { realm_id } => ScopeRef::RealmControl {
                realm_id: realm_id.clone(),
            },
            Self::Circle {
                realm_id,
                circle_id,
            } => ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            },
            Self::Sidecar {
                realm_id,
                sidecar_id,
            } => ScopeRef::Sidecar {
                realm_id: realm_id.clone(),
                sidecar_id: sidecar_id.clone(),
            },
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
            ScopeRef::RealmControl { realm_id } => Ok(Self::RealmControl {
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
    #[serde(rename = "ak.realm_actor_creation_signature.v1")]
    RealmActorCreation,
    #[serde(rename = "ak.realm_actor_control_acceptance_signature.v1")]
    RealmActorControlAcceptance,
    #[serde(rename = "ak.realm_actor_manager_acceptance_signature.v1")]
    RealmActorManagerAcceptance,
    #[serde(rename = "ak.realm_actor_recovery_acceptance_signature.v1")]
    RealmActorRecoveryAcceptance,
    #[serde(rename = "ak.realm_actor_material_signature.v1")]
    RealmActorMaterial,
}

impl DetachedSignatureContext {
    /// The wire string this context serializes to. It is also the domain
    /// separation label of the signature transcript, so a signature made for
    /// one context can never verify under another.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::RealmActorCreation => {
                crate::DomainSeparationId::REALM_ACTOR_CREATION_SIGNATURE_V1
            }
            Self::RealmActorControlAcceptance => {
                crate::DomainSeparationId::REALM_ACTOR_CONTROL_ACCEPTANCE_SIGNATURE_V1
            }
            Self::RealmActorManagerAcceptance => {
                crate::DomainSeparationId::REALM_ACTOR_MANAGER_ACCEPTANCE_SIGNATURE_V1
            }
            Self::RealmActorRecoveryAcceptance => {
                crate::DomainSeparationId::REALM_ACTOR_RECOVERY_ACCEPTANCE_SIGNATURE_V1
            }
            Self::RealmActorMaterial => {
                crate::DomainSeparationId::REALM_ACTOR_MATERIAL_SIGNATURE_V1
            }
            Self::RealmCommit => crate::DomainSeparationId::REALM_COMMIT_SIGNATURE_V1,
            Self::RealmAuthorityHandoffOld => {
                crate::DomainSeparationId::REALM_AUTHORITY_HANDOFF_OLD_SIGNATURE_V1
            }
            Self::RealmAuthorityHandoffNewAcceptance => {
                crate::DomainSeparationId::REALM_AUTHORITY_HANDOFF_NEW_ACCEPTANCE_SIGNATURE_V1
            }
            Self::RealmAuthorityCurrentAssertion => {
                crate::DomainSeparationId::REALM_AUTHORITY_CURRENT_ASSERTION_SIGNATURE_V1
            }
            Self::RealmSnapshot => crate::DomainSeparationId::REALM_SNAPSHOT_SIGNATURE_V1,
            Self::MlsWelcomeDelivery => {
                crate::DomainSeparationId::MLS_WELCOME_DELIVERY_SIGNATURE_V1
            }
        }
    }

    /// Every context the closed enum admits, in declaration order.
    pub const ALL: [Self; 11] = [
        Self::RealmCommit,
        Self::RealmAuthorityHandoffOld,
        Self::RealmAuthorityHandoffNewAcceptance,
        Self::RealmAuthorityCurrentAssertion,
        Self::RealmSnapshot,
        Self::MlsWelcomeDelivery,
        Self::RealmActorCreation,
        Self::RealmActorControlAcceptance,
        Self::RealmActorManagerAcceptance,
        Self::RealmActorRecoveryAcceptance,
        Self::RealmActorMaterial,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarMetadataContext {
    pub source: CommittedEventRef,
    pub event_kind: crate::EventKind,
    pub signer_id: ActorId,
    pub payload_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarScheduleSourceValue {
    pub effective_scope: ScopeRef,
    #[serde(deserialize_with = "deserialize_required_calendar_nullable")]
    pub source: Option<CommittedEventRef>,
    pub strand_revision: CurrentRevision,
    #[serde(deserialize_with = "deserialize_required_calendar_nullable")]
    pub metadata_context: Option<CalendarMetadataContext>,
}

fn deserialize_required_calendar_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl CalendarScheduleSourceValue {
    pub fn validate_for_current(
        &self,
        realm: &RealmId,
        stream: &CommitStreamRef,
        revision: &CurrentRevision,
    ) -> Result<()> {
        if self.strand_revision != *revision
            || self.effective_scope.realm_id_opt() != Some(realm)
            || CommitStreamRef::from_scope(&self.effective_scope, None)? != *stream
        {
            return Err(WireError::Protocol(
                "Calendar source differs from its paired Strand cut".into(),
            ));
        }
        for source in self
            .source
            .iter()
            .chain(self.metadata_context.iter().map(|context| &context.source))
        {
            if source.stream_ref != *stream
                || source.stream_position > revision.stream_position
                || (source.stream_position == revision.stream_position
                    && source.commit_id != revision.commit_id)
            {
                return Err(WireError::Protocol(
                    "Calendar source is outside its current stream cut".into(),
                ));
            }
        }
        if revision.stream_position > 9_007_199_254_740_991 {
            return Err(WireError::Protocol(
                "Calendar revision exceeds the v1 integer range".into(),
            ));
        }
        if let Some(context) = &self.metadata_context {
            context.signer_id.validate()?;
        }
        if let Some(context) = &self.metadata_context
            && (!matches!(
                context.event_kind,
                crate::EventKind::StrandCreate | crate::EventKind::StrandUpdate
            ) || self.source.as_ref() != Some(&context.source))
        {
            return Err(WireError::Protocol(
                "Calendar metadata context does not name the eligible encryption source".into(),
            ));
        }
        Ok(())
    }
}

impl RealmAuthorityRootValue {
    pub fn validate(&self) -> Result<()> {
        const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
        if self.controller_epoch > MAX_SAFE_INTEGER || self.authority_generation > MAX_SAFE_INTEGER
        {
            return Err(WireError::Protocol(
                "authority root counter exceeds the v1 integer range".into(),
            ));
        }
        Ok(())
    }
}

impl RealmCommit {
    /// Re-derive the original content address without resolving its signer.
    /// This is required by both native auditors and own-Station consumers;
    /// it does not authenticate the governing signature or establish authority.
    pub fn validate_content_address(&self) -> Result<()> {
        self.validate_shape()?;
        let bytes = self.canonical_id_bytes()?;
        if self.commit_id != RealmCommitId::from_digest(crate::canonical::sha256_bytes(&bytes)) {
            return Err(WireError::Protocol(
                "RealmCommit ID differs from its canonical content".to_owned(),
            ));
        }
        Ok(())
    }

    /// The one canonical body used to derive a RealmCommit content address.
    pub fn canonical_id_bytes(&self) -> Result<Vec<u8>> {
        let mut body = serde_json::to_value(self)?;
        let object = body.as_object_mut().ok_or_else(|| {
            WireError::Protocol("RealmCommit identity is not an object".to_owned())
        })?;
        object.remove("commit_id");
        object.remove("signature");
        Ok(crate::canonical::canonical_json_bytes(&body)?)
    }

    /// Compatibility name for the one canonical content-address verifier.
    pub fn verify_commit_id_matches_content(&self) -> Result<()> {
        self.validate_content_address()
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self
            .producer_signer_fact_digest
            .as_ref()
            .is_some_and(|digest| !digest.as_str().starts_with("sha256:"))
        {
            return Err(WireError::Protocol(
                "Human signer fact digest requires fixed SHA256".into(),
            ));
        }
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
        let expected = previous.stream_position.checked_add(1).ok_or_else(|| {
            WireError::Protocol("RealmCommit predecessor position overflows".to_owned())
        })?;
        if self.stream_position > expected {
            return Err(WireError::StreamPositionGap {
                stream_ref: self.stream_ref.clone(),
                expected,
                actual: self.stream_position,
            });
        }
        if self.stream_position != expected {
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

impl RealmAuthorityHandoff {
    pub fn validate_shape(&self) -> Result<()> {
        if self
            .pcr_private_state_digest
            .as_ref()
            .is_some_and(|digest| !digest.as_str().starts_with("sha256:"))
        {
            return Err(WireError::Protocol(
                "PCR private state digest requires fixed SHA256".into(),
            ));
        }
        if self
            .historical_signer_facts_digest
            .as_ref()
            .is_some_and(|digest| !digest.as_str().starts_with("sha256:"))
        {
            return Err(WireError::Protocol(
                "handoff signer inventory digest requires fixed SHA256".into(),
            ));
        }
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

/// Extract the signature method controller's Service ID; this does not verify its authority or
/// signature.
pub fn detached_signature_service_id(signature: &DetachedObjectSignature) -> Result<DidCoreId> {
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

/// A restriction derived from the immutable genesis original, not an authority
/// grant. Callers must independently verify the native admission and its complete
/// accepted closure before using a non-Human branch to permit an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenesisGovernance {
    Human(AccountId),
    Organization,
    Agent(AccountId),
    Collaboration,
    DirectConversation(DidCoreId),
}

impl GenesisGovernance {
    pub fn from_genesis(event: &Event) -> Result<Self> {
        if event.kind != crate::EventKind::RealmCreate {
            return Err(WireError::Protocol(
                "governance requires the original Realm genesis".into(),
            ));
        }
        let payload = serde_json::to_value(&event.payload)?;
        let purpose = payload.pointer("/object/purpose").and_then(Value::as_str);
        let executor_pair = (
            event.executed_by.is_some(),
            event.authorization_ref.is_some(),
        );
        match (purpose, executor_pair) {
            (Some("principal_control"), (false, false)) => {
                let account = event.actor_id.as_account_id().ok_or_else(|| {
                    WireError::Protocol(
                        "Human registration genesis requires a complete Account actor".into(),
                    )
                })?;
                if payload
                    .pointer("/object/governance_station_id")
                    .and_then(Value::as_str)
                    != Some(account.station_id.as_str())
                {
                    return Err(WireError::Protocol("failed_precondition: Human PCR genesis governor differs from its account Station".into()));
                }
                Ok(Self::Human(account.clone()))
            }
            (Some("principal_control"), (true, true)) => Ok(Self::Organization),
            (Some("agent_control"), (true, true)) => {
                let account = event.actor_id.as_account_id().ok_or_else(|| {
                    WireError::Protocol(
                        "failed_precondition: Agent PCR requires a complete Account actor".into(),
                    )
                })?;
                let controller = event
                    .executed_by
                    .as_ref()
                    .and_then(ActorId::as_account_id)
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "failed_precondition: Agent PCR requires a complete controller Account"
                                .into(),
                        )
                    })?;
                if account.principal_id == controller.principal_id
                    || account.station_id != controller.station_id
                    || payload
                        .pointer("/object/governance_station_id")
                        .and_then(Value::as_str)
                        != Some(account.station_id.as_str())
                {
                    return Err(WireError::Protocol("failed_precondition: Agent PCR genesis and controller must share the original account Station".into()));
                }
                Ok(Self::Agent(account.clone()))
            }
            (Some("collaboration"), _) => Ok(Self::Collaboration),
            (Some("direct_conversation"), _) => {
                let station = payload
                    .pointer("/object/governance_station_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "failed_precondition: Direct genesis has no governing Station".into(),
                        )
                    })?;
                Ok(Self::DirectConversation(DidCoreId::new(station)?))
            }
            _ => Err(WireError::Protocol(
                "failed_precondition: Realm genesis governance provenance is unresolved".into(),
            )),
        }
    }

    pub fn is_human(&self) -> bool {
        matches!(self, Self::Human(_))
    }

    pub fn is_principal_control(&self) -> bool {
        matches!(self, Self::Human(_) | Self::Organization | Self::Agent(_))
    }

    pub fn validate_current(&self, service: &DidCoreId, generation: u64) -> Result<()> {
        if let Self::Human(account) = self
            && (service != &account.station_id || generation != 0)
        {
            return Err(WireError::Protocol(
                "failed_precondition: Human PCR remains at its account Station and initial tenure"
                    .into(),
            ));
        }
        if let Self::DirectConversation(station) = self
            && (service != station || generation != 0)
        {
            return Err(WireError::Protocol(
                "failed_precondition: Direct Conversation remains at its genesis Station and initial tenure".into(),
            ));
        }
        if let Self::Agent(account) = self
            && (service != &account.station_id || generation != 0)
        {
            return Err(WireError::Protocol(
                "failed_precondition: Agent PCR remains at its account Station and initial tenure"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn require_transferable(&self) -> Result<()> {
        if self.is_human() {
            return Err(WireError::Protocol(
                "failed_precondition: Human PCR cannot independently transfer governance".into(),
            ));
        }
        if matches!(self, Self::DirectConversation(_)) {
            return Err(WireError::Protocol(
                "failed_precondition: Direct Conversation governance cannot transfer".into(),
            ));
        }
        if matches!(self, Self::Agent(_)) {
            return Err(WireError::Protocol(
                "failed_precondition: Agent PCR cannot independently transfer governance".into(),
            ));
        }
        Ok(())
    }
}

impl RealmAuthorityBundle {
    /// Validate the closed public handoff chain and the nonce-bound current
    /// assertion shape. Cryptographic verification and freshness are caller
    /// responsibilities and must fail closed.
    pub fn validate_shape(&self) -> Result<()> {
        if self.genesis_event.scope_ref != ScopeRef::RealmGenesis
            || RealmId::from_event_id(&self.genesis_event.event_id) != self.realm_id
        {
            return Err(WireError::Protocol(
                "genesis original does not derive this Realm".into(),
            ));
        }
        let governance = GenesisGovernance::from_genesis(&self.genesis_event)?;
        governance.validate_current(&self.current_service_id, self.current_generation)?;
        if !self.authority_transitions.is_empty() {
            governance.require_transferable()?;
        }
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
        let private_control = governance.is_principal_control();
        for transition in &self.authority_transitions {
            transition.validate_shape()?;
            if transition.handoff.pcr_private_state_digest.is_some() != private_control {
                return Err(WireError::Protocol(
                    "handoff private state commitment applicability differs from inception purpose"
                        .into(),
                ));
            }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmSnapshotPurpose {
    FullRecovery,
    StreamHistory,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSnapshotHistoryBasis {
    pub account_id: AccountId,
    pub stream_ref: CommitStreamRef,
    pub anchor_position: u64,
    pub anchor_commit_ref: RealmCommitId,
    pub accepted_dependency_refs: Vec<CommittedEventRef>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmStateSnapshot {
    pub snapshot_id: RealmSnapshotId,
    pub realm_id: RealmId,
    pub governance_generation: u64,
    pub purpose: RealmSnapshotPurpose,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub history_basis: Option<RealmSnapshotHistoryBasis>,
    pub visible_stream_heads: Vec<CommitStreamHead>,
    pub current_state_entries: Vec<TypedCurrentRow>,
    pub retention_and_history_floor: RetentionAndHistoryFloor,
    #[serde(serialize_with = "crate::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub signature: DetachedObjectSignature,
}

impl RealmStateSnapshot {
    pub fn require_full_recovery(&self) -> Result<()> {
        self.validate_purpose()?;
        if self.purpose != RealmSnapshotPurpose::FullRecovery {
            return Err(WireError::Protocol(
                "historical basis cannot replace current state".into(),
            ));
        }
        Ok(())
    }

    /// Validate signed purpose, exact selector coverage and dependency closure.
    /// Source completeness at the declared cut remains the governor's duty.
    pub fn validate_purpose(&self) -> Result<()> {
        let reject = || WireError::Protocol("snapshot purpose or history coverage mismatch".into());
        let basis = match (&self.purpose, &self.history_basis) {
            (RealmSnapshotPurpose::FullRecovery, None) => return Ok(()),
            (RealmSnapshotPurpose::StreamHistory, Some(basis)) => basis,
            _ => return Err(reject()),
        };
        basis.account_id.validate()?;
        if basis.stream_ref.realm_id() != &self.realm_id {
            return Err(reject());
        }
        let target = self
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == basis.stream_ref)
            .ok_or_else(reject)?;
        if target.stream_position != basis.anchor_position
            || target.commit_id != basis.anchor_commit_ref
        {
            return Err(reject());
        }
        let realm = CommitStreamRef::Realm {
            realm_id: self.realm_id.clone(),
        };
        let parent = match &basis.stream_ref {
            CommitStreamRef::Realm { .. } => None,
            CommitStreamRef::Circle { circle_id, .. } => Some(CurrentSelector::Circle {
                circle_id: circle_id.clone(),
            }),
            CommitStreamRef::Sidecar { sidecar_id, .. } => Some(CurrentSelector::Sidecar {
                sidecar_id: sidecar_id.clone(),
            }),
            _ => return Err(reject()),
        };
        let member = CurrentSelector::MemberState {
            actor_id: ActorId::account(basis.account_id.clone()),
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut sources = std::collections::BTreeSet::from([basis.stream_ref.clone()]);
        let mut dependencies = Vec::new();
        let mut parent_seen = false;
        let mut member_seen = false;
        for row in &self.current_state_entries {
            let TypedCurrentRow::Value {
                selector,
                source_stream_ref,
                revision,
                ..
            } = row;
            if !seen.insert(crate::canonical::canonical_json_bytes(selector)?) {
                return Err(reject());
            }
            if source_stream_ref == &basis.stream_ref {
                if matches!(
                    selector,
                    CurrentSelector::Circle { .. } | CurrentSelector::Sidecar { .. }
                ) {
                    return Err(reject());
                }
                continue;
            }
            if parent.is_none()
                || source_stream_ref != &realm
                || (Some(selector) != parent.as_ref() && selector != &member)
            {
                return Err(reject());
            }
            parent_seen |= Some(selector) == parent.as_ref();
            member_seen |= selector == &member;
            sources.insert(source_stream_ref.clone());
            let matching: Vec<_> = basis
                .accepted_dependency_refs
                .iter()
                .filter(|dep| {
                    dep.stream_ref == *source_stream_ref
                        && dep.commit_id == revision.commit_id
                        && dep.stream_position == revision.stream_position
                })
                .collect();
            if matching.len() != 1 {
                return Err(reject());
            }
            if !dependencies.contains(matching[0]) {
                dependencies.push(matching[0].clone());
            }
        }
        dependencies.sort();
        let heads: std::collections::BTreeSet<_> = self
            .visible_stream_heads
            .iter()
            .map(|h| h.stream_ref.clone())
            .collect();
        let floors: std::collections::BTreeSet<_> = self
            .retention_and_history_floor
            .stream_floors
            .iter()
            .map(|f| f.stream_ref.clone())
            .collect();
        if (parent.is_some() && (!parent_seen || !member_seen))
            || dependencies != basis.accepted_dependency_refs
            || heads != sources
            || floors != sources
            || heads.len() != self.visible_stream_heads.len()
            || floors.len() != self.retention_and_history_floor.stream_floors.len()
        {
            return Err(reject());
        }
        Ok(())
    }

    /// The exact typed revision of `member`'s current parent Realm
    /// `member_state` join in this snapshot's cut -- the value a Circle join
    /// signs as `parent_membership_revision` (`zh/models/circle.md` section
    /// 9.1). `None` unless that current is `join` on this Realm's stream.
    pub fn parent_membership_revision(&self, member: &ActorId) -> Option<CurrentRevision> {
        self.current_state_entries
            .iter()
            .find_map(|entry| entry.parent_membership_revision(&self.realm_id, member))
    }
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_approval_signatures"
    )]
    pub approval_signatures: Option<Vec<ApprovalSignature>>,
}

// The registered carrier permits absence or an array, never explicit null.
// Missing members use the field default; present members must decode as Vec.
fn deserialize_present_approval_signatures<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<ApprovalSignature>>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<ApprovalSignature>::deserialize(deserializer).map(Some)
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
    Management {
        management_operation: crate::ManagementOperation,
        effective_scope: ScopeRef,
        request_id: String,
    },
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

impl ApprovalSignature {
    /// Complete shape checks not already enforced by the closed serde carriers
    /// and typed IDs in approval-signature.schema.json. This establishes no
    /// signature, historical control, voting qualification, or consumed nonce.
    pub fn validate(&self) -> Result<()> {
        if !(22..=256).contains(&self.input.nonce.chars().count()) {
            return Err(WireError::Protocol(
                "approval nonce must contain 22..=256 characters".into(),
            ));
        }
        if self.input.request_canonical_digest.digest_suite()?
            != arkret_canonical::DigestSuite::Sha256
        {
            return Err(WireError::Protocol(
                "approval request digest must use SHA-256".into(),
            ));
        }
        if crate::ServiceOperationId::from_wire(&self.input.operation).is_none() {
            return Err(WireError::Protocol(
                "approval operation is not registered".into(),
            ));
        }
        if self.input.approval_target == ApprovalTarget::Operation
            && !matches!(
                self.input.operation.as_str(),
                crate::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1
                    | crate::ServiceOperationId::SELF_APPLET_CONFIGURATION_COMMAND_SUBMIT_V1
            )
        {
            return Err(WireError::Protocol(
                "approval operation target has no registered evidence carrier".into(),
            ));
        }
        if !crate::is_compact_detached_jws(&self.proof.jws) {
            return Err(WireError::Protocol(
                "approval proof must be compact detached JWS".into(),
            ));
        }
        arkret_canonical::canonical::validate_timestamp_canonical(
            &arkret_canonical::canonical::format_timestamp_canonical(self.input.approved_at),
        )?;
        // Existing canonical numeric validation also checks a directly
        // constructed List current revision before it can be signed.
        arkret_canonical::canonical::canonical_json_bytes(self)?;
        Ok(())
    }
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
        if !GenesisGovernance::from_genesis(create)?.is_human() {
            return Err(WireError::Protocol(
                "registration-anchor unit is not a Human genesis".into(),
            ));
        }
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

/// Closed source identity of a native Sidecar context current result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarContextRef {
    Relation { relation_id: RelationId },
    Strand { strand_id: StrandId },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmActorStatusGate {
    Owner,
    Governance,
}

fn deserialize_realm_actor_selector<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<ActorId, D::Error> {
    let actor = ActorId::deserialize(deserializer)?;
    if actor.as_realm_actor_id().is_none() {
        return Err(serde::de::Error::custom(
            "Realm actor selector requires a Realm ActorId",
        ));
    }
    actor.validate().map_err(serde::de::Error::custom)?;
    Ok(actor)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentSelector {
    RealmActorIdentity {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorControl {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorManager {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorStatus {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
        gate: RealmActorStatusGate,
    },
    RealmActorDeviceGeneration {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorDeviceAuthorization {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
        device_id: DeviceId,
    },
    RealmActorDeviceRevocationProposals {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
        device_id: DeviceId,
    },
    RealmActorProfile {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorRecovery {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    Sidecar {
        sidecar_id: SidecarId,
    },
    SidecarContext {
        sidecar_id: SidecarId,
        source_context_ref: SidecarContextRef,
    },
    AgentSidecarExchangeControls {
        sidecar_id: SidecarId,
        source_context_ref: SidecarContextRef,
    },
    RealmGenesis,
    AppletRegistration {
        applet_id: AppletId,
        service_id: DidCoreId,
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
    RealmPreviewPolicy,
    ScopeReadReceiptPolicy {
        #[serde(deserialize_with = "deserialize_read_receipt_policy_scope")]
        scope_ref: ScopeRef,
    },
    RealmTombstone,
    RealmArchive,
    RealmFreeze,
    RealmDiscovery,
    RealmAlias,
    RealmPlaintextVisibleServices,
    RealmSetDefaultStrand,
    Policy {
        policy_id: PolicyId,
    },
    SchemaDefinition {
        schema_id: String,
    },
    Pin {
        pin_scope: PinScope,
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
    AgentInteraction {
        agent_account_id: AccountId,
    },
    AgentActionApproval {
        approval_id: String,
    },
    MimiRoomBinding {
        mimi_room_uri: MimiRoomUri,
    },
    Strand {
        strand_id: StrandId,
    },
    /// One Calendar event occurrence and responder's complete RSVP entry.
    CalendarScheduleSource {
        strand_id: StrandId,
    },
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
    /// The reacted-to object: a reaction set is keyed per target and the
    /// payload carries no other target field
    /// (`typed-current-result.schema.json#/$defs/message_reactions_result`).
    MessageReactions {
        target_ref: crate::ObjectRef,
    },
    Relation {
        primary_conflict_domain: crate::relation::RelationPrimaryConflictDomain,
    },
    CallState {
        call_id: CallId,
    },
    Consent {
        peer_id: ActorId,
    },
    CallFocus {
        call_id: CallId,
    },
    CallRoster {
        call_id: CallId,
    },
    CallModeration {
        call_id: CallId,
    },
    RealmMediaService,
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
    RealmActorIdentity {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorControl {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorManager {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorStatus {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
        gate: RealmActorStatusGate,
    },
    RealmActorDeviceGeneration {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorDeviceAuthorization {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
        device_id: DeviceId,
    },
    RealmActorDeviceRevocationProposals {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
        device_id: DeviceId,
    },
    RealmActorProfile {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    RealmActorRecovery {
        #[serde(deserialize_with = "deserialize_realm_actor_selector")]
        actor_id: ActorId,
    },
    Sidecar {
        sidecar_id: SidecarId,
    },
    SidecarContext {
        sidecar_id: SidecarId,
        source_context_ref: SidecarContextRef,
    },
    AgentSidecarExchangeControls {
        sidecar_id: SidecarId,
        source_context_ref: SidecarContextRef,
    },
    RealmGenesis,
    AppletRegistration {
        applet_id: AppletId,
        service_id: DidCoreId,
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
    RealmPreviewPolicy,
    ScopeReadReceiptPolicy {
        #[serde(deserialize_with = "deserialize_read_receipt_policy_scope")]
        scope_ref: ScopeRef,
    },
    RealmTombstone,
    RealmArchive,
    RealmFreeze,
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
    AgentInteraction {
        agent_account_id: AccountId,
    },
    AgentActionApproval {
        approval_id: String,
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
    CalendarScheduleSource {
        strand_id: StrandId,
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
        target_ref: crate::ObjectRef,
    },
    Relation {
        primary_conflict_domain: crate::relation::RelationPrimaryConflictDomain,
    },
    CallState {
        call_id: CallId,
    },
    Consent {
        peer_id: ActorId,
    },
    CallFocus {
        call_id: CallId,
    },
    CallRoster {
        call_id: CallId,
    },
    CallModeration {
        call_id: CallId,
    },
    RealmMediaService,
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
            Some("pin") => {
                wire.remove("kind");
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Subject {
                    pin_scope: PinScope,
                }
                let subject = serde_json::from_value::<Subject>(Value::Object(wire))
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Pin {
                    pin_scope: subject.pin_scope,
                })
            }
            Some("schema_definition") => {
                wire.remove("kind");
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Subject {
                    schema_id: String,
                }
                let subject = serde_json::from_value::<Subject>(Value::Object(wire))
                    .map_err(serde::de::Error::custom)?;
                let valid = subject
                    .schema_id
                    .strip_prefix("ak.schema.")
                    .and_then(|name| name.rsplit_once(".v"))
                    .is_some_and(|(name, version)| {
                        !name.is_empty()
                            && name.split('.').all(|segment| {
                                !segment.is_empty()
                                    && segment.bytes().all(|byte| {
                                        byte.is_ascii_lowercase()
                                            || byte.is_ascii_digit()
                                            || byte == b'_'
                                    })
                            })
                            && !version.is_empty()
                            && version.bytes().all(|byte| byte.is_ascii_digit())
                    });
                if !valid {
                    return Err(serde::de::Error::custom(
                        "invalid schema definition subject",
                    ));
                }
                Ok(Self::SchemaDefinition {
                    schema_id: subject.schema_id,
                })
            }
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
                | "realm_preview_policy"
                | "realm_tombstone"
                | "realm_archive"
                | "realm_freeze"
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
                    "realm_preview_policy" => Self::RealmPreviewPolicy,
                    "realm_tombstone" => Self::RealmTombstone,
                    "realm_archive" => Self::RealmArchive,
                    "realm_freeze" => Self::RealmFreeze,
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
                    FlatCurrentSelector::RealmActorIdentity { actor_id } => {
                        Self::RealmActorIdentity { actor_id }
                    }
                    FlatCurrentSelector::RealmActorControl { actor_id } => {
                        Self::RealmActorControl { actor_id }
                    }
                    FlatCurrentSelector::RealmActorManager { actor_id } => {
                        Self::RealmActorManager { actor_id }
                    }
                    FlatCurrentSelector::RealmActorStatus { actor_id, gate } => {
                        Self::RealmActorStatus { actor_id, gate }
                    }
                    FlatCurrentSelector::RealmActorDeviceGeneration { actor_id } => {
                        Self::RealmActorDeviceGeneration { actor_id }
                    }
                    FlatCurrentSelector::RealmActorDeviceAuthorization {
                        actor_id,
                        device_id,
                    } => Self::RealmActorDeviceAuthorization {
                        actor_id,
                        device_id,
                    },
                    FlatCurrentSelector::RealmActorDeviceRevocationProposals {
                        actor_id,
                        device_id,
                    } => Self::RealmActorDeviceRevocationProposals {
                        actor_id,
                        device_id,
                    },
                    FlatCurrentSelector::RealmActorProfile { actor_id } => {
                        Self::RealmActorProfile { actor_id }
                    }
                    FlatCurrentSelector::RealmActorRecovery { actor_id } => {
                        Self::RealmActorRecovery { actor_id }
                    }
                    FlatCurrentSelector::Sidecar { sidecar_id } => Self::Sidecar { sidecar_id },
                    FlatCurrentSelector::SidecarContext {
                        sidecar_id,
                        source_context_ref,
                    } => Self::SidecarContext {
                        sidecar_id,
                        source_context_ref,
                    },
                    FlatCurrentSelector::AgentSidecarExchangeControls {
                        sidecar_id,
                        source_context_ref,
                    } => Self::AgentSidecarExchangeControls {
                        sidecar_id,
                        source_context_ref,
                    },
                    FlatCurrentSelector::RealmGenesis => Self::RealmGenesis,
                    FlatCurrentSelector::AppletRegistration {
                        applet_id,
                        service_id,
                    } => Self::AppletRegistration {
                        applet_id,
                        service_id,
                    },
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
                    FlatCurrentSelector::RealmPreviewPolicy => Self::RealmPreviewPolicy,
                    FlatCurrentSelector::ScopeReadReceiptPolicy { scope_ref } => {
                        Self::ScopeReadReceiptPolicy { scope_ref }
                    }
                    FlatCurrentSelector::RealmTombstone => Self::RealmTombstone,
                    FlatCurrentSelector::RealmArchive => Self::RealmArchive,
                    FlatCurrentSelector::RealmFreeze => Self::RealmFreeze,
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
                    FlatCurrentSelector::AgentInteraction { agent_account_id } => {
                        Self::AgentInteraction { agent_account_id }
                    }
                    FlatCurrentSelector::AgentActionApproval { approval_id } => {
                        if approval_id.is_empty() || approval_id.starts_with("ak:") {
                            return Err(serde::de::Error::custom(
                                "Agent confirmation approval_id must be nonempty and outside the ak: namespace",
                            ));
                        }
                        Self::AgentActionApproval { approval_id }
                    }
                    FlatCurrentSelector::MimiRoomBinding { mimi_room_uri } => {
                        Self::MimiRoomBinding { mimi_room_uri }
                    }
                    FlatCurrentSelector::Strand { strand_id } => Self::Strand { strand_id },
                    FlatCurrentSelector::CalendarScheduleSource { strand_id } => {
                        Self::CalendarScheduleSource { strand_id }
                    }
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
                    FlatCurrentSelector::MessageReactions { target_ref } => {
                        if !crate::is_object_ref(&target_ref) {
                            return Err(serde::de::Error::custom(
                                "message_reactions target_ref is not a formal object_ref",
                            ));
                        }
                        Self::MessageReactions { target_ref }
                    }
                    FlatCurrentSelector::Relation {
                        primary_conflict_domain,
                    } => Self::Relation {
                        primary_conflict_domain,
                    },
                    FlatCurrentSelector::CallState { call_id } => Self::CallState { call_id },
                    FlatCurrentSelector::Consent { peer_id } => Self::Consent { peer_id },
                    FlatCurrentSelector::CallFocus { call_id } => Self::CallFocus { call_id },
                    FlatCurrentSelector::CallRoster { call_id } => Self::CallRoster { call_id },
                    FlatCurrentSelector::CallModeration { call_id } => {
                        Self::CallModeration { call_id }
                    }
                    FlatCurrentSelector::RealmMediaService => Self::RealmMediaService,
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

/// Restrict receipt policy selectors to the two registered independent scopes.
fn deserialize_read_receipt_policy_scope<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<ScopeRef, D::Error> {
    let scope = ScopeRef::deserialize(deserializer)?;
    if !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. }) {
        return Err(serde::de::Error::custom(
            "read receipt policy requires a Realm or Circle scope",
        ));
    }
    Ok(scope)
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
///
/// A `join` value carries the producer-signed `parent_membership_revision`
/// copied verbatim from the accepted Event; every other value forbids it.
/// Deserialization enforces that conditional, so no invalid register exists.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CircleMemberStateCurrentWire")]
pub struct CircleMemberStateCurrent {
    pub membership: MembershipState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_membership_revision: Option<CurrentRevision>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CircleMemberStateCurrentWire {
    membership: MembershipState,
    #[serde(default, deserialize_with = "deserialize_present_revision")]
    parent_membership_revision: Option<CurrentRevision>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    effective_at: DateTime<Utc>,
}

fn deserialize_present_revision<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<CurrentRevision>, D::Error>
where
    D: Deserializer<'de>,
{
    CurrentRevision::deserialize(deserializer).map(Some)
}

impl TryFrom<CircleMemberStateCurrentWire> for CircleMemberStateCurrent {
    type Error = WireError;

    fn try_from(value: CircleMemberStateCurrentWire) -> Result<Self> {
        let current = Self {
            membership: value.membership,
            parent_membership_revision: value.parent_membership_revision,
            effective_at: value.effective_at,
        };
        current.validate()?;
        Ok(current)
    }
}

impl CircleMemberStateCurrent {
    /// `parent_membership_revision` is present exactly on a `join` value.
    pub fn validate(&self) -> Result<()> {
        validate_parent_membership_revision(
            self.membership == MembershipState::Join,
            self.parent_membership_revision.is_some(),
        )
    }

    /// Conditions (a) and (b) of effective Circle membership
    /// (`zh/models/circle.md` section 9.1): this canonical value is `join`
    /// and the parent Realm `member_state` current of the same actor, read in
    /// the same durable cut, is `join` on the parent Realm stream at exactly
    /// the bound revision. The comparison is by the content-addressed Commit
    /// identity together with its parent Realm stream position, never by a
    /// position number shared with a Circle stream. Condition (c), the rest of
    /// the parent Realm effective membership, stays with the caller.
    pub fn is_effective_under_parent(
        &self,
        realm_id: &RealmId,
        parent_source_stream_ref: &CommitStreamRef,
        parent_revision: &CurrentRevision,
        parent_membership: MembershipState,
    ) -> bool {
        self.membership == MembershipState::Join
            && parent_membership == MembershipState::Join
            && matches!(
                parent_source_stream_ref,
                CommitStreamRef::Realm { realm_id: parent_realm } if parent_realm == realm_id
            )
            && self.parent_membership_revision.as_ref() == Some(parent_revision)
    }
}

/// Shared presence rule of `parent_membership_revision` on the
/// `ak.circle.member.state` payload and on its current value.
pub fn validate_parent_membership_revision(is_join: bool, present: bool) -> Result<()> {
    match (is_join, present) {
        (true, true) | (false, false) => Ok(()),
        (true, false) => Err(WireError::ProtocolCode {
            code: crate::ErrorCode::SchemaViolation,
            message: "a Circle join requires parent_membership_revision".to_owned(),
        }),
        (false, true) => Err(WireError::ProtocolCode {
            code: crate::ErrorCode::SchemaViolation,
            message: "only a Circle join carries parent_membership_revision".to_owned(),
        }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGroupCurrent {
    pub effective_scope: ScopeRef,
    pub genesis_event_ref: EventId,
    pub cipher_suite: crate::NonEmptyString,
    pub current_mls_commit_event_ref: EventId,
    pub epoch: u64,
    pub current_key_access_revision: u64,
    pub covered_key_access_revision: u64,
    pub public_tree_ref: crate::BlobRef,
}

/// Closed selector union for snapshot/current reads. Complex domain values
/// remain their canonical schema JSON until their owning model crates expose a
/// dependency-safe shared representation; the owning model crate decodes
/// `value` against the selector's family (for example `message_reactions`
/// through `arkret_models_collaboration::events_payloads::reaction`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypedCurrentRow {
    Value {
        selector: CurrentSelector,
        source_stream_ref: CommitStreamRef,
        revision: CurrentRevision,
        value: Value,
    },
}

impl TypedCurrentRow {
    /// Circle join basis from one already verified parent Realm current row.
    /// The complete ActorId and exact Realm stream must match; only join qualifies.
    pub fn parent_membership_revision(
        &self,
        parent_realm: &RealmId,
        member: &ActorId,
    ) -> Option<CurrentRevision> {
        let Self::Value {
            selector: CurrentSelector::MemberState { actor_id },
            source_stream_ref: CommitStreamRef::Realm { realm_id },
            revision,
            value,
        } = self
        else {
            return None;
        };
        (actor_id == member
            && realm_id == parent_realm
            && serde_json::from_value::<MemberStateCurrent>(value.clone())
                .is_ok_and(|current| current.membership == MembershipState::Join))
        .then(|| revision.clone())
    }
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

    /// Scope of the actual disclosed resource. Circle creation uses a Realm
    /// authorization shell, while its full private object belongs to the Circle.
    /// This structural projection does not authenticate or authorize the source.
    pub fn disclosure_scope(&self) -> Result<ScopeRef> {
        self.validate_shape()?;
        if let Self::Full(view) = self
            && view.event.kind == crate::EventKind::CircleCreate
        {
            if !matches!(&view.event.scope_ref, ScopeRef::Realm { realm_id } if realm_id==&view.event.realm_id)
            {
                return Err(WireError::Protocol(
                    "Circle creation requires its Realm authorization shell".into(),
                ));
            }
            return Ok(ScopeRef::Circle {
                realm_id: view.event.realm_id.clone(),
                circle_id: CircleId::from_event_id(&view.event.event_id),
            });
        }
        Ok(self.commit().stream_ref.scope_ref())
    }

    /// Narrow an already authorized audience to one exact data scope. Never
    /// promote withheld bytes; retain the exact Commit when only its stream is
    /// in scope. Other scopes yield no result rather than a partial Full Event.
    pub fn into_effective_scope(self, scope: &ScopeRef) -> Result<Option<Self>> {
        if self.disclosure_scope()? == *scope {
            return Ok(Some(self));
        }
        if self.commit().stream_ref.scope_ref() != *scope {
            return Ok(None);
        }
        Ok(Some(Self::Withheld(CommittedEventWithheldView {
            commit: self.commit().clone(),
            event_disclosure: EventDisclosure {
                status: EventDisclosureStatus::Withheld,
            },
        })))
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
    /// Additional scope narrowing after the caller proved the actual requested
    /// stream and member interval. Empty pages carry no structural scope proof.
    pub fn into_effective_scope(mut self, scope: &ScopeRef) -> Result<Option<Self>> {
        let mut events = Vec::with_capacity(self.committed_events.len());
        for event in self.committed_events {
            let Some(event) = event.into_effective_scope(scope)? else {
                return Ok(None);
            };
            events.push(event);
        }
        self.committed_events = events;
        Ok(Some(self))
    }

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
                        if let Some(expected) = next
                            && first.commit().stream_position > expected
                        {
                            return Err(WireError::StreamPositionGap {
                                stream_ref: request.stream_ref.clone(),
                                expected,
                                actual: first.commit().stream_position,
                            });
                        }
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
        if let StreamScanDirection::Before(_) = request.direction
            && let Some(last) = self.committed_events.last()
        {
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
        Ok(())
    }
}

/// Maximum rows in one `ak.self.realm.read.streams.v1` page.
pub const REALM_STREAM_LIST_MAX_ITEMS: usize = 500;

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
        Self::validate_rows(&self.realm_id, &self.streams)
    }

    /// Validate an internal full discovery cut before it is divided into wire
    /// pages. The 500-item wire bound remains enforced by `validate`.
    pub fn validate_rows(realm_id: &RealmId, streams: &[RealmStreamRow]) -> Result<()> {
        let mut previous: Option<Vec<u8>> = None;
        for row in streams {
            if row.stream_ref.realm_id() != realm_id {
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

// Absent legacy fields are distinct from an explicit wire-null digest.
fn deserialize_optional_original_digest<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Hash>, D::Error> {
    Hash::deserialize(deserializer).map(Some)
}

#[cfg(test)]
#[path = "authority_commit/tests.rs"]
mod tests;

include!("generated/authority_commit_contracts.rs");
