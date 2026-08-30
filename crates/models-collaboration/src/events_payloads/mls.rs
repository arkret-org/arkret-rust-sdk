//! MLS lifecycle event payloads.

use arkret_canonical::serde_helpers::{canonical_timestamp, serialize_canonical_timestamp};
use arkret_models_crypto::PeerKeyPackageClaimReceipt;
use arkret_wire::{DeviceId, DidCoreId, OrganizationRecoveryArchive};

use crate::history_key::AuthorizationIncarnation;
use crate::internal_prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsCommitFailureStage {
    WelcomeDecrypt,
    TranscriptVerify,
    GovernanceBinding,
    GroupStateUpdate,
    KeypackageClaim,
    SecurityFrontierMismatch,
    UnsupportedCipherSuite,
    StorageFailure,
    UnknownEpoch,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsProposalType {
    Add,
    Update,
    Remove,
    Psk,
    Reinit,
    GroupContextExtensions,
    AppCustom,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MlsGenesisEpoch;

impl Serialize for MlsGenesisEpoch {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(0)
    }
}

impl<'de> Deserialize<'de> for MlsGenesisEpoch {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let epoch = u64::deserialize(deserializer)?;
        if epoch == 0 {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("MLS genesis epoch must be 0"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsClaimTrustBinding {
    DeviceAuthorizeEventId(NonEmptyString),
    AgentKeyAuthorizeEventId(NonEmptyString),
    MinimalMetadataPairwise {
        pairwise_actor_id: DidCoreId,
        pairwise_verification_method: DidUrl,
    },
}

impl MlsClaimTrustBinding {
    pub fn device_authorize_event_id(&self) -> Option<&str> {
        match self {
            Self::DeviceAuthorizeEventId(event_id) => Some(event_id.as_str()),
            Self::AgentKeyAuthorizeEventId(_) | Self::MinimalMetadataPairwise { .. } => None,
        }
    }

    pub fn agent_key_authorize_event_id(&self) -> Option<&str> {
        match self {
            Self::DeviceAuthorizeEventId(_) => None,
            Self::AgentKeyAuthorizeEventId(event_id) => Some(event_id.as_str()),
            Self::MinimalMetadataPairwise { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum MlsRequesterTrustBinding {
    RequesterDevice {
        requester_device_id: DeviceId,
        requester_device_authorize_event_id: EventId,
    },
    RequesterNativeAgent {
        requester_agent_id: DidCoreId,
        requester_agent_verification_method: DidUrl,
        requester_agent_key_authorize_event_id: EventId,
    },
    RequesterMinimalMetadataPairwise {
        requester_pairwise_verification_method: DidUrl,
    },
}

impl MlsRequesterTrustBinding {
    pub fn requester_device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::RequesterDevice {
                requester_device_id,
                ..
            } => Some(requester_device_id),
            Self::RequesterNativeAgent { .. } | Self::RequesterMinimalMetadataPairwise { .. } => {
                None
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsWelcomeRecipient {
    Device {
        recipient_device_id: DeviceId,
    },
    NativeAgent {
        recipient_agent_id: DidCoreId,
        recipient_agent_verification_method: DidUrl,
        agent_key_authorize_event_id: EventId,
    },
    MinimalMetadataPairwise {
        recipient_pairwise_actor_id: DidCoreId,
        recipient_pairwise_verification_method: DidUrl,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeCarrier(Vec<u8>);

impl MlsWelcomeCarrier {
    pub fn new(welcome_bytes: Vec<u8>) -> std::result::Result<Self, &'static str> {
        if welcome_bytes.is_empty() {
            return Err("MLS Welcome bytes must not be empty");
        }
        Ok(Self(welcome_bytes))
    }

    fn from_base64url(ciphertext: &Base64UrlString) -> std::result::Result<Self, &'static str> {
        let welcome_bytes = arkret_canonical::base64url::base64url_decode(ciphertext.as_str())
            .map_err(|_| "MLS Welcome ciphertext must decode as unpadded base64url")?;
        if arkret_canonical::base64url::base64url_encode(&welcome_bytes) != ciphertext.as_str() {
            return Err("MLS Welcome ciphertext must be canonical unpadded base64url");
        }
        Self::new(welcome_bytes)
    }

    pub fn welcome_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn ciphertext(&self) -> String {
        arkret_canonical::base64url::base64url_encode(&self.0)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_commit_failed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCommitFailedPayload {
    /// Exact MLS scope of the failed Commit/Welcome. It MUST match the
    /// referenced event governance binding and the canonical group-id
    /// derivation.
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub commit_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_ref: Option<EventId>,
    pub epoch: u64,
    pub failure_stage: MlsCommitFailureStage,
    pub reporter_device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_digest: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub failed_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_epoch_range`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsEpochRange {
    pub first_epoch: u64,
    pub last_epoch: u64,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_genesis_payload`.
#[derive(Clone, Debug)]
pub struct MlsGenesisPayload {
    pub mls_group_id: MlsGroupId,
    pub effective_scope: ScopeRef,
    pub epoch: MlsGenesisEpoch,
    pub cipher_suite: NonEmptyString,
    pub group_info_ref: BlobRef,
    pub group_info_digest: Hash,
    pub ratchet_tree_ref: BlobRef,
    pub ratchet_tree_digest: Hash,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub organization_recovery_archive: Option<OrganizationRecoveryArchive>,
    pub created_at: DateTime<Utc>,
}

/// Compute the registered Genesis MLS transition digest from a complete,
/// schema-validated `mls_genesis_payload` JSON value. The embedded recovery
/// archive is removed internally so callers cannot accidentally hash the
/// self-referential archive branch.
pub fn mls_genesis_transition_digest(payload: &Value) -> Result<Hash> {
    arkret_wire::mls_genesis_transition_digest(payload)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsGenesisPayloadWire {
    mls_group_id: MlsGroupId,
    effective_scope: ScopeRef,
    epoch: MlsGenesisEpoch,
    cipher_suite: NonEmptyString,
    group_info_ref: BlobRef,
    group_info_digest: Hash,
    ratchet_tree_ref: BlobRef,
    ratchet_tree_digest: Hash,
    governance_binding: MlsGovernanceBindingPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    organization_recovery_archive: Option<OrganizationRecoveryArchive>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    created_at: DateTime<Utc>,
}

impl MlsGenesisPayload {
    pub fn validate(&self) -> Result<()> {
        crate::mls_group_state_material::validate_content_address(
            &self.group_info_ref,
            &self.group_info_digest,
        )?;
        crate::mls_group_state_material::validate_content_address(
            &self.ratchet_tree_ref,
            &self.ratchet_tree_digest,
        )?;
        if self.governance_binding.mls_group_id() != self.mls_group_id.as_str()
            || self.governance_binding.effective_scope() != &self.effective_scope
        {
            return Err(WireError::Protocol(
                "mls_genesis_payload governance binding does not match the group and scope"
                    .to_owned(),
            ));
        }
        let transition_digest = self.transition_digest()?;
        validate_transition_recovery_archive(
            "mls_genesis_payload",
            &self.governance_binding,
            0,
            &transition_digest,
            self.organization_recovery_archive.as_ref(),
        )
    }

    /// Registered `ak.mls-genesis-transition-v1` digest over the closed Genesis
    /// core: the embedded recovery archive, the outer `event_id` and every
    /// proof are excluded.
    pub fn transition_digest(&self) -> Result<Hash> {
        mls_genesis_transition_digest(&serde_json::to_value(self.wire())?)
    }

    fn wire(&self) -> MlsGenesisPayloadWire {
        MlsGenesisPayloadWire {
            mls_group_id: self.mls_group_id.clone(),
            effective_scope: self.effective_scope.clone(),
            epoch: self.epoch,
            cipher_suite: self.cipher_suite.clone(),
            group_info_ref: self.group_info_ref.clone(),
            group_info_digest: self.group_info_digest.clone(),
            ratchet_tree_ref: self.ratchet_tree_ref.clone(),
            ratchet_tree_digest: self.ratchet_tree_digest.clone(),
            governance_binding: self.governance_binding.clone(),
            organization_recovery_archive: self.organization_recovery_archive.clone(),
            created_at: self.created_at,
        }
    }
}

impl Serialize for MlsGenesisPayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        self.wire().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MlsGenesisPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsGenesisPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            mls_group_id: wire.mls_group_id,
            effective_scope: wire.effective_scope,
            epoch: wire.epoch,
            cipher_suite: wire.cipher_suite,
            group_info_ref: wire.group_info_ref,
            group_info_digest: wire.group_info_digest,
            ratchet_tree_ref: wire.ratchet_tree_ref,
            ratchet_tree_digest: wire.ratchet_tree_digest,
            governance_binding: wire.governance_binding,
            organization_recovery_archive: wire.organization_recovery_archive,
            created_at: wire.created_at,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

use arkret_models_crypto::MlsKeyPackageState;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_keypackage_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsKeypackagePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_id: Option<NonEmptyString>,
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_realm_id: Option<RealmId>,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub cipher_suites: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    pub state: MlsKeyPackageState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<NonEmptyString>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl MlsKeypackagePayload {
    pub fn validate_endpoint(&self) -> std::result::Result<(), &'static str> {
        match (
            &self.device_id,
            &self.endpoint_verification_method,
            &self.device_authorize_event_id,
            &self.agent_key_authorize_event_id,
            &self.intended_realm_id,
        ) {
            (Some(_), None, Some(_), None, None) => Ok(()),
            (None, Some(_), None, Some(_), None) => Ok(()),
            (None, Some(method), None, None, Some(_))
                if arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                    self.principal_id.clone(),
                    method.clone(),
                )
                .is_ok() =>
            {
                Ok(())
            }
            _ => Err("MLS KeyPackage endpoint branch is invalid"),
        }
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_proposal_payload`.
#[derive(Clone, Debug)]
pub struct MlsProposalPayload {
    pub mls_group_id: MlsGroupId,
    pub base_epoch: u64,
    pub proposal_type: MlsProposalType,
    pub proposal_bytes_b64: String,
    pub proposal_digest: Hash,
    pub target_principal_id: Option<DidCoreId>,
    pub target_authorization_incarnation: Option<AuthorizationIncarnation>,
    pub governance_binding: MlsGovernanceBindingPayload,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsProposalPayloadWire {
    mls_group_id: MlsGroupId,
    base_epoch: u64,
    proposal_type: MlsProposalType,
    proposal_bytes_b64: String,
    proposal_digest: Hash,
    #[serde(default)]
    target_principal_id: Option<DidCoreId>,
    #[serde(default)]
    target_authorization_incarnation: Option<AuthorizationIncarnation>,
    governance_binding: MlsGovernanceBindingPayload,
}

impl MlsProposalPayload {
    pub fn validate(&self) -> Result<()> {
        let proposal_bytes = arkret_canonical::base64url_decode(&self.proposal_bytes_b64)
            .map_err(|error| WireError::Protocol(format!("invalid MLS proposal bytes: {error}")))?;
        if proposal_bytes.is_empty()
            || arkret_canonical::base64url_encode(&proposal_bytes) != self.proposal_bytes_b64
            || self.proposal_digest.as_str() != arkret_canonical::sha256_digest(&proposal_bytes)
        {
            return Err(WireError::Protocol(
                "MLS proposal bytes are empty, non-canonical, or do not match proposal_digest"
                    .to_owned(),
            ));
        }
        if self.governance_binding.mls_group_id() != self.mls_group_id.as_str() {
            return Err(WireError::Protocol(
                "mls_proposal_payload governance binding does not match mls_group_id".to_owned(),
            ));
        }
        if matches!(self.proposal_type, MlsProposalType::Add) {
            let Some(incarnation) = &self.target_authorization_incarnation else {
                return Err(WireError::Protocol(
                    "add MLS proposal requires target authorization incarnation".to_owned(),
                ));
            };
            if self.target_principal_id.is_none()
                || !matches!(
                    (self.governance_binding.effective_scope(), incarnation),
                    (
                        ScopeRef::Realm { .. },
                        AuthorizationIncarnation::Realm { .. }
                    ) | (
                        ScopeRef::Circle { .. },
                        AuthorizationIncarnation::Circle { .. }
                    )
                )
            {
                return Err(WireError::Protocol(
                    "add MLS proposal target authorization incarnation does not match its scope"
                        .to_owned(),
                ));
            }
        } else if self.target_authorization_incarnation.is_some() {
            return Err(WireError::Protocol(
                "non-add MLS proposal forbids target_authorization_incarnation".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Serialize for MlsProposalPayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        MlsProposalPayloadWire {
            mls_group_id: self.mls_group_id.clone(),
            base_epoch: self.base_epoch,
            proposal_type: self.proposal_type,
            proposal_bytes_b64: self.proposal_bytes_b64.clone(),
            proposal_digest: self.proposal_digest.clone(),
            target_principal_id: self.target_principal_id.clone(),
            target_authorization_incarnation: self.target_authorization_incarnation.clone(),
            governance_binding: self.governance_binding.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MlsProposalPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsProposalPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            mls_group_id: wire.mls_group_id,
            base_epoch: wire.base_epoch,
            proposal_type: wire.proposal_type,
            proposal_bytes_b64: wire.proposal_bytes_b64,
            proposal_digest: wire.proposal_digest,
            target_principal_id: wire.target_principal_id,
            target_authorization_incarnation: wire.target_authorization_incarnation,
            governance_binding: wire.governance_binding,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_welcome_payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomePayloadClaimRef {
    pub claim_id: NonEmptyString,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub capabilities_digest: Hash,
    pub trust_binding: MlsClaimTrustBinding,
}

#[derive(Clone, Debug)]
pub struct MlsWelcomeClaimEnvelope {
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub intended_realm_id: RealmId,
    pub claim_id: NonEmptyString,
    pub requester_actor_id: DidCoreId,
    pub trust_binding: MlsRequesterTrustBinding,
    pub welcome_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[derive(Clone, Debug)]
pub struct MlsWelcomeClaimEnvelopeSigningInput {
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub intended_realm_id: RealmId,
    pub claim_id: NonEmptyString,
    pub requester_actor_id: DidCoreId,
    pub trust_binding: MlsRequesterTrustBinding,
    pub welcome_digest: Hash,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsWelcomePayloadClaimRefWire {
    claim_id: NonEmptyString,
    keypackage_ref: ObjectRef,
    keypackage_digest: Hash,
    capabilities_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_authorize_event_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_key_authorize_event_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pairwise_actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pairwise_verification_method: Option<DidUrl>,
}

impl Serialize for MlsWelcomePayloadClaimRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (
            device_authorize_event_id,
            agent_key_authorize_event_id,
            pairwise_actor_id,
            pairwise_verification_method,
        ) = match &self.trust_binding {
            MlsClaimTrustBinding::DeviceAuthorizeEventId(event_id) => {
                (Some(event_id.clone()), None, None, None)
            }
            MlsClaimTrustBinding::AgentKeyAuthorizeEventId(event_id) => {
                (None, Some(event_id.clone()), None, None)
            }
            MlsClaimTrustBinding::MinimalMetadataPairwise {
                pairwise_actor_id,
                pairwise_verification_method,
            } => (
                None,
                None,
                Some(pairwise_actor_id.clone()),
                Some(pairwise_verification_method.clone()),
            ),
        };
        MlsWelcomePayloadClaimRefWire {
            claim_id: self.claim_id.clone(),
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            capabilities_digest: self.capabilities_digest.clone(),
            device_authorize_event_id,
            agent_key_authorize_event_id,
            pairwise_actor_id,
            pairwise_verification_method,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MlsWelcomePayloadClaimRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsWelcomePayloadClaimRefWire::deserialize(deserializer)?;
        let trust_binding = match (
            wire.device_authorize_event_id,
            wire.agent_key_authorize_event_id,
            wire.pairwise_actor_id,
            wire.pairwise_verification_method,
        ) {
            (Some(event_id), None, None, None) => {
                MlsClaimTrustBinding::DeviceAuthorizeEventId(event_id)
            }
            (None, Some(event_id), None, None) => {
                MlsClaimTrustBinding::AgentKeyAuthorizeEventId(event_id)
            }
            (None, None, Some(actor_id), Some(method)) => {
                arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                    actor_id.clone(),
                    method.clone(),
                )
                .map_err(serde::de::Error::custom)?;
                MlsClaimTrustBinding::MinimalMetadataPairwise {
                    pairwise_actor_id: actor_id,
                    pairwise_verification_method: method,
                }
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "claim_ref must contain exactly one trust binding",
                ));
            }
        };
        Ok(Self {
            claim_id: wire.claim_id,
            keypackage_ref: wire.keypackage_ref,
            keypackage_digest: wire.keypackage_digest,
            capabilities_digest: wire.capabilities_digest,
            trust_binding,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsWelcomeClaimEnvelopeWire {
    keypackage_ref: ObjectRef,
    keypackage_digest: Hash,
    intended_realm_id: RealmId,
    claim_id: NonEmptyString,
    requester_actor_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_agent_key_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_pairwise_verification_method: Option<DidUrl>,
    welcome_digest: Hash,
    #[serde(with = "canonical_timestamp")]
    created_at: DateTime<Utc>,
    signature: KeyOperationSignature,
}

impl Serialize for MlsWelcomeClaimEnvelope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (
            requester_device_id,
            requester_device_authorize_event_id,
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
            requester_pairwise_verification_method,
        ) = match &self.trust_binding {
            MlsRequesterTrustBinding::RequesterDevice {
                requester_device_id,
                requester_device_authorize_event_id,
            } => (
                Some(requester_device_id.clone()),
                Some(requester_device_authorize_event_id.clone()),
                None,
                None,
                None,
                None,
            ),
            MlsRequesterTrustBinding::RequesterNativeAgent {
                requester_agent_id,
                requester_agent_verification_method,
                requester_agent_key_authorize_event_id,
            } => (
                None,
                None,
                Some(requester_agent_id.clone()),
                Some(requester_agent_verification_method.clone()),
                Some(requester_agent_key_authorize_event_id.clone()),
                None,
            ),
            MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                requester_pairwise_verification_method,
            } => (
                None,
                None,
                None,
                None,
                None,
                Some(requester_pairwise_verification_method.clone()),
            ),
        };
        MlsWelcomeClaimEnvelopeWire {
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            claim_id: self.claim_id.clone(),
            requester_actor_id: self.requester_actor_id.clone(),
            requester_device_id,
            requester_device_authorize_event_id,
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
            requester_pairwise_verification_method,
            welcome_digest: self.welcome_digest.clone(),
            created_at: self.created_at,
            signature: self.signature.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MlsWelcomeClaimEnvelope {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsWelcomeClaimEnvelopeWire::deserialize(deserializer)?;
        let trust_binding = match (
            wire.requester_device_id,
            wire.requester_device_authorize_event_id,
            wire.requester_agent_id,
            wire.requester_agent_verification_method,
            wire.requester_agent_key_authorize_event_id,
            wire.requester_pairwise_verification_method,
        ) {
            (Some(device_id), Some(event_id), None, None, None, None) => {
                MlsRequesterTrustBinding::RequesterDevice {
                    requester_device_id: device_id,
                    requester_device_authorize_event_id: event_id,
                }
            }
            (None, None, Some(agent_id), Some(method), Some(authorize_event_id), None) => {
                MlsRequesterTrustBinding::RequesterNativeAgent {
                    requester_agent_id: agent_id,
                    requester_agent_verification_method: method,
                    requester_agent_key_authorize_event_id: authorize_event_id,
                }
            }
            (None, None, None, None, None, Some(method)) => {
                arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                    wire.requester_actor_id.clone(),
                    method.clone(),
                )
                .map_err(serde::de::Error::custom)?;
                MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                    requester_pairwise_verification_method: method,
                }
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "Welcome claim requester must select exactly one device, Native Agent, or minimal-metadata pairwise branch",
                ));
            }
        };
        Ok(Self {
            keypackage_ref: wire.keypackage_ref,
            keypackage_digest: wire.keypackage_digest,
            intended_realm_id: wire.intended_realm_id,
            claim_id: wire.claim_id,
            requester_actor_id: wire.requester_actor_id,
            trust_binding,
            welcome_digest: wire.welcome_digest,
            created_at: wire.created_at,
            signature: wire.signature,
        })
    }
}

#[derive(Serialize)]
struct MlsWelcomeClaimEnvelopeSigningInputWire {
    keypackage_ref: ObjectRef,
    keypackage_digest: Hash,
    intended_realm_id: RealmId,
    claim_id: NonEmptyString,
    requester_actor_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_device_authorize_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_agent_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_agent_verification_method: Option<DidUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_agent_key_authorize_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_pairwise_verification_method: Option<DidUrl>,
    claim_request_id: Base64UrlString,
    welcome_digest: Hash,
    #[serde(serialize_with = "serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

impl MlsWelcomeClaimEnvelopeSigningInput {
    fn wire(&self, claim_request_id: &Base64UrlString) -> MlsWelcomeClaimEnvelopeSigningInputWire {
        let (
            requester_device_id,
            requester_device_authorize_event_id,
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
            requester_pairwise_verification_method,
        ) = match &self.trust_binding {
            MlsRequesterTrustBinding::RequesterDevice {
                requester_device_id,
                requester_device_authorize_event_id,
            } => (
                Some(requester_device_id.clone()),
                Some(requester_device_authorize_event_id.clone()),
                None,
                None,
                None,
                None,
            ),
            MlsRequesterTrustBinding::RequesterNativeAgent {
                requester_agent_id,
                requester_agent_verification_method,
                requester_agent_key_authorize_event_id,
            } => (
                None,
                None,
                Some(requester_agent_id.clone()),
                Some(requester_agent_verification_method.clone()),
                Some(requester_agent_key_authorize_event_id.clone()),
                None,
            ),
            MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                requester_pairwise_verification_method,
            } => (
                None,
                None,
                None,
                None,
                None,
                Some(requester_pairwise_verification_method.clone()),
            ),
        };
        MlsWelcomeClaimEnvelopeSigningInputWire {
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            claim_id: self.claim_id.clone(),
            requester_actor_id: self.requester_actor_id.clone(),
            requester_device_id,
            requester_device_authorize_event_id,
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
            requester_pairwise_verification_method,
            claim_request_id: claim_request_id.clone(),
            welcome_digest: self.welcome_digest.clone(),
            created_at: self.created_at,
        }
    }
}

impl MlsWelcomeClaimEnvelope {
    pub fn signing_input(
        &self,
        claim_receipt: &PeerKeyPackageClaimReceipt,
    ) -> Result<MlsWelcomeClaimEnvelopeSigningInput> {
        if claim_receipt.claim_request_id != claim_receipt.request.claim_request_id {
            return Err(WireError::Protocol(
                "claim receipt request id does not match its request context".to_owned(),
            ));
        }
        Ok(MlsWelcomeClaimEnvelopeSigningInput {
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            claim_id: self.claim_id.clone(),
            requester_actor_id: self.requester_actor_id.clone(),
            trust_binding: self.trust_binding.clone(),
            welcome_digest: self.welcome_digest.clone(),
            created_at: self.created_at,
        })
    }

    pub fn canonical_signing_bytes(
        &self,
        claim_receipt: &PeerKeyPackageClaimReceipt,
    ) -> Result<Vec<u8>> {
        let input = self.signing_input(claim_receipt)?;
        Ok(canonical::canonical_json_bytes(
            &input.wire(&claim_receipt.claim_request_id),
        )?)
    }

    pub fn validate_signature_shape(&self) -> std::result::Result<(), &'static str> {
        if self.signature.kid.is_empty() || self.signature.sig.is_empty() {
            return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
        }
        if let Some(alg) = self.signature.signature_algorithm.as_deref()
            && alg != "Ed25519"
        {
            return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
        }
        if let MlsRequesterTrustBinding::RequesterNativeAgent {
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
        } = &self.trust_binding
        {
            if requester_agent_id != &self.requester_actor_id
                || self.signature.kid.as_str() != requester_agent_verification_method.as_str()
            {
                return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            let _ = requester_agent_key_authorize_event_id;
        }
        if let MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
            requester_pairwise_verification_method,
        } = &self.trust_binding
            && (self.signature.kid.as_str() != requester_pairwise_verification_method.as_str()
                || arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                    self.requester_actor_id.clone(),
                    requester_pairwise_verification_method.clone(),
                )
                .is_err())
        {
            return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
        }
        Ok(())
    }
}

/// Welcome-claim authoring state before the requester signature exists.
/// The signing-input model owns the envelope-derived transcript fields, while
/// the exact claim receipt supplies the sole claim request id. This wrapper
/// makes attachment of a real signature the only transition to the outbound
/// envelope.
#[derive(Clone, Debug)]
pub struct UnsignedMlsWelcomeClaimEnvelope {
    signing_input: MlsWelcomeClaimEnvelopeSigningInput,
    claim_request_id: Base64UrlString,
}

impl UnsignedMlsWelcomeClaimEnvelope {
    pub fn new(
        signing_input: MlsWelcomeClaimEnvelopeSigningInput,
        claim_receipt: &PeerKeyPackageClaimReceipt,
    ) -> Result<Self> {
        if claim_receipt.claim_request_id != claim_receipt.request.claim_request_id {
            return Err(WireError::Protocol(
                "claim receipt request id does not match its request context".to_owned(),
            ));
        }
        Ok(Self {
            signing_input,
            claim_request_id: claim_receipt.claim_request_id.clone(),
        })
    }

    pub fn signing_input(&self) -> &MlsWelcomeClaimEnvelopeSigningInput {
        &self.signing_input
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(
            &self.signing_input.wire(&self.claim_request_id),
        )?)
    }

    pub fn attach_signature(
        self,
        kid: NonEmptyString,
        sig: Base64UrlString,
    ) -> Result<MlsWelcomeClaimEnvelope> {
        let input = self.signing_input;
        let envelope = MlsWelcomeClaimEnvelope {
            keypackage_ref: input.keypackage_ref,
            keypackage_digest: input.keypackage_digest,
            intended_realm_id: input.intended_realm_id,
            claim_id: input.claim_id,
            requester_actor_id: input.requester_actor_id,
            trust_binding: input.trust_binding,
            welcome_digest: input.welcome_digest,
            created_at: input.created_at,
            signature: KeyOperationSignature {
                kid,
                signature_algorithm: Some(
                    NonEmptyString::new("Ed25519")
                        .expect("the fixed signature algorithm is non-empty"),
                ),
                sig,
            },
        };
        envelope
            .validate_signature_shape()
            .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
        Ok(envelope)
    }
}

#[derive(Clone, Debug)]
pub struct MlsWelcomePayload {
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
    pub recipient_principal_id: Option<DidCoreId>,
    pub recipient: MlsWelcomeRecipient,
    pub sender_device_id: Option<DeviceId>,
    pub keypackage_ref: ObjectRef,
    pub claim_id: NonEmptyString,
    pub claim_ref: MlsWelcomePayloadClaimRef,
    pub claim_envelope: MlsWelcomeClaimEnvelope,
    pub claim_receipt: PeerKeyPackageClaimReceipt,
    pub carrier: MlsWelcomeCarrier,
    pub commit_ref: EventId,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsWelcomePayloadWire {
    mls_group_id: MlsGroupId,
    epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_principal_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_key_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_pairwise_actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_pairwise_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender_device_id: Option<DeviceId>,
    keypackage_ref: ObjectRef,
    claim_id: NonEmptyString,
    claim_ref: MlsWelcomePayloadClaimRef,
    claim_envelope: MlsWelcomeClaimEnvelope,
    claim_receipt: PeerKeyPackageClaimReceipt,
    ciphertext: Base64UrlString,
    commit_ref: EventId,
    governance_binding: MlsGovernanceBindingPayload,
    #[serde(with = "canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

impl Serialize for MlsWelcomePayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let expected_welcome_digest = arkret_canonical::sha256_digest(self.carrier.welcome_bytes());
        if self.claim_receipt.claim_request_id != self.claim_receipt.request.claim_request_id {
            return Err(serde::ser::Error::custom(
                "mls_welcome_payload claim receipt request id context does not match",
            ));
        }
        if self.claim_envelope.welcome_digest.as_str() != expected_welcome_digest {
            return Err(serde::ser::Error::custom(
                "mls_welcome_payload claim_envelope welcome_digest does not match Welcome bytes",
            ));
        }
        let (
            recipient_device_id,
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
        ) = match &self.recipient {
            MlsWelcomeRecipient::Device {
                recipient_device_id,
            } => (
                Some(recipient_device_id.clone()),
                None,
                None,
                None,
                None,
                None,
            ),
            MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            } => (
                None,
                Some(recipient_agent_id.clone()),
                Some(recipient_agent_verification_method.clone()),
                Some(agent_key_authorize_event_id.clone()),
                None,
                None,
            ),
            MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id,
                recipient_pairwise_verification_method,
            } => (
                None,
                None,
                None,
                None,
                Some(recipient_pairwise_actor_id.clone()),
                Some(recipient_pairwise_verification_method.clone()),
            ),
        };
        MlsWelcomePayloadWire {
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
            recipient_principal_id: self.recipient_principal_id.clone(),
            recipient_device_id,
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
            sender_device_id: self.sender_device_id.clone(),
            keypackage_ref: self.keypackage_ref.clone(),
            claim_id: self.claim_id.clone(),
            claim_ref: self.claim_ref.clone(),
            claim_envelope: self.claim_envelope.clone(),
            claim_receipt: self.claim_receipt.clone(),
            ciphertext: Base64UrlString::new(self.carrier.ciphertext())
                .expect("encoded non-empty Welcome bytes are canonical base64url"),
            commit_ref: self.commit_ref.clone(),
            governance_binding: self.governance_binding.clone(),
            expires_at: self.expires_at,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MlsWelcomePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsWelcomePayloadWire::deserialize(deserializer)?;
        let recipient = match (
            wire.recipient_device_id,
            wire.recipient_agent_id,
            wire.recipient_agent_verification_method,
            wire.agent_key_authorize_event_id,
            wire.recipient_pairwise_actor_id,
            wire.recipient_pairwise_verification_method,
        ) {
            (Some(device_id), None, None, None, None, None)
                if wire.recipient_principal_id.is_some() =>
            {
                MlsWelcomeRecipient::Device {
                    recipient_device_id: device_id,
                }
            }
            (None, Some(agent_id), Some(method), Some(authorize_event_id), None, None)
                if wire.recipient_principal_id.as_ref() == Some(&agent_id) =>
            {
                MlsWelcomeRecipient::NativeAgent {
                    recipient_agent_id: agent_id,
                    recipient_agent_verification_method: method,
                    agent_key_authorize_event_id: authorize_event_id,
                }
            }
            (None, None, None, None, Some(actor_id), Some(method))
                if wire.recipient_principal_id.is_none() =>
            {
                arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                    actor_id.clone(),
                    method.clone(),
                )
                .map_err(serde::de::Error::custom)?;
                MlsWelcomeRecipient::MinimalMetadataPairwise {
                    recipient_pairwise_actor_id: actor_id,
                    recipient_pairwise_verification_method: method,
                }
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "MLS Welcome recipient must select exactly one device, Native Agent, or minimal-metadata pairwise branch",
                ));
            }
        };
        let carrier = MlsWelcomeCarrier::from_base64url(&wire.ciphertext)
            .map_err(serde::de::Error::custom)?;
        let claim_receipt = wire.claim_receipt;
        if claim_receipt.claim_request_id != claim_receipt.request.claim_request_id {
            return Err(serde::de::Error::custom(
                "mls_welcome_payload claim receipt request id context does not match",
            ));
        }
        if wire.governance_binding.mls_group_id() != wire.mls_group_id.as_str()
            || wire.governance_binding.next_epoch() != wire.epoch
        {
            return Err(serde::de::Error::custom(
                "mls_welcome_payload governance binding does not match group and epoch",
            ));
        }
        if wire.claim_ref.claim_id != wire.claim_id
            || wire.claim_ref.keypackage_ref != wire.keypackage_ref
            || wire.claim_envelope.claim_id != wire.claim_id
            || wire.claim_envelope.keypackage_ref != wire.keypackage_ref
            || wire.claim_envelope.keypackage_digest != wire.claim_ref.keypackage_digest
        {
            return Err(serde::de::Error::custom(
                "mls_welcome_payload claim bindings do not match top-level fields",
            ));
        }
        if wire.claim_envelope.welcome_digest.as_str()
            != arkret_canonical::sha256_digest(carrier.welcome_bytes())
        {
            return Err(serde::de::Error::custom(
                "mls_welcome_payload claim_envelope welcome_digest does not match Welcome bytes",
            ));
        }
        if let MlsWelcomeRecipient::MinimalMetadataPairwise {
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
        } = &recipient
        {
            match &wire.claim_ref.trust_binding {
                MlsClaimTrustBinding::MinimalMetadataPairwise {
                    pairwise_actor_id,
                    pairwise_verification_method,
                } if pairwise_actor_id == recipient_pairwise_actor_id
                    && pairwise_verification_method == recipient_pairwise_verification_method => {}
                _ => {
                    return Err(serde::de::Error::custom(
                        "pairwise Welcome recipient must equal the claim_ref pairwise endpoint",
                    ));
                }
            }
        } else if matches!(
            &wire.claim_ref.trust_binding,
            MlsClaimTrustBinding::MinimalMetadataPairwise { .. }
        ) {
            return Err(serde::de::Error::custom(
                "pairwise claim_ref requires the pairwise Welcome recipient branch",
            ));
        }
        Ok(Self {
            mls_group_id: wire.mls_group_id,
            epoch: wire.epoch,
            recipient_principal_id: wire.recipient_principal_id,
            recipient,
            sender_device_id: wire.sender_device_id,
            keypackage_ref: wire.keypackage_ref,
            claim_id: wire.claim_id,
            claim_ref: wire.claim_ref,
            claim_envelope: wire.claim_envelope,
            claim_receipt,
            carrier,
            commit_ref: wire.commit_ref,
            governance_binding: wire.governance_binding,
            expires_at: wire.expires_at,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn validate_mls_welcome_claim_envelope(
    welcome: &MlsWelcomePayload,
    claim: &KeyPackageClaimRecord,
    published: &MlsKeypackagePayload,
    intended_realm_id: &RealmId,
    requester_actor_id: &DidCoreId,
    welcome_digest: &Hash,
    current_claim_device_authorize_event_id: Option<&str>,
    current_claim_agent_key_authorize_event_id: Option<&str>,
    current_requester_device_id: Option<&str>,
    current_requester_device_authorize_event_id: Option<&str>,
) -> std::result::Result<(), &'static str> {
    let claim_keypackage = arkret_canonical::base64url::base64url_decode(&claim.keypackage)
        .map_err(|_| ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let claim_keypackage_digest = arkret_canonical::sha256_digest(&claim_keypackage);
    let claim_capabilities = arkret_canonical::canonical_json_bytes(&claim.capabilities)
        .map_err(|_| ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let claim_capabilities_digest = arkret_canonical::sha256_digest(&claim_capabilities);
    if welcome.keypackage_ref != claim.keypackage_ref
        || welcome.claim_id.as_str() != claim.claim_id
        || welcome.claim_ref.claim_id.as_str() != claim.claim_id
        || welcome.claim_ref.keypackage_ref != claim.keypackage_ref
        || published.keypackage_ref != claim.keypackage_ref
        || welcome.claim_ref.keypackage_digest.as_str() != claim_keypackage_digest
        || published.keypackage_digest.as_str() != claim_keypackage_digest
        || welcome.claim_ref.capabilities_digest.as_str() != claim_capabilities_digest
        || welcome.claim_ref.trust_binding.device_authorize_event_id()
            != claim
                .device_authorize_event_id
                .as_ref()
                .map(EventId::as_str)
        || welcome
            .claim_ref
            .trust_binding
            .agent_key_authorize_event_id()
            != claim
                .agent_key_authorize_event_id
                .as_ref()
                .map(EventId::as_str)
    {
        return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    match (
        &welcome.recipient,
        &claim.device_id,
        &claim.agent_id,
        &claim.agent_verification_method,
        &claim.agent_key_authorize_event_id,
        &claim.pairwise_verification_method,
    ) {
        (
            MlsWelcomeRecipient::Device {
                recipient_device_id,
            },
            Some(claim_device_id),
            None,
            None,
            None,
            None,
        ) if recipient_device_id == claim_device_id => {}
        (
            MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            },
            None,
            Some(claim_agent_id),
            Some(claim_method),
            Some(claim_authorize_event_id),
            None,
        ) if recipient_agent_id == claim_agent_id
            && welcome
                .recipient_principal_id
                .as_ref()
                .is_some_and(|principal_id| {
                    recipient_agent_id.as_core_id() == principal_id.as_core_id()
                })
            && recipient_agent_verification_method == claim_method
            && agent_key_authorize_event_id == claim_authorize_event_id => {}
        (
            MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id,
                recipient_pairwise_verification_method,
            },
            None,
            None,
            None,
            None,
            Some(claim_method),
        ) if welcome.recipient_principal_id.is_none()
            && recipient_pairwise_actor_id == &claim.principal_id
            && recipient_pairwise_verification_method == claim_method => {}
        _ => return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH),
    }
    validate_claim_trust_binding(
        &welcome.claim_ref.trust_binding,
        current_claim_device_authorize_event_id,
        current_claim_agent_key_authorize_event_id,
    )?;

    let envelope = &welcome.claim_envelope;
    if envelope.keypackage_ref != claim.keypackage_ref
        || envelope.keypackage_digest.as_str() != claim_keypackage_digest
        || envelope.intended_realm_id != *intended_realm_id
        || envelope.claim_id.as_str() != claim.claim_id
        || envelope.requester_actor_id != *requester_actor_id
        || envelope.welcome_digest.as_str() != welcome_digest.as_str()
    {
        return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    if welcome.claim_receipt.claim_request_id != welcome.claim_receipt.request.claim_request_id {
        return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    validate_requester_signature_binding(
        &envelope.trust_binding,
        requester_actor_id,
        current_requester_device_id,
        current_requester_device_authorize_event_id,
    )?;
    envelope.validate_signature_shape()?;
    if envelope.created_at > claim.expires_at || welcome.expires_at > claim.expires_at {
        return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}

fn validate_claim_trust_binding(
    trust_binding: &MlsClaimTrustBinding,
    current_claim_device_authorize_event_id: Option<&str>,
    current_claim_agent_key_authorize_event_id: Option<&str>,
) -> std::result::Result<(), &'static str> {
    match trust_binding {
        MlsClaimTrustBinding::DeviceAuthorizeEventId(event_id)
            if Some(event_id.as_str()) == current_claim_device_authorize_event_id =>
        {
            Ok(())
        }
        MlsClaimTrustBinding::AgentKeyAuthorizeEventId(event_id)
            if Some(event_id.as_str()) == current_claim_agent_key_authorize_event_id =>
        {
            Ok(())
        }
        MlsClaimTrustBinding::MinimalMetadataPairwise {
            pairwise_actor_id,
            pairwise_verification_method,
        } if arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
            pairwise_actor_id.clone(),
            pairwise_verification_method.clone(),
        )
        .is_ok() =>
        {
            Ok(())
        }
        _ => Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH),
    }
}

fn validate_requester_signature_binding(
    trust_binding: &MlsRequesterTrustBinding,
    requester_actor_id: &DidCoreId,
    current_requester_device_id: Option<&str>,
    current_requester_device_authorize_event_id: Option<&str>,
) -> std::result::Result<(), &'static str> {
    match trust_binding {
        MlsRequesterTrustBinding::RequesterDevice {
            requester_device_id,
            requester_device_authorize_event_id,
        } if Some(requester_device_id.as_str()) == current_requester_device_id
            && Some(requester_device_authorize_event_id.as_str())
                == current_requester_device_authorize_event_id =>
        {
            Ok(())
        }
        MlsRequesterTrustBinding::RequesterNativeAgent {
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
        } => {
            let _ = (
                requester_agent_id,
                requester_agent_verification_method,
                requester_agent_key_authorize_event_id,
            );
            Ok(())
        }
        MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
            requester_pairwise_verification_method,
        } if arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
            requester_actor_id.clone(),
            requester_pairwise_verification_method.clone(),
        )
        .is_ok() =>
        {
            Ok(())
        }
        _ => Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_claim_envelope(created_at: DateTime<Utc>) -> MlsWelcomeClaimEnvelope {
        MlsWelcomeClaimEnvelope {
            keypackage_ref:
                "sha256:0c361e822d3c7f63425704ed86689eb2b4d3c5395d7f4029e420ce9621b556a7".to_owned(),
            keypackage_digest: Hash::new(
                "sha256:0c361e822d3c7f63425704ed86689eb2b4d3c5395d7f4029e420ce9621b556a7",
            )
            .unwrap(),
            intended_realm_id: RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            )
            .unwrap(),
            claim_id: NonEmptyString::new("keypackage-claim").unwrap(),
            requester_actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            trust_binding: MlsRequesterTrustBinding::RequesterDevice {
                requester_device_id: DeviceId::new(
                    "ak:device:01904100-0000-7000-8000-000000000001",
                )
                .unwrap(),
                requester_device_authorize_event_id: EventId::from_event_digest(
                    &Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                )
                .unwrap(),
            },
            welcome_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            created_at,
            signature: KeyOperationSignature {
                kid: NonEmptyString::new("did:webvh:z6mkfixture:alice.example#device").unwrap(),
                signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
                sig: Base64UrlString::new("signature").unwrap(),
            },
        }
    }

    #[test]
    fn welcome_claim_envelope_timestamp_serializes_canonical_milliseconds() {
        let created_at = DateTime::parse_from_rfc3339("2026-06-23T07:51:12.729Z")
            .unwrap()
            .with_timezone(&Utc);
        let envelope = test_claim_envelope(created_at);

        let value = serde_json::to_value(&envelope).unwrap();

        assert_eq!(value["created_at"], "2026-06-23T07:51:12.729Z");
    }

    #[test]
    fn welcome_claim_envelope_timestamp_rejects_missing_milliseconds() {
        let mut value = serde_json::to_value(test_claim_envelope(
            DateTime::parse_from_rfc3339("2026-06-23T07:51:12.000Z")
                .unwrap()
                .with_timezone(&Utc),
        ))
        .unwrap();
        value["created_at"] = serde_json::json!("2026-06-23T07:51:12Z");

        assert!(serde_json::from_value::<MlsWelcomeClaimEnvelope>(value).is_err());
    }

    #[test]
    fn welcome_carrier_accepts_only_canonical_unpadded_base64url_bytes() {
        let canonical = Base64UrlString::new("AA").unwrap();
        let carrier = MlsWelcomeCarrier::from_base64url(&canonical).unwrap();
        assert_eq!(carrier.welcome_bytes(), &[0]);
        assert_eq!(carrier.ciphertext(), "AA");

        let noncanonical = Base64UrlString::new("AB").unwrap();
        assert!(MlsWelcomeCarrier::from_base64url(&noncanonical).is_err());
        let undecodable = Base64UrlString::new("A").unwrap();
        assert!(MlsWelcomeCarrier::from_base64url(&undecodable).is_err());
        assert!(Base64UrlString::new("AA==").is_err());
        assert!(MlsWelcomeCarrier::new(Vec::new()).is_err());
    }

    #[test]
    fn welcome_payload_fixture_binds_inline_bytes_and_rejects_retired_carriers() {
        let fixture = arkret_schema::embedded_json_artifact(
            "fixtures/keypackage-pairwise-welcome-fixture.json",
        )
        .unwrap();
        let valid = fixture["schema_validation_cases"][0]["instance"].clone();
        let payload: MlsWelcomePayload = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(payload.carrier.welcome_bytes(), &[0]);
        assert_eq!(
            payload.claim_envelope.welcome_digest.as_str(),
            "sha256:6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        assert_eq!(serde_json::to_value(&payload).unwrap(), valid);

        let signing_input = payload
            .claim_envelope
            .signing_input(&payload.claim_receipt)
            .unwrap();
        let unsigned =
            UnsignedMlsWelcomeClaimEnvelope::new(signing_input.clone(), &payload.claim_receipt)
                .unwrap();
        let transcript: Value =
            serde_json::from_slice(&unsigned.canonical_signing_bytes().unwrap()).unwrap();
        assert_eq!(
            transcript["claim_request_id"],
            payload.claim_receipt.claim_request_id.as_str()
        );
        let mut mismatched_authoring_context = payload.claim_receipt;
        mismatched_authoring_context.request.claim_request_id =
            Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAQ").unwrap();
        assert!(
            UnsignedMlsWelcomeClaimEnvelope::new(signing_input, &mismatched_authoring_context)
                .is_err()
        );

        let mut retired_nonce = valid.clone();
        retired_nonce["claim_envelope"]["nonce"] = serde_json::json!("legacy");
        assert!(serde_json::from_value::<MlsWelcomePayload>(retired_nonce).is_err());

        let mut mismatched_receipt_context = valid.clone();
        mismatched_receipt_context["claim_receipt"]["request"]["claim_request_id"] =
            serde_json::json!("AAAAAAAAAAAAAAAAAAAAAQ");
        assert!(serde_json::from_value::<MlsWelcomePayload>(mismatched_receipt_context).is_err());

        for retired_field in ["welcome_ref", "encrypted_welcome_ref"] {
            let mut invalid = valid.clone();
            invalid[retired_field] = serde_json::json!(
                "ak:blob:sha256:8888888888888888888888888888888888888888888888888888888888888888"
            );
            assert!(serde_json::from_value::<MlsWelcomePayload>(invalid).is_err());
        }
        for invalid_ciphertext in ["AA==", "AB", "A"] {
            let mut invalid = valid.clone();
            invalid["ciphertext"] = serde_json::json!(invalid_ciphertext);
            assert!(serde_json::from_value::<MlsWelcomePayload>(invalid).is_err());
        }
        let mut invalid_digest = valid;
        invalid_digest["claim_envelope"]["welcome_digest"] = serde_json::json!(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert!(serde_json::from_value::<MlsWelcomePayload>(invalid_digest).is_err());
    }

    #[test]
    fn native_agent_claim_ref_requires_exclusive_authorization_binding() {
        let value = serde_json::json!({
            "claim_id": "claim-1",
            "keypackage_ref": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "keypackage_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "capabilities_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "agent_key_authorize_event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        });
        let claim_ref = serde_json::from_value::<MlsWelcomePayloadClaimRef>(value.clone()).unwrap();
        assert!(matches!(
            claim_ref.trust_binding,
            MlsClaimTrustBinding::AgentKeyAuthorizeEventId(_)
        ));

        let mut mixed = value;
        mixed["device_authorize_event_id"] =
            serde_json::json!("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1");
        assert!(serde_json::from_value::<MlsWelcomePayloadClaimRef>(mixed).is_err());
    }

    #[test]
    fn message_redact_payload_carries_only_the_registered_target() {
        let payload = MessageRedactPayload {
            message_id: MessageId::new(
                "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            )
            .unwrap(),
            track_name: None,
            reason: Some("author_redaction".to_owned()),
            preserve: None,
            mimi_provenance: None,
        };

        let value = serde_json::to_value(payload).unwrap();

        assert_eq!(
            value["message_id"],
            "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        );
    }

    #[test]
    fn mls_governance_binding_uses_single_security_frontier_digest() {
        let value = serde_json::json!({
            "binding_version": 1,
            "encoding_profile": "cbor-deterministic-rfc8949-v1",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "mls_group_id": "Z3JvdXA",
            "previous_epoch": 0,
            "next_epoch": 1,
            "security_frontier_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "content_scheme": "mls_exporter_aead_v1",
            "durability_policy": "none",
            "binding_profile": "ak.profile.mls_governance_binding.full.v1",
            "reducer_profile": "ak.reducer.control_state.v1"
        });

        let binding = serde_json::from_value::<MlsGovernanceBindingPayload>(value).unwrap();

        assert_eq!(
            binding.security_frontier_digest().as_str(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }
}
