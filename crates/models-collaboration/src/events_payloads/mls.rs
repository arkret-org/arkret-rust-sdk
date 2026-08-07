//! MLS lifecycle event payloads.

use std::num::NonZeroU64;

use arkret_canonical::serde_helpers::{canonical_timestamp, serialize_canonical_timestamp};
use arkret_models_crypto::PeerKeyPackageClaimReceipt;

use crate::internal_prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsCommitFailureStage {
    WelcomeDecrypt,
    TranscriptVerify,
    GovernanceBinding,
    GroupStateUpdate,
    KeypackageClaim,
    PolicyRootMismatch,
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
    ExternalInit,
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
    SskGeneration(NonZeroU64),
    DeviceAuthorizeEventId(NonEmptyString),
    AgentKeyAuthorizeEventId(NonEmptyString),
}

impl MlsClaimTrustBinding {
    pub fn ssk_generation(&self) -> Option<u64> {
        match self {
            Self::SskGeneration(generation) => Some(generation.get()),
            Self::DeviceAuthorizeEventId(_) | Self::AgentKeyAuthorizeEventId(_) => None,
        }
    }

    pub fn device_authorize_event_id(&self) -> Option<&str> {
        match self {
            Self::SskGeneration(_) => None,
            Self::DeviceAuthorizeEventId(event_id) => Some(event_id.as_str()),
            Self::AgentKeyAuthorizeEventId(_) => None,
        }
    }

    pub fn agent_key_authorize_event_id(&self) -> Option<&str> {
        match self {
            Self::SskGeneration(_) | Self::DeviceAuthorizeEventId(_) => None,
            Self::AgentKeyAuthorizeEventId(event_id) => Some(event_id.as_str()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsRequesterTrustBinding {
    SskGeneration(NonZeroU64),
    RequesterDeviceId(DeviceId),
}

impl MlsRequesterTrustBinding {
    pub fn ssk_generation(&self) -> Option<u64> {
        match self {
            Self::SskGeneration(generation) => Some(generation.get()),
            Self::RequesterDeviceId(_) => None,
        }
    }

    pub fn requester_device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::SskGeneration(_) => None,
            Self::RequesterDeviceId(device_id) => Some(device_id),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeCarrier {
    welcome_ref: Option<ObjectRef>,
    encrypted_welcome_ref: Option<ObjectRef>,
    ciphertext: Option<NonEmptyString>,
}

impl MlsWelcomeCarrier {
    pub fn new(
        welcome_ref: Option<ObjectRef>,
        encrypted_welcome_ref: Option<ObjectRef>,
        ciphertext: Option<NonEmptyString>,
    ) -> std::result::Result<Self, &'static str> {
        if welcome_ref.is_none() && encrypted_welcome_ref.is_none() && ciphertext.is_none() {
            return Err(
                "MLS Welcome carrier must include welcome_ref, encrypted_welcome_ref, or ciphertext",
            );
        }
        Ok(Self {
            welcome_ref,
            encrypted_welcome_ref,
            ciphertext,
        })
    }

    pub fn welcome_ref(&self) -> Option<&str> {
        self.welcome_ref.as_deref()
    }

    pub fn encrypted_welcome_ref(&self) -> Option<&str> {
        self.encrypted_welcome_ref.as_deref()
    }

    pub fn ciphertext(&self) -> Option<&str> {
        self.ciphertext.as_deref()
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_commit_failed_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCommitFailedPayload {
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
    pub creator_principal_id: Did,
    pub creator_device_id: DeviceId,
    pub cipher_suite: NonEmptyString,
    pub group_info_ref: BlobRef,
    pub group_info_digest: Hash,
    pub ratchet_tree_ref: BlobRef,
    pub ratchet_tree_digest: Hash,
    pub initial_keypackage_refs: Option<Vec<ObjectRef>>,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsGenesisPayloadWire {
    mls_group_id: MlsGroupId,
    effective_scope: ScopeRef,
    epoch: MlsGenesisEpoch,
    creator_principal_id: Did,
    creator_device_id: DeviceId,
    cipher_suite: NonEmptyString,
    group_info_ref: BlobRef,
    group_info_digest: Hash,
    ratchet_tree_ref: BlobRef,
    ratchet_tree_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initial_keypackage_refs: Option<Vec<ObjectRef>>,
    governance_binding: MlsGovernanceBindingPayload,
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
            return Err(Error::Protocol(
                "mls_genesis_payload governance binding does not match the group and scope"
                    .to_owned(),
            ));
        }
        if let Some(refs) = &self.initial_keypackage_refs {
            let unique = refs.iter().collect::<std::collections::BTreeSet<_>>();
            if unique.len() != refs.len() {
                return Err(Error::Protocol(
                    "mls_genesis_payload initial_keypackage_refs must be unique".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl Serialize for MlsGenesisPayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        MlsGenesisPayloadWire {
            mls_group_id: self.mls_group_id.clone(),
            effective_scope: self.effective_scope.clone(),
            epoch: self.epoch,
            creator_principal_id: self.creator_principal_id.clone(),
            creator_device_id: self.creator_device_id.clone(),
            cipher_suite: self.cipher_suite.clone(),
            group_info_ref: self.group_info_ref.clone(),
            group_info_digest: self.group_info_digest.clone(),
            ratchet_tree_ref: self.ratchet_tree_ref.clone(),
            ratchet_tree_digest: self.ratchet_tree_digest.clone(),
            initial_keypackage_refs: self.initial_keypackage_refs.clone(),
            governance_binding: self.governance_binding.clone(),
            created_at: self.created_at,
        }
        .serialize(serializer)
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
            creator_principal_id: wire.creator_principal_id,
            creator_device_id: wire.creator_device_id,
            cipher_suite: wire.cipher_suite,
            group_info_ref: wire.group_info_ref,
            group_info_digest: wire.group_info_digest,
            ratchet_tree_ref: wire.ratchet_tree_ref,
            ratchet_tree_digest: wire.ratchet_tree_digest,
            initial_keypackage_refs: wire.initial_keypackage_refs,
            governance_binding: wire.governance_binding,
            created_at: wire.created_at,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

// `MlsKeyPackageState` moved to `arkret-models-crypto` (mls_records) so the MLS
// behavior layer can reach it without depending on this crate. Re-exported here
// to keep the public `events_payloads::MlsKeyPackageState` path stable.
pub use arkret_models_crypto::MlsKeyPackageState;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_keypackage_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsKeypackagePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_id: Option<NonEmptyString>,
    pub principal_id: Did,
    pub device_id: DeviceId,
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
    pub device_signature: SignatureMaterial,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_proposal_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MlsProposalPayload {
    pub mls_group_id: MlsGroupId,
    pub base_epoch: u64,
    pub proposal_type: MlsProposalType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_message_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_binding: Option<MlsGovernanceBindingPayload>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsProposalPayloadWire {
    mls_group_id: MlsGroupId,
    base_epoch: u64,
    proposal_type: MlsProposalType,
    #[serde(default)]
    proposal_message_ref: Option<ObjectRef>,
    #[serde(default)]
    proposal_digest: Option<Hash>,
    #[serde(default)]
    target_principal_id: Option<Did>,
    #[serde(default)]
    target_device_id: Option<DeviceId>,
    #[serde(default)]
    governance_binding: Option<MlsGovernanceBindingPayload>,
}

impl<'de> Deserialize<'de> for MlsProposalPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsProposalPayloadWire::deserialize(deserializer)?;
        if wire.proposal_message_ref.is_none() && wire.proposal_digest.is_none() {
            return Err(serde::de::Error::custom(
                "mls_proposal_payload requires proposal_message_ref or proposal_digest",
            ));
        }
        if let Some(binding) = &wire.governance_binding
            && binding.mls_group_id() != wire.mls_group_id.as_str()
        {
            return Err(serde::de::Error::custom(
                "mls_proposal_payload governance binding does not match mls_group_id",
            ));
        }
        Ok(Self {
            mls_group_id: wire.mls_group_id,
            base_epoch: wire.base_epoch,
            proposal_type: wire.proposal_type,
            proposal_message_ref: wire.proposal_message_ref,
            proposal_digest: wire.proposal_digest,
            target_principal_id: wire.target_principal_id,
            target_device_id: wire.target_device_id,
            governance_binding: wire.governance_binding,
        })
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
    pub requester_did: Did,
    pub trust_binding: MlsRequesterTrustBinding,
    pub nonce: NonEmptyString,
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
    pub requester_did: Did,
    pub trust_binding: MlsRequesterTrustBinding,
    pub nonce: NonEmptyString,
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
    ssk_generation: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_authorize_event_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_key_authorize_event_id: Option<NonEmptyString>,
}

impl Serialize for MlsWelcomePayloadClaimRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (ssk_generation, device_authorize_event_id, agent_key_authorize_event_id) =
            match &self.trust_binding {
                MlsClaimTrustBinding::SskGeneration(generation) => (Some(*generation), None, None),
                MlsClaimTrustBinding::DeviceAuthorizeEventId(event_id) => {
                    (None, Some(event_id.clone()), None)
                }
                MlsClaimTrustBinding::AgentKeyAuthorizeEventId(event_id) => {
                    (None, None, Some(event_id.clone()))
                }
            };
        MlsWelcomePayloadClaimRefWire {
            claim_id: self.claim_id.clone(),
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            capabilities_digest: self.capabilities_digest.clone(),
            ssk_generation,
            device_authorize_event_id,
            agent_key_authorize_event_id,
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
            wire.ssk_generation,
            wire.device_authorize_event_id,
            wire.agent_key_authorize_event_id,
        ) {
            (Some(generation), None, None) => MlsClaimTrustBinding::SskGeneration(generation),
            (None, Some(event_id), None) => MlsClaimTrustBinding::DeviceAuthorizeEventId(event_id),
            (None, None, Some(event_id)) => {
                MlsClaimTrustBinding::AgentKeyAuthorizeEventId(event_id)
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
    requester_did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssk_generation: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_device_id: Option<DeviceId>,
    nonce: NonEmptyString,
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
        let (ssk_generation, requester_device_id) = match &self.trust_binding {
            MlsRequesterTrustBinding::SskGeneration(generation) => (Some(*generation), None),
            MlsRequesterTrustBinding::RequesterDeviceId(device_id) => {
                (None, Some(device_id.clone()))
            }
        };
        MlsWelcomeClaimEnvelopeWire {
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            claim_id: self.claim_id.clone(),
            requester_did: self.requester_did.clone(),
            ssk_generation,
            requester_device_id,
            nonce: self.nonce.clone(),
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
        let trust_binding = match (wire.ssk_generation, wire.requester_device_id) {
            (Some(generation), None) => MlsRequesterTrustBinding::SskGeneration(generation),
            (None, Some(device_id)) => MlsRequesterTrustBinding::RequesterDeviceId(device_id),
            _ => {
                return Err(serde::de::Error::custom(
                    "claim_envelope must contain exactly one requester trust binding",
                ));
            }
        };
        Ok(Self {
            keypackage_ref: wire.keypackage_ref,
            keypackage_digest: wire.keypackage_digest,
            intended_realm_id: wire.intended_realm_id,
            claim_id: wire.claim_id,
            requester_did: wire.requester_did,
            trust_binding,
            nonce: wire.nonce,
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
    requester_did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssk_generation: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester_device_id: Option<DeviceId>,
    nonce: NonEmptyString,
    welcome_digest: Hash,
    #[serde(serialize_with = "serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

impl Serialize for MlsWelcomeClaimEnvelopeSigningInput {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (ssk_generation, requester_device_id) = match &self.trust_binding {
            MlsRequesterTrustBinding::SskGeneration(generation) => (Some(*generation), None),
            MlsRequesterTrustBinding::RequesterDeviceId(device_id) => {
                (None, Some(device_id.clone()))
            }
        };
        MlsWelcomeClaimEnvelopeSigningInputWire {
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            claim_id: self.claim_id.clone(),
            requester_did: self.requester_did.clone(),
            ssk_generation,
            requester_device_id,
            nonce: self.nonce.clone(),
            welcome_digest: self.welcome_digest.clone(),
            created_at: self.created_at,
        }
        .serialize(serializer)
    }
}

impl MlsWelcomeClaimEnvelope {
    pub fn signing_input(&self) -> MlsWelcomeClaimEnvelopeSigningInput {
        MlsWelcomeClaimEnvelopeSigningInput {
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            claim_id: self.claim_id.clone(),
            requester_did: self.requester_did.clone(),
            trust_binding: self.trust_binding.clone(),
            nonce: self.nonce.clone(),
            welcome_digest: self.welcome_digest.clone(),
            created_at: self.created_at,
        }
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(&self.signing_input())?)
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
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MlsWelcomePayload {
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub sender_device_id: Option<DeviceId>,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub claim_id: NonEmptyString,
    pub claim_ref: MlsWelcomePayloadClaimRef,
    pub claim_envelope: MlsWelcomeClaimEnvelope,
    pub peer_claim_receipt: Option<PeerKeyPackageClaimReceipt>,
    pub carrier: MlsWelcomeCarrier,
    pub commit_ref: Option<EventId>,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsWelcomePayloadWire {
    mls_group_id: MlsGroupId,
    epoch: u64,
    recipient_principal_id: Did,
    recipient_device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender_device_id: Option<DeviceId>,
    keypackage_ref: ObjectRef,
    keypackage_digest: Hash,
    claim_id: NonEmptyString,
    claim_ref: MlsWelcomePayloadClaimRef,
    claim_envelope: MlsWelcomeClaimEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_claim_receipt: Option<PeerKeyPackageClaimReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    welcome_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_welcome_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_ref: Option<EventId>,
    governance_binding: MlsGovernanceBindingPayload,
    #[serde(with = "canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

impl Serialize for MlsWelcomePayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        MlsWelcomePayloadWire {
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
            recipient_principal_id: self.recipient_principal_id.clone(),
            recipient_device_id: self.recipient_device_id.clone(),
            sender_device_id: self.sender_device_id.clone(),
            keypackage_ref: self.keypackage_ref.clone(),
            keypackage_digest: self.keypackage_digest.clone(),
            claim_id: self.claim_id.clone(),
            claim_ref: self.claim_ref.clone(),
            claim_envelope: self.claim_envelope.clone(),
            peer_claim_receipt: self.peer_claim_receipt.clone(),
            welcome_ref: self.carrier.welcome_ref.clone(),
            encrypted_welcome_ref: self.carrier.encrypted_welcome_ref.clone(),
            ciphertext: self.carrier.ciphertext.clone(),
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
        let carrier = MlsWelcomeCarrier::new(
            wire.welcome_ref,
            wire.encrypted_welcome_ref,
            wire.ciphertext,
        )
        .map_err(serde::de::Error::custom)?;
        if wire.governance_binding.mls_group_id() != wire.mls_group_id.as_str()
            || wire.governance_binding.next_epoch() != wire.epoch
        {
            return Err(serde::de::Error::custom(
                "mls_welcome_payload governance binding does not match group and epoch",
            ));
        }
        if wire.claim_ref.claim_id != wire.claim_id
            || wire.claim_ref.keypackage_ref != wire.keypackage_ref
            || wire.claim_ref.keypackage_digest != wire.keypackage_digest
            || wire.claim_envelope.claim_id != wire.claim_id
            || wire.claim_envelope.keypackage_ref != wire.keypackage_ref
            || wire.claim_envelope.keypackage_digest != wire.keypackage_digest
        {
            return Err(serde::de::Error::custom(
                "mls_welcome_payload claim bindings do not match top-level fields",
            ));
        }
        Ok(Self {
            mls_group_id: wire.mls_group_id,
            epoch: wire.epoch,
            recipient_principal_id: wire.recipient_principal_id,
            recipient_device_id: wire.recipient_device_id,
            sender_device_id: wire.sender_device_id,
            keypackage_ref: wire.keypackage_ref,
            keypackage_digest: wire.keypackage_digest,
            claim_id: wire.claim_id,
            claim_ref: wire.claim_ref,
            claim_envelope: wire.claim_envelope,
            peer_claim_receipt: wire.peer_claim_receipt,
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
    requester_did: &Did,
    welcome_digest: &Hash,
    claim_nonce: &str,
    current_claim_ssk_generation: Option<u64>,
    current_claim_device_authorize_event_id: Option<&str>,
    current_claim_agent_key_authorize_event_id: Option<&str>,
    current_requester_ssk_generation: Option<u64>,
    current_requester_device_id: Option<&str>,
) -> std::result::Result<(), &'static str> {
    if welcome.keypackage_ref != claim.keypackage_ref
        || welcome.claim_id.as_str() != claim.claim_id
        || welcome.claim_ref.claim_id.as_str() != claim.claim_id
        || welcome.claim_ref.keypackage_ref != claim.keypackage_ref
        || published.keypackage_ref != claim.keypackage_ref
        || welcome.keypackage_digest.as_str() != claim.keypackage_digest.as_str()
        || welcome.claim_ref.keypackage_digest.as_str() != claim.keypackage_digest.as_str()
        || published.keypackage_digest.as_str() != claim.keypackage_digest.as_str()
        || welcome.claim_ref.capabilities_digest.as_str() != claim.capabilities_digest.as_str()
        || welcome.claim_ref.trust_binding.ssk_generation() != claim.ssk_generation
        || welcome.claim_ref.trust_binding.device_authorize_event_id()
            != claim.device_authorize_event_id.as_deref()
        || welcome
            .claim_ref
            .trust_binding
            .agent_key_authorize_event_id()
            != claim.agent_key_authorize_event_id.as_deref()
    {
        return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    validate_claim_trust_binding(
        &welcome.claim_ref.trust_binding,
        current_claim_ssk_generation,
        current_claim_device_authorize_event_id,
        current_claim_agent_key_authorize_event_id,
    )?;

    let envelope = &welcome.claim_envelope;
    if envelope.keypackage_ref != claim.keypackage_ref
        || envelope.keypackage_digest.as_str() != claim.keypackage_digest.as_str()
        || envelope.intended_realm_id != *intended_realm_id
        || envelope.claim_id.as_str() != claim.claim_id
        || envelope.requester_did != *requester_did
        || envelope.nonce.as_str() != claim_nonce
        || envelope.welcome_digest.as_str() != welcome_digest.as_str()
    {
        return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    validate_requester_signature_binding(
        &envelope.trust_binding,
        current_requester_ssk_generation,
        current_requester_device_id,
    )?;
    envelope.validate_signature_shape()?;
    if envelope.created_at > claim.expires_at || welcome.expires_at > claim.expires_at {
        return Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}

fn validate_claim_trust_binding(
    trust_binding: &MlsClaimTrustBinding,
    current_claim_ssk_generation: Option<u64>,
    current_claim_device_authorize_event_id: Option<&str>,
    current_claim_agent_key_authorize_event_id: Option<&str>,
) -> std::result::Result<(), &'static str> {
    match trust_binding {
        MlsClaimTrustBinding::SskGeneration(generation)
            if Some(generation.get()) == current_claim_ssk_generation =>
        {
            Ok(())
        }
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
        _ => Err(ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH),
    }
}

fn validate_requester_signature_binding(
    trust_binding: &MlsRequesterTrustBinding,
    current_requester_ssk_generation: Option<u64>,
    current_requester_device_id: Option<&str>,
) -> std::result::Result<(), &'static str> {
    match trust_binding {
        MlsRequesterTrustBinding::SskGeneration(generation)
            if Some(generation.get()) == current_requester_ssk_generation =>
        {
            Ok(())
        }
        MlsRequesterTrustBinding::RequesterDeviceId(device_id)
            if Some(device_id.as_str()) == current_requester_device_id =>
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
            claim_id: NonEmptyString::new("ak:mls:kp:claim").unwrap(),
            requester_did: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            trust_binding: MlsRequesterTrustBinding::RequesterDeviceId(
                DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            ),
            nonce: NonEmptyString::new("nonce").unwrap(),
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
    fn message_redact_payload_event_fields_serialize_as_schema_strings() {
        let payload = MessageRedactPayload {
            message_id: None,
            target_ref: None,
            event_id: None,
            target_event_id: Some(
                EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            ),
            track_name: None,
            reason: Some("author_redaction".to_owned()),
            preserve: None,
        };

        let value = serde_json::to_value(payload).unwrap();

        assert_eq!(
            value["target_event_id"],
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        );
        assert!(value.get("event_id").is_none());
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
