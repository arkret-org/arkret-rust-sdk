//! MLS event payloads under governance-Station commit finality.

pub use arkret_models_crypto::MlsCommitPayload;
use arkret_models_crypto::{MlsGovernanceBindingPayload, MlsKeyPackageState};
pub use arkret_wire::MlsCommitSubmission;
use arkret_wire::{
    ActorId, BlobRef, DeviceId, DidCoreId, DidUrl, EventId, Hash, MlsGroupId, MlsWelcomeDelivery,
    MlsWelcomeRecipientEndpoint, NonEmptyString, ObjectRef, RealmId, Result, ScopeRef, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MlsCommitFailureStage {
    WelcomeDecrypt,
    TranscriptVerify,
    GovernanceBinding,
    GroupStateUpdate,
    KeypackageClaim,
    UnsupportedCipherSuite,
    StorageFailure,
    UnknownEpoch,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(try_from = "u64", into = "u64")]
pub struct MlsGenesisEpoch;

impl TryFrom<u64> for MlsGenesisEpoch {
    type Error = &'static str;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        (value == 0)
            .then_some(Self)
            .ok_or("MLS genesis epoch must be 0")
    }
}

impl From<MlsGenesisEpoch> for u64 {
    fn from(_: MlsGenesisEpoch) -> Self {
        0
    }
}

/// `ak.mls.genesis` payload. Group ordering starts when the containing Event is
/// accepted into the scope's independent Realm/Circle/Sidecar commit stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGenesisPayload {
    pub cipher_suite: NonEmptyString,
    pub group_info_ref: BlobRef,
    pub ratchet_tree_ref: BlobRef,
    pub governance_binding: MlsGovernanceBindingPayload,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl MlsGenesisPayload {
    pub fn validate(&self) -> Result<()> {
        self.governance_binding.validate()?;
        if self.governance_binding.previous_epoch() != 0
            || self.governance_binding.next_epoch() != 0
            || self.governance_binding.base_group_state_ref().is_some()
        {
            return Err(WireError::Protocol(
                "MLS Genesis must use the epoch-zero governance binding".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn effective_scope(&self) -> &ScopeRef {
        self.governance_binding.effective_scope()
    }

    pub fn mls_group_id(&self) -> Result<String> {
        self.governance_binding.mls_group_id()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsCommitFailedPayload {
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub commit_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_ref: Option<EventId>,
    pub epoch: u64,
    pub failure_stage: MlsCommitFailureStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub failed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsEpochRange {
    pub first_epoch: u64,
    pub last_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsKeypackagePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_id: Option<NonEmptyString>,
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_verification_method: Option<DidUrl>,
    pub keypackage_ref: ObjectRef,
    pub keypackage_digest: Hash,
    pub cipher_suites: Vec<String>,
    pub state: MlsKeyPackageState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_realm_id: Option<RealmId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsProposalPayload {
    pub mls_group_id: MlsGroupId,
    pub base_epoch: u64,
    pub proposal_type: MlsProposalType,
    pub proposal_bytes_b64: String,
    pub proposal_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<ActorId>,
    pub governance_binding: MlsGovernanceBindingPayload,
}

// Keep the transport artifacts discoverable from the payload namespace.
pub type MlsWelcomeArtifact = MlsWelcomeDelivery;
pub type MlsWelcomeEndpoint = MlsWelcomeRecipientEndpoint;
