//! MLS transport envelope wire shapes.
//!
//! Proposal / commit / welcome envelopes carried by MLS repo operations
//! and device-message delivery. The event-draft binding (building a repo `Operation`
//! from one of these envelopes) lives in `arkret-event-draft` as an
//! extension trait — this crate holds the data shapes and the deterministic
//! CBOR codec only.

use arkret_wire::{DeviceId, Did, Hash};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsProposalEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub proposal_type: String,
    pub proposal: String,
    pub proposal_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsCommitEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub commit: String,
    pub commit_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsWelcomeEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub welcome: String,
    pub welcome_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}
