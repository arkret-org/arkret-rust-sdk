//! MLS transport envelope wire shapes.
//!
//! Proposal / commit / welcome envelopes carried by MLS repo operations
//! and device-message delivery. The event-draft binding (building a local scheduler draft
//! from one of these envelopes) lives in `arkret-event-draft` as an
//! extension trait — this crate holds the data shapes and the deterministic
//! CBOR codec only.

use arkret_wire::{DeviceId, DidCoreId, DidUrl, EventId, Hash, MlsGroupId};
use serde::{Deserialize, Serialize};

use crate::MlsEndpointIdentity;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsProposalEnvelope {
    pub group_id: MlsGroupId,
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
    pub group_id: MlsGroupId,
    pub epoch: u64,
    pub commit: String,
    pub commit_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeEnvelope {
    pub group_id: MlsGroupId,
    pub epoch: u64,
    pub recipient: MlsEndpointIdentity,
    pub welcome: String,
    pub welcome_hash: Hash,
    pub ratchet_tree: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsWelcomeEnvelopeWire {
    group_id: MlsGroupId,
    epoch: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_principal_id: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_device_id: Option<DeviceId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_agent_id: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    recipient_agent_verification_method: Option<DidUrl>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    agent_key_authorize_event_id: Option<EventId>,
    welcome: String,
    welcome_hash: Hash,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    ratchet_tree: Option<String>,
}

impl Serialize for MlsWelcomeEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (
            recipient_principal_id,
            recipient_device_id,
            recipient_agent_id,
            method,
            authorization_ref,
        ) = match &self.recipient {
            MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } => (
                Some(principal_id.clone()),
                Some(device_id.clone()),
                None,
                None,
                None,
            ),
            MlsEndpointIdentity::AgentRuntime {
                agent_id,
                verification_method,
                agent_key_authorize_event_id,
            } => (
                Some(agent_id.clone()),
                None,
                Some(agent_id.clone()),
                Some(verification_method.clone()),
                Some(agent_key_authorize_event_id.clone()),
            ),
        };
        MlsWelcomeEnvelopeWire {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            recipient_principal_id,
            recipient_device_id,
            recipient_agent_id,
            recipient_agent_verification_method: method,
            agent_key_authorize_event_id: authorization_ref,
            welcome: self.welcome.clone(),
            welcome_hash: self.welcome_hash.clone(),
            ratchet_tree: self.ratchet_tree.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MlsWelcomeEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsWelcomeEnvelopeWire::deserialize(deserializer)?;
        let recipient = match (
            wire.recipient_device_id,
            wire.recipient_agent_id,
            wire.recipient_agent_verification_method,
            wire.agent_key_authorize_event_id,
        ) {
            (Some(device_id), None, None, None) => {
                let principal_id = wire.recipient_principal_id.clone().ok_or_else(|| {
                    serde::de::Error::custom("human MLS Welcome requires recipient_principal_id")
                })?;
                MlsEndpointIdentity::human_device(principal_id, device_id)
            }
            (None, Some(agent_id), Some(method), Some(authorization_ref))
                if wire.recipient_principal_id.as_ref() == Some(&agent_id) =>
            {
                MlsEndpointIdentity::agent_runtime(agent_id, method, authorization_ref)
                    .map_err(serde::de::Error::custom)?
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "MLS Welcome must select exactly one human device or Agent endpoint",
                ));
            }
        };
        Ok(Self {
            group_id: wire.group_id,
            epoch: wire.epoch,
            recipient,
            welcome: wire.welcome,
            welcome_hash: wire.welcome_hash,
            ratchet_tree: wire.ratchet_tree,
        })
    }
}
