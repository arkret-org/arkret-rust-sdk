//! MLS transport envelope wire shapes.
//!
//! Proposal / commit / welcome envelopes carried by MLS repo operations
//! and device-message delivery. The event-draft binding (building a local scheduler draft
//! from one of these envelopes) lives in `arkret-event-draft` as an
//! extension trait — this crate holds the data shapes and the deterministic
//! CBOR codec only.

use arkret_wire::{DeviceId, DidCoreId, DidUrl, EventId, Hash};
use serde::{Deserialize, Serialize};

use crate::MlsEndpointIdentity;

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub recipient: MlsEndpointIdentity,
    pub welcome: String,
    pub welcome_hash: Hash,
    pub ratchet_tree: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsWelcomeEnvelopeWire {
    group_id: String,
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
    welcome: String,
    welcome_hash: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
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
                None,
                None,
            ),
            MlsEndpointIdentity::NativeAgentRuntime {
                agent_id,
                verification_method,
                agent_key_authorize_event_id,
            } => (
                Some(agent_id.clone()),
                None,
                Some(agent_id.clone()),
                Some(verification_method.clone()),
                Some(agent_key_authorize_event_id.clone()),
                None,
                None,
            ),
            MlsEndpointIdentity::MinimalMetadataPairwise {
                pairwise_actor_id,
                verification_method,
            } => (
                None,
                None,
                None,
                None,
                None,
                Some(pairwise_actor_id.clone()),
                Some(verification_method.clone()),
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
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
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
            wire.recipient_pairwise_actor_id,
            wire.recipient_pairwise_verification_method,
        ) {
            (Some(device_id), None, None, None, None, None) => {
                let principal_id = wire.recipient_principal_id.clone().ok_or_else(|| {
                    serde::de::Error::custom("human MLS Welcome requires recipient_principal_id")
                })?;
                MlsEndpointIdentity::human_device(principal_id, device_id)
            }
            (None, Some(agent_id), Some(method), Some(authorization_ref), None, None)
                if wire.recipient_principal_id.as_ref() == Some(&agent_id) =>
            {
                MlsEndpointIdentity::native_agent_runtime(agent_id, method, authorization_ref)
                    .map_err(serde::de::Error::custom)?
            }
            (None, None, None, None, Some(actor_id), Some(method))
                if wire.recipient_principal_id.is_none() =>
            {
                MlsEndpointIdentity::minimal_metadata_pairwise(actor_id, method)
                    .map_err(serde::de::Error::custom)?
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "MLS Welcome must select exactly one human device, Native Agent, or minimal-metadata pairwise endpoint",
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
