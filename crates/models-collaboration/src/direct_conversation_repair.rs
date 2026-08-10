//! Durable Direct Conversation replacement-repair dispatch and peer relay DTOs.
//!
//! Mirrors the repair definitions in
//! `schemas/direct-conversation-operations.schema.json`. These operations carry
//! a non-authorizing trigger only; Commit, Welcome and activation remain Events.

use arkret_models_identity::CurrentAgentSignerEvidence;
use arkret_wire::{
    Base64UrlString, DeviceId, DidCoreId, DidUrl, EventId, FederatedDeviceSigningKeyEvidence, Hash,
    ProtocolSignature,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::{MemberRepairRequestPayload, MemberRepairRequester};

pub const DIRECT_CONVERSATION_REPAIR_DISPATCH_DOMAIN: &[u8] =
    b"ak.direct-conversation-repair-dispatch-v1\n";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationRepairAuthorization {
    Device {
        requester_device_id: DeviceId,
        verification_method: DidUrl,
        device_authorize_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        signed_at: DateTime<Utc>,
        signature: ProtocolSignature,
    },
    NativeAgent {
        requester_agent_id: DidCoreId,
        verification_method: DidUrl,
        agent_key_authorize_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        signed_at: DateTime<Utc>,
        signature: ProtocolSignature,
    },
}

impl DirectConversationRepairAuthorization {
    pub fn validate_against_content(
        &self,
        content: &MemberRepairRequestPayload,
    ) -> arkret_wire::Result<()> {
        let valid = match (self, &content.requester) {
            (
                Self::Device {
                    requester_device_id,
                    verification_method,
                    signed_at,
                    signature,
                    ..
                },
                MemberRepairRequester::Device {
                    requester_device_id: content_device_id,
                },
            ) => {
                requester_device_id == content_device_id
                    && verification_method == &signature.verification_method
                    && signed_at == &signature.created_at
            }
            (
                Self::NativeAgent {
                    requester_agent_id,
                    verification_method,
                    agent_key_authorize_event_id,
                    signed_at,
                    signature,
                },
                MemberRepairRequester::NativeAgent {
                    requester_agent_id: content_agent_id,
                    requester_agent_verification_method,
                    agent_key_authorize_event_id: content_authorize_event_id,
                },
            ) => {
                requester_agent_id == content_agent_id
                    && requester_agent_id.as_core_id()
                        == content.requester_principal_id.as_core_id()
                    && verification_method == requester_agent_verification_method
                    && agent_key_authorize_event_id == content_authorize_event_id
                    && verification_method == &signature.verification_method
                    && signed_at == &signature.created_at
            }
            _ => false,
        };
        if !valid {
            return Err(arkret_wire::Error::Protocol(
                "repair authorization does not match repair content".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[allow(clippy::large_enum_variant)]
pub enum DirectConversationRepairRequesterEvidence {
    Device {
        #[cfg_attr(
            feature = "openapi",
            salvo(schema(value_type = serde_json::Value))
        )]
        device_authorization_evidence: FederatedDeviceSigningKeyEvidence,
    },
    NativeAgent {
        agent_signer_evidence: CurrentAgentSignerEvidence,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationRepairDispatchRequest {
    pub request_id: Base64UrlString,
    pub content: MemberRepairRequestPayload,
    pub requester_authorization: DirectConversationRepairAuthorization,
}

impl DirectConversationRepairDispatchRequest {
    pub fn signing_input(&self) -> arkret_wire::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningMaterial<'a> {
            request_id: &'a Base64UrlString,
            content: &'a MemberRepairRequestPayload,
        }
        let canonical = arkret_canonical::canonical_json_bytes(&SigningMaterial {
            request_id: &self.request_id,
            content: &self.content,
        })
        .map_err(protocol_error)?;
        let mut input =
            Vec::with_capacity(DIRECT_CONVERSATION_REPAIR_DISPATCH_DOMAIN.len() + canonical.len());
        input.extend_from_slice(DIRECT_CONVERSATION_REPAIR_DISPATCH_DOMAIN);
        input.extend_from_slice(&canonical);
        Ok(input)
    }

    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if !(22..=128).contains(&self.request_id.as_str().len()) {
            return Err(arkret_wire::Error::Protocol(
                "repair request_id length is invalid".to_owned(),
            ));
        }
        self.content.validate()?;
        self.requester_authorization
            .validate_against_content(&self.content)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationRepairRelayRequest {
    pub request_id: Base64UrlString,
    pub content: MemberRepairRequestPayload,
    pub requester_authorization: DirectConversationRepairAuthorization,
    pub requester_evidence: DirectConversationRepairRequesterEvidence,
}

impl DirectConversationRepairRelayRequest {
    pub fn dispatch_request(&self) -> DirectConversationRepairDispatchRequest {
        DirectConversationRepairDispatchRequest {
            request_id: self.request_id.clone(),
            content: self.content.clone(),
            requester_authorization: self.requester_authorization.clone(),
        }
    }

    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        self.dispatch_request().validate_shape()?;
        let valid = match (&self.requester_authorization, &self.requester_evidence) {
            (
                DirectConversationRepairAuthorization::Device {
                    requester_device_id,
                    verification_method,
                    device_authorize_event_id,
                    ..
                },
                DirectConversationRepairRequesterEvidence::Device {
                    device_authorization_evidence: evidence,
                },
            ) => {
                evidence.validate_shape().is_ok()
                    && evidence.actor_id.as_str() == self.content.requester_principal_id.as_str()
                    && &evidence.device_id == requester_device_id
                    && evidence.verification_method == verification_method.as_str()
                    && evidence
                        .current_device_projection
                        .device_record
                        .device_authorize_event_id
                        .as_ref()
                        .is_some_and(|event_id| {
                            event_id.as_str() == device_authorize_event_id.as_str()
                        })
            }
            (
                DirectConversationRepairAuthorization::NativeAgent {
                    requester_agent_id,
                    verification_method,
                    agent_key_authorize_event_id,
                    ..
                },
                DirectConversationRepairRequesterEvidence::NativeAgent {
                    agent_signer_evidence: evidence,
                },
            ) => {
                let binding = &evidence
                    .admission_evidence
                    .agent_authority_snapshot
                    .core
                    .signing_key_binding;
                binding.core.agent_id.as_str() == requester_agent_id.as_str()
                    && &binding.core.verification_method == verification_method
                    && &binding.agent_key_authorize_event_id == agent_key_authorize_event_id
            }
            _ => false,
        };
        if !valid {
            return Err(arkret_wire::Error::Protocol(
                "repair requester evidence branch is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationRepairRecipientTarget {
    HumanPrincipal {
        target_snapshot_digest: Hash,
        enqueued_target_count: u64,
    },
    NativeAgent {
        target_snapshot_digest: Hash,
        enqueued_target_count: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationRepairEnqueueStatus {
    Enqueued,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationRepairEnqueueOutcome {
    pub request_id: Base64UrlString,
    pub request_digest: Hash,
    pub destination_service_id: DidCoreId,
    pub status: DirectConversationRepairEnqueueStatus,
    pub recipient_target: DirectConversationRepairRecipientTarget,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

impl DirectConversationRepairEnqueueOutcome {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        let count = match &self.recipient_target {
            DirectConversationRepairRecipientTarget::HumanPrincipal {
                enqueued_target_count,
                ..
            } if *enqueued_target_count > 0 => *enqueued_target_count,
            DirectConversationRepairRecipientTarget::NativeAgent {
                enqueued_target_count: 1,
                ..
            } => 1,
            _ => 0,
        };
        if count == 0 {
            return Err(arkret_wire::Error::Protocol(
                "repair enqueue outcome has an invalid closed target count".to_owned(),
            ));
        }
        Ok(())
    }
}

fn protocol_error(error: impl std::fmt::Display) -> arkret_wire::Error {
    arkret_wire::Error::Protocol(error.to_string())
}
