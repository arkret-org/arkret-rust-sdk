//! Durable Direct Conversation replacement-repair dispatch and peer relay DTOs.
//!
//! Mirrors the repair definitions in
//! `schemas/direct-conversation-operations.schema.json`. These operations carry
//! a non-authorizing trigger only; Commit, Welcome and activation remain Events.

use arkret_wire::{
    Base64UrlString, DeviceId, DeviceMessageId, DidCoreId, DidUrl, EventId, Hash, ProtocolSignature,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::{MemberRepairRequestPayload, MemberRepairRequester};

pub const DIRECT_CONVERSATION_REPAIR_DISPATCH_DOMAIN: &[u8] =
    b"ak.direct-conversation-repair-dispatch-v1\n";

/// Domain separator of the human-principal member-repair target snapshot
/// transcript (`contact-and-direct-conversation.md` §8.2.1).
pub const MEMBER_REPAIR_TARGET_SNAPSHOT_HUMAN_DOMAIN: &[u8] =
    b"ak.member-repair-target-snapshot-human-v1\n";

/// Domain separator of the Native Agent member-repair target snapshot
/// transcript (`contact-and-direct-conversation.md` §8.2.1).
pub const MEMBER_REPAIR_TARGET_SNAPSHOT_NATIVE_AGENT_DOMAIN: &[u8] =
    b"ak.member-repair-target-snapshot-native-agent-v1\n";

/// One frozen human-device target of a member-repair enqueue batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberRepairHumanTarget {
    pub recipient_device_id: DeviceId,
    pub device_message_id: DeviceMessageId,
}

/// The one frozen Native Agent runtime endpoint of a member-repair enqueue.
///
/// The three `recipient_*` members are the closed Agent endpoint triple the
/// spec uses for every other Agent role (`sender` / `requester` / `consumer` /
/// `target`). §8.2.1 forbids an opaque `*_ref` here: member names enter the JCS
/// preimage verbatim, so hiding `verification_method` and
/// `agent_key_authorize_event_id` behind one string would let two
/// implementations compute different digests from the same endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberRepairNativeAgentTarget {
    pub recipient_agent_id: DidCoreId,
    pub recipient_agent_verification_method: DidUrl,
    pub recipient_agent_key_authorize_event_id: EventId,
    pub device_message_id: DeviceMessageId,
}

/// Canonical `target_snapshot_digest` of a human-principal repair enqueue.
///
/// Targets are sorted by `recipient_device_id` so the transcript is a pure
/// function of the frozen snapshot rather than of enqueue order.
pub fn member_repair_human_target_snapshot_digest(
    targets: &[MemberRepairHumanTarget],
) -> arkret_wire::Result<Hash> {
    let mut sorted = targets.to_vec();
    sorted.sort_by(|left, right| left.recipient_device_id.cmp(&right.recipient_device_id));
    member_repair_snapshot_digest(MEMBER_REPAIR_TARGET_SNAPSHOT_HUMAN_DOMAIN, &sorted)
}

/// Canonical `target_snapshot_digest` of a Native Agent repair enqueue.
pub fn member_repair_native_agent_target_snapshot_digest(
    target: &MemberRepairNativeAgentTarget,
) -> arkret_wire::Result<Hash> {
    member_repair_snapshot_digest(MEMBER_REPAIR_TARGET_SNAPSHOT_NATIVE_AGENT_DOMAIN, target)
}

fn member_repair_snapshot_digest(
    domain: &[u8],
    value: &impl Serialize,
) -> arkret_wire::Result<Hash> {
    let canonical = arkret_canonical::canonical_json_bytes(value).map_err(protocol_error)?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(input)).map_err(protocol_error)
}

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
        self.dispatch_request().validate_shape()
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
