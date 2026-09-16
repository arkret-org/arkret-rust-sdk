//! Message authoring and authority submission DTOs.

use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{
    EncryptedPayloadScheme, EventCommitSubmission, EventKind, Result, ScopeRef, StrandId, WireError,
};
use serde::{Deserialize, Serialize};

use crate::events_payloads::message::{ContentBlock, MessageCreatePayload, MessageTrackName};
use crate::objects::strand::MessageMetadata;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessageEncryptionContext {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub scheme: EncryptedPayloadScheme,
    pub effective_scope: ScopeRef,
    pub sender_domain: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MessageAuthoringContent {
    Plaintext {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        content: ContentBlock,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<serde_json::Value>)))]
        metadata: Option<MessageMetadata>,
    },
    Mls {
        encrypted_content: EncryptedEnvelope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encrypted_metadata: Option<EncryptedEnvelope>,
        encryption_context: MessageEncryptionContext,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessageAuthoringIntent {
    pub strand_id: StrandId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub track_name: MessageTrackName,
    pub content: MessageAuthoringContent,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<String>,
}

impl MessageAuthoringIntent {
    pub fn payload(&self) -> MessageCreatePayload {
        let mut payload = MessageCreatePayload {
            strand_id: self.strand_id.clone(),
            track_name: match self.track_name {
                MessageTrackName::Discussion => "discussion".to_owned(),
            },
            content: None,
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            blob_refs: self.blob_refs.clone(),
            reply_to_id: self.reply_to_id.clone(),
            agent_context: None,
            mimi_provenance: None,
        };
        match &self.content {
            MessageAuthoringContent::Plaintext { content, metadata } => {
                payload.content = Some(content.clone());
                payload.metadata = metadata.clone();
            }
            MessageAuthoringContent::Mls {
                encrypted_content,
                encrypted_metadata,
                ..
            } => {
                payload.encrypted_content = Some(encrypted_content.clone());
                payload.encrypted_metadata = encrypted_metadata.clone();
            }
        }
        payload
    }
}

/// A producer-authored Message Event submitted to the governance Station.
/// The response is `AuthoritySubmitOutcome`; no actor frontier is returned or
/// signed because producer Events no longer form a causal predecessor graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageSubmitRequestBody {
    pub submission: EventCommitSubmission,
}

impl MessageSubmitRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.submission.event.kind != EventKind::MessageCreate {
            return Err(WireError::Protocol(
                "message submission requires ak.message.create".to_owned(),
            ));
        }
        Ok(())
    }
}
