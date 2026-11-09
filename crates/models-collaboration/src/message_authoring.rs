//! Message authoring and authority submission DTOs.

use arkret_canonical::canonical;
use arkret_models_crypto::{
    ContentEndpoint, EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EventContentMaterial,
};
use arkret_wire::{
    EncryptedPayloadScheme, Event, EventAdmissionSubmission, EventKind, Hash, Result, ScopeRef,
    StrandId, WireError,
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
    pub producer: ContentEndpoint,
    pub outer_event_digest: Hash,
}

impl MessageEncryptionContext {
    /// Check the frozen bytes against an independently verified native producer.
    /// This pure binding check does not establish current authority or membership.
    pub fn validate_for_event(
        &self,
        event: &Event,
        actual_producer: &ContentEndpoint,
    ) -> Result<()> {
        self.producer.validate()?;
        let outer = EventContentMaterial::outer_event_for(event)?;
        let expected_digest = Hash::new(canonical::canonical_sha256(&outer)?)?;
        let expected_sender = canonical::canonical_json_string(&actual_producer.actor_id)?;
        if self.effective_scope != event.scope_ref
            || &self.producer != actual_producer
            || &actual_producer.actor_id != event.executed_by.as_ref().unwrap_or(&event.actor_id)
            || self.sender_domain != expected_sender
            || self.outer_event_digest != expected_digest
        {
            return Err(WireError::Protocol(
                "encrypted message differs from its frozen Event or actual producer".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
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
    /// Verify the exact local intent before Event ID derivation or signing.
    /// Native qualification and current Direct-reference checks remain external.
    pub fn validate_encryption_binding(
        &self,
        event: &Event,
        actual_producer: &ContentEndpoint,
    ) -> Result<()> {
        if event.kind != EventKind::MessageCreate
            || serde_json::to_value(self.payload())? != serde_json::to_value(&event.payload)?
        {
            return Err(WireError::Protocol(
                "message Event differs from its complete local payload".to_owned(),
            ));
        }
        if let MessageAuthoringContent::Mls {
            encrypted_content,
            encrypted_metadata,
            encryption_context,
        } = &self.content
        {
            encryption_context.validate_for_event(event, actual_producer)?;
            encrypted_content.validate()?;
            if encrypted_content.encryption_scheme != encryption_context.scheme {
                return Err(WireError::Protocol(
                    "message envelope differs from its frozen construction".to_owned(),
                ));
            }
            if let Some(metadata) = encrypted_metadata {
                metadata.validate()?;
                let EncryptedEnvelopeEncryptionContext::EpochContent {
                    epoch,
                    group_state_ref,
                    content_key_salt,
                    root_ref,
                    ..
                } = &encrypted_content.encryption_context;
                let EncryptedEnvelopeEncryptionContext::EpochContent {
                    epoch: metadata_epoch,
                    group_state_ref: metadata_group_state,
                    content_key_salt: metadata_salt,
                    root_ref: metadata_root,
                    ..
                } = &metadata.encryption_context;
                if metadata.encryption_scheme != encryption_context.scheme
                    || epoch != metadata_epoch
                    || group_state_ref != metadata_group_state
                    || root_ref != metadata_root
                    || content_key_salt == metadata_salt
                {
                    return Err(WireError::Protocol(
                        "message content slots mix original roots or reuse their key domain"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

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
            mimi_provenance: None,
            poll_response_heads: Vec::new(),
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
/// The response is `AuthoritySubmitResponseBody`; no actor checkpoint is returned or
/// signed because producer Events no longer form a causal predecessor graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageSubmitRequestBody {
    pub submission: EventAdmissionSubmission,
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
