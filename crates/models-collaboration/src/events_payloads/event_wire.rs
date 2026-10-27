//! Event wire schema artifact counterparts.

use arkret_wire::{AccountStatusRecordId, ActorId, CommittedEventRef, Event, EventId, SchemaId};
use serde::de::DeserializeOwned;

use crate::governance::erasure::{ErasureScope, ErasureSubject, ErasureSubjectKind, LegalHoldRef};
use crate::internal_prelude::*;

/// Decode payload bytes only after the enclosing model has proved the Event's
/// exact kind. This crate-private boundary exists because the payload model
/// crate cannot depend on the higher-level `arkret-event-draft` binding crate.
pub(crate) fn decode_payload_after_kind_validation<T: DeserializeOwned>(
    event: &Event,
) -> Result<T> {
    serde_json::from_value(Value::Object(event.payload.clone().into_iter().collect()))
        .map_err(Into::into)
}

pub use arkret_models_crypto::encrypted_envelope::{
    EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EncryptedEnvelopeRoutingContext,
    EventContentPreEncryptionHeader, EventContentRoutingContext, base64url_token,
    content_type_byte, content_type_token, fixed_base64url_token, major_minor_version,
};
pub use arkret_wire::EventProofAudience;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErasureTrigger {
    Event {
        event_id: EventId,
    },
    AccountStatusRecord {
        account_status_record_id: AccountStatusRecordId,
    },
}

/// Counterpart for `spec/v1/artifacts/schemas/erasure-verification-stub.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct VerificationStub {
    pub stub_schema: String,
    pub subject: ErasureSubject,
    pub scope: ErasureScope,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub event_digest: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub retained_digests: Option<Vec<Hash>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub committed_event_ref: Option<CommittedEventRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub redaction_authorization_ref: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_present_nullable"
    )]
    pub legal_hold_ref: Option<Option<LegalHoldRef>>,
    pub receipt_id: String,
    pub trigger: ErasureTrigger,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
}

impl VerificationStub {
    /// Check retained Event linkage; this does not verify acceptance or a proof.
    pub fn validate_linkage(&self) -> Result<()> {
        if self.subject.kind != ErasureSubjectKind::Event {
            if self.event_digest.is_some() || self.committed_event_ref.is_some() {
                return Err(WireError::Protocol(
                    "non-Event erasure stub carries Event-only evidence".into(),
                ));
            }
            return Ok(());
        }
        let event_id = EventId::new(&self.subject.subject_ref)?;
        if self
            .event_digest
            .as_ref()
            .is_some_and(|digest| *digest != event_id.event_digest())
            || self
                .committed_event_ref
                .as_ref()
                .is_some_and(|reference| reference.event_id != event_id)
        {
            return Err(WireError::Protocol(
                "erasure stub Event linkage differs from its subject".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageLifecycleState {
    Active,
    Redacted,
}

/// Counterpart for `spec/v1/artifacts/schemas/message.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: MessageId,
    pub schema: String,
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    pub state: MessageLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_root_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub edited_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_ref: Option<EventId>,
    pub created_by: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Message {
    pub const SCHEMA: &'static str = SchemaId::MESSAGE_V1;
}
