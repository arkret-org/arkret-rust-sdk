//! Event wire schema artifact counterparts.

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json`.
pub type EventPayload = GenericStandardPayload;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/generic_standard_payload`.
pub type GenericStandardPayload = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/nullable_timestamp`.
pub type NullableTimestamp = Option<DateTime<Utc>>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/plaintext_data_class`.
pub type PlaintextDataClass = String;

/// Counterpart for `spec/v1/artifacts/schemas/disappearing-messages.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DisappearingMessages {
    MessageExpiry(MessageExpiry),
    DisappearingPolicy(DisappearingPolicy),
}

pub use arkret_models_crypto::encrypted_envelope::{
    EncryptedEnvelope, EncryptedEnvelopeAad, EncryptedEnvelopeAadVisibility,
    EncryptedEnvelopeGroupStateRef, EncryptedEnvelopeKeyAlgorithm, EncryptedEnvelopeKeyRef,
    base64url_token, content_type_byte, content_type_token, major_minor_version,
};
pub use arkret_wire::event_receipt::{
    DeviceReanchorReceiptScope, DeviceReanchorReceiptScopeKind, EventBatchOrdinaryReceiptScope,
    EventBatchReceipt, EventBatchReceiptEvent, EventBatchReceiptFrontier, EventBatchReceiptItem,
    EventBatchReceiptScope, EventProofAudience,
};

/// Counterpart for `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/subject_ref`.
pub type SubjectRef = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/verification_stub`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubSubject {
    pub kind: String,
    pub subject_ref: SubjectRef,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubScope {
    pub storage_boundary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<SubjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubSealInclusion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStub {
    pub stub_schema: String,
    pub subject: VerificationStubSubject,
    pub scope: VerificationStubScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_digests: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_inclusion: Option<VerificationStubSealInclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_authorization_ref: Option<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<LegalHoldRef>,
    pub receipt_id: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub completed_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/board_space_id`.
pub type BoardSpaceId = SpaceId;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LegalHoldRef {
    PolicyId(PolicyId),
    Hash(Hash),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageLifecycleState {
    Active,
    Redacted,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/feature_ref`.
pub type FeatureRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/grant_ref`.
pub type GrantRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/list_space_id`.
pub type ListSpaceId = SpaceId;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/profile_ref`.
pub type ProfileRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/rank`.
pub type Rank = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/track_name`.
pub type TrackName = String;

/// Counterpart for `spec/v1/artifacts/schemas/message.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: MessageId,
    pub schema: String,
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub track_name: MessageTrackName,
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_root: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub edited_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_ref: Option<EventId>,
    pub created_by: Did,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}
