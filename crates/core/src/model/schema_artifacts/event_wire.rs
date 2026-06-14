//! Event wire schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/disappearing-messages.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DisappearingMessages {
    MessageExpiry(MessageExpiry),
    DisappearingPolicy(DisappearingPolicy),
}

/// Counterpart for `spec/v1/artifacts/schemas/draft-sync.schema.json`.
pub type DraftSync = DraftSyncValue;

/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeAad {
    pub realm_id: RealmId,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_refs: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_ref_digests: Option<Vec<Hash>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeKeyRef {
    pub algorithm: String,
    pub group_state_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub scheme: String,
    pub version: String,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    pub aad_visibility_event_id: String,
    pub aad: EncryptedEnvelopeAad,
    pub key_ref: EncryptedEnvelopeKeyRef,
    pub payload_digest: Hash,
    pub aad_digest: Hash,
}

/// Counterpart for `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/subject_ref`.
pub type SubjectRef = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/verification_stub`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubSubject {
    pub kind: String,
    pub r#ref: SubjectRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubErasureScope {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubSealInclusion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStub {
    pub stub_schema: String,
    pub subject: VerificationStubSubject,
    pub erasure_scope: VerificationStubErasureScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_digests: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_inclusion: Option<VerificationStubSealInclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_authorization_ref: Option<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<Value>,
    pub receipt_id: String,
    pub completed_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/erasure-verification-stub.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureVerificationStubSubject {
    pub kind: String,
    pub r#ref: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureVerificationStubErasureScope {
    pub storage_boundary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureVerificationStubSealInclusion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureVerificationStub {
    pub stub_schema: String,
    pub subject: ErasureVerificationStubSubject,
    pub erasure_scope: ErasureVerificationStubErasureScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_digests: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_inclusion: Option<ErasureVerificationStubSealInclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_authorization_ref: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<Value>,
    pub receipt_id: String,
    pub completed_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceiptReceiptScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_digest: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceiptFrontier {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub issuer: Did,
    pub receipt_scope: EventBatchReceiptReceiptScope,
    pub frontier: EventBatchReceiptFrontier,
    pub events: Vec<Value>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/board_space_id`.
pub type BoardSpaceId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/event_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventProof {
    pub kind: String,
    pub verification_method: Did,
    pub alg: String,
    pub event_digest: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Value>,
    pub jws: String,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/feature_ref`.
pub type FeatureRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/grant_ref`.
pub type GrantRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/list_space_id`.
pub type ListSpaceId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/profile_ref`.
pub type ProfileRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/rank`.
pub type Rank = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/track_name`.
pub type TrackName = String;

/// Counterpart for `spec/v1/artifacts/schemas/message.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub schema: String,
    pub realm_id: RealmId,
    pub flow_id: FlowId,
    pub track_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<Value>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_root: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_ref: Option<EventId>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}
