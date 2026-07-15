//! Top-level JSON Schema artifact names that compose existing protocol DTOs.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/account-data-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountDataOperations {
    AccountDataReplaceRequestBody(AccountDataReplaceRequestBody),
    AccountDataEntry(AccountDataEntry),
    AccountDataList(AccountDataList),
    AccountDataDeleteOutcome(AccountDataDeleteOutcome),
}

/// Counterpart for `spec/v1/artifacts/schemas/availability-receipt.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityReceipt {
    pub realm_id: RealmId,
    pub event_id: EventId,
    pub bytes_digest: Hash,
    pub holder_id: Did,
    pub retention_expires_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

/// Counterpart for `spec/v1/artifacts/schemas/circle-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum CircleOperations {
    CircleCreateRequestBody(CircleCreateRequestBody),
    CircleView(CircleView),
    CircleList(CircleList),
    CircleMemberRequestBody(CircleMemberRequestBody),
    CircleMembershipOutcome(CircleMembershipOutcome),
    CircleScopeRotateOutcome(CircleScopeRotateOutcome),
    CircleLifecycleRequestBody(CircleLifecycleRequestBody),
}

/// Counterpart for `spec/v1/artifacts/schemas/consent-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConsentOperations {
    ConsentCellView(ConsentCellView),
    ConsentCellList(ConsentCellList),
    ConsentUpdateRequestBody(ConsentUpdateRequestBody),
    ConsentRequestRequestBody(ConsentRequestRequestBody),
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_answer`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollAnswer {
    pub id: String,
    pub text: ContentBlock,
}

/// Discriminator for `content-block-poll.schema.json#/$defs/poll_body.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollDisclosureKind {
    #[serde(rename = "disclosed")]
    Disclosed,
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollBody {
    pub kind: PollDisclosureKind,
    pub max_selections: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<ContentBlock>,
    pub answers: Vec<PollAnswer>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_response_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResponseBody {
    pub poll_ref: MessageId,
    pub selections: Vec<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/reply_context`.
pub type PollReplyContext = BTreeMap<String, Value>;

/// Discriminator for `content-block-poll.schema.json#/$defs/poll_block.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollBlockKind {
    #[serde(rename = "ak.content.poll")]
    Poll,
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_block`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollBlock {
    pub kind: PollBlockKind,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted_body: Option<FormattedBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_context: Option<PollReplyContext>,
    pub poll: PollBody,
}

/// Discriminator for
/// `content-block-poll.schema.json#/$defs/poll_response_block.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollResponseBlockKind {
    #[serde(rename = "ak.content.poll.response")]
    PollResponse,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/content-block-poll.schema.json#/$defs/poll_response_block`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollResponseBlock {
    pub kind: PollResponseBlockKind,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted_body: Option<FormattedBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_context: Option<PollReplyContext>,
    pub poll_response: PollResponseBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FormattedBody {
    Text(String),
    Structured(BTreeMap<String, Value>),
}

/// Counterpart for `spec/v1/artifacts/schemas/content-block-poll.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ContentBlockPoll {
    PollBlock(PollBlock),
    PollResponseBlock(PollResponseBlock),
}

/// Counterpart for `spec/v1/artifacts/schemas/inclusion-list.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionList {
    pub realm_id: RealmId,
    pub signer_id: Did,
    pub list_seq: u64,
    pub event_digests: Vec<Hash>,
    pub expiry_seal_count: u64,
    pub created_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

/// Counterpart for `spec/v1/artifacts/schemas/key-view-proof.schema.json#/$defs/key_view`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyView {
    pub cell_id: String,
    pub lattice_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heads: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_covered_event: Option<Hash>,
}

/// Counterpart for `spec/v1/artifacts/schemas/key-view-proof.schema.json#/$defs/audit_path`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyViewAuditPathItem {
    pub side: String,
    pub digest: Hash,
}

/// Counterpart for `spec/v1/artifacts/schemas/key-view-proof.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyViewProof {
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub data_view_root: Hash,
    pub key_view: KeyView,
    pub audit_path: Vec<KeyViewAuditPathItem>,
}

/// Counterpart for `spec/v1/artifacts/schemas/list-handles-for-subject-response.schema.json`.

/// Counterpart for `spec/v1/artifacts/schemas/read-cursor-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReadCursorOperations {
    ReadCursorAdvanceRequestBody(ReadCursorAdvanceRequestBody),
    ReadMarkerOutcome(ReadMarkerOutcome),
    ReadCursorList(ReadCursorList),
}

/// Counterpart for `spec/v1/artifacts/schemas/realm-link-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum RealmLinkOperations {
    RealmLinkCreateRequestBody(RealmLinkCreateRequestBody),
    RealmLinkList(RealmLinkList),
    RealmLinkMutationOutcome(RealmLinkMutationOutcome),
    RealmEffectivePolicyOutcome(RealmEffectivePolicyOutcome),
}

/// Counterpart for `spec/v1/artifacts/schemas/realm-policy-server-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmPolicyServerOperations {
    RealmPolicyServerReplaceRequestBody(RealmPolicyServerReplaceRequestBody),
    RealmPolicyServerView(RealmPolicyServerView),
}

/// Counterpart for `spec/v1/artifacts/schemas/realm-organization-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmOrganizationOperations {
    RealmOrganizationRelationshipList(RealmOrganizationRelationshipList),
}

/// Counterpart for `spec/v1/artifacts/schemas/realm-read-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum RealmReadOperations {
    RealmLifecycleView(RealmLifecycleView),
    RealmExport(RealmExport),
    RealmEffectiveModerationPolicy(RealmEffectiveModerationPolicy),
    RealmModerationPolicyReplaceRequestBody(RealmModerationPolicyReplaceRequestBody),
    RealmModerationPolicyDocument(RealmModerationPolicyDocument),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/seal-transparency.schema.json#/$defs/auditor_attestation/checks`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealTransparencyChecks {
    pub append_only: bool,
    pub seal_signatures: bool,
    pub set_root_monotonic: bool,
    pub completeness_monotonic: bool,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/seal-transparency.schema.json#/$defs/auditor_attestation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealTransparencyAuditorAttestation {
    pub log_id: String,
    pub realm_id: RealmId,
    pub from_index: u64,
    pub to_index: u64,
    pub head_entry_digest: Hash,
    pub auditor_id: Did,
    pub checks: SealTransparencyChecks,
    pub attested_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

/// Counterpart for `spec/v1/artifacts/schemas/seal-transparency.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealTransparency {
    pub log_id: String,
    pub log_index: u64,
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub control_event_set_root: Hash,
    pub completeness_root: Hash,
    pub state_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_entry_digest: Option<Hash>,
    pub logged_at: DateTime<Utc>,
    pub log_signature: PayloadProof,
}
