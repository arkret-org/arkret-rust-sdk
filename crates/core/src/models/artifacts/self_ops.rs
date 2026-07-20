//! Top-level JSON Schema artifact names that compose existing protocol DTOs.
//!
//! The content-block-poll shapes migrated to `arkret-models-collaboration`
//! (`events_payloads::content_block_poll`) and the inclusion-list /
//! seal-transparency shapes to `arkret-models-collaboration`
//! (`seal_transparency`); both re-exported below. The untagged aggregator
//! enums kept here are cross-domain schema counterparts (they compose DTOs
//! spanning several model crates) with no runtime consumer; they resist a
//! single-crate home and stay as core-local schema anchors.

pub use arkret_models_collaboration::events_payloads::content_block_poll::*;
pub use arkret_models_collaboration::seal_transparency::*;

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
