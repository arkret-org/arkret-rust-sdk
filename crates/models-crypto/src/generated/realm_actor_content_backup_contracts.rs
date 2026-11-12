// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-actor.schema.json
// sha256=87c35a6c300e76490630f6c0fad0dd6bb7c7c601042572f84b1f24ca28be4dc7
//
// Input: schemas/key-backup.schema.json
// sha256=e9280313666a5fc0055a9f15edaa9e4716369fb362e6a808b64f919a1c8a398d
//
// Input: schemas/keys-operations.schema.json
// sha256=8dc3a9556fd7ff9a27bb8ea8014b6b7a859692c94e40b7b7b4202192e3ea7dcf
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Input: schemas/authorization-operations.schema.json
// sha256=b367d60aeb13aa9e524c5201cc1857d8ac9defd5c78293f696a4f4c0a5d4450b
//
// Input: schemas/account-operations.schema.json
// sha256=0ae0fec5fd63dca4b9df9293eb71936cf73a3eeeae13b2268dc99699c1ed7607
//
// Input: schemas/agent-operations.schema.json
// sha256=80fba7d397f1c4d067304c83b87dcdacee8db4585991eda985aceb0272890fa1
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/realm-actor-material.schema.json
// sha256=fe13177cf262150b299d101c2cf7e364e2f38fc2fbb8dc6a78ae3c45b1816d1b
//
// Input: schemas/key-backup-unlock-proof.schema.json
// sha256=0f7bd19e12cdfcf610e9456e1b704c1f52f11059b038ecd2bdaaa8baeaad9a9b
//
// Bindings: tools/closed-model-bindings.json
// sha256=bb8c3350621b1f35ac031f7e6919326951b3576cd3c52db20323ba3e6e740687

/// Counterpart: `realm-actor.schema.json#/$defs/content_backup_recipient/properties/hpke_suite`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentBackupRecipientHpkeSuite {
    #[serde(rename = "ak.hpke_x25519_aead_chacha20poly1305.v1")]
    Value,
}

/// Counterpart: `realm-actor.schema.json#/$defs/content_backup_recipient`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(remote = "Self")]
pub struct RealmActorContentBackupRecipient {
    pub key_agreement_ref: arkret_wire::DidUrl,
    pub hpke_suite: ContentBackupRecipientHpkeSuite,
    pub public_key_base64url: String,
}

/// Counterpart: `key-backup.schema.json#/$defs/realm_actor_backup_auth_binding/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupAuthBindingKind {
    #[serde(rename = "realm_device")]
    Value,
}

/// Counterpart: `key-backup.schema.json#/$defs/realm_actor_backup_auth_binding`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(remote = "Self")]
pub struct RealmActorBackupAuthBinding {
    pub kind: RealmActorBackupAuthBindingKind,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    pub device_generation: u64,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/keys_backups_issue_unlock_challenge_response_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum KeysBackupsIssueUnlockChallengeResponseBody {
    Account(crate::KeysBackupsUnlockChallenge),
    Native(RealmActorBackupUnlockChallenge),
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/keys_backups_list_query/oneOf/1/properties/purpose`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeysBackupsListQueryOneOf1Purpose {
    #[serde(rename = "series_predecessor")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_list_query/oneOf/1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupHeadQuery {
    pub purpose: KeysBackupsListQueryOneOf1Purpose,
    pub realm_actor_id: arkret_wire::RealmActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub circle_id: Option<arkret_wire::CircleId>,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/keys_backups_list_query/oneOf/2/properties/purpose`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeysBackupsListQueryOneOf2Purpose {
    #[serde(rename = "archive_inventory")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_list_query/oneOf/2`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorArchiveInventoryQuery {
    pub purpose: KeysBackupsListQueryOneOf2Purpose,
    pub realm_actor_id: arkret_wire::RealmActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub cursor: Option<arkret_wire::Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub limit: Option<u64>,
}

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_list_query`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum KeysBackupsListParameters {
    Account(crate::KeyBackupsListQuery),
    Device(RealmActorBackupHeadQuery),
    Manager(RealmActorArchiveInventoryQuery),
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_active_series_state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupActiveSeriesState {
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    pub authority_commit_id: arkret_wire::RealmCommitId,
    pub secret_storage: crate::BackupActiveSeriesPointer,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_head_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupHeadEntry {
    pub metadata: RealmActorBackupMetadata,
    pub admission: RealmActorContentBackupAdmission,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_metadata/properties/backup_kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupMetadataBackupKind {
    #[serde(rename = "secret_storage")]
    Value,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_metadata/properties/encryption/
/// properties/recipient_method`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupMetadataEncryptionRecipientMethod {
    #[serde(rename = "realm_actor_recovery")]
    Value,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_metadata/properties/encryption/
/// properties/hpke_suite`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupMetadataEncryptionHpkeSuite {
    #[serde(rename = "ak.hpke_x25519_aead_chacha20poly1305.v1")]
    Value,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_metadata/properties/encryption`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupMetadataEncryption {
    pub recipient_method: RealmActorBackupMetadataEncryptionRecipientMethod,
    pub recipient_key_ref: arkret_wire::DidUrl,
    pub hpke_suite: RealmActorBackupMetadataEncryptionHpkeSuite,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_metadata`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupMetadata {
    pub backup_id: arkret_wire::BackupId,
    pub actor_id: arkret_wire::ActorId,
    pub device_id: arkret_wire::DeviceId,
    pub backup_kind: RealmActorBackupMetadataBackupKind,
    pub backup_version: arkret_wire::NonEmptyString,
    pub series_id: arkret_wire::BackupSeriesId,
    pub series_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_present_nullable")]
    pub supersedes_id: Option<Option<arkret_wire::BackupId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub supersedes_digest: Option<arkret_wire::Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub ciphertext_digest: arkret_wire::Hash,
    pub encryption: RealmActorBackupMetadataEncryption,
    pub auth_binding: RealmActorBackupAuthBinding,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_series_head_response_body/properties/
/// purpose`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupSeriesHeadResponseBodyPurpose {
    #[serde(rename = "series_predecessor")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_series_head_response_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupSeriesHeadResponseBody {
    pub purpose: RealmActorBackupSeriesHeadResponseBodyPurpose,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub active_series: RealmActorBackupActiveSeriesState,
    pub items: Vec<RealmActorBackupHeadEntry>,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_unlock_challenge/properties/operation`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupUnlockChallengeOperation {
    #[serde(rename = "ak.self.keys.backups.command.unlock.v1")]
    Value,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_unlock_challenge/properties/kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupUnlockChallengeKind {
    #[serde(rename = "realm_actor_device")]
    RealmActorDevice,
    #[serde(rename = "realm_actor_manager")]
    RealmActorManager,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_backup_unlock_challenge/properties/purpose`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorBackupUnlockChallengePurpose {
    #[serde(rename = "series_predecessor")]
    SeriesPredecessor,
    #[serde(rename = "archive_recovery")]
    ArchiveRecovery,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_unlock_challenge`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupUnlockChallenge {
    pub challenge_id: arkret_wire::Base64UrlString,
    pub challenge: arkret_wire::Base64UrlString,
    pub nonce: arkret_wire::Base64UrlString,
    pub operation: RealmActorBackupUnlockChallengeOperation,
    pub backup_id: arkret_wire::BackupId,
    pub audience: arkret_wire::NonEmptyString,
    pub service_id: arkret_wire::DidCoreId,
    pub request_id: arkret_wire::NonEmptyString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub series_id: arkret_wire::BackupSeriesId,
    pub ciphertext_digest: arkret_wire::Hash,
    pub kind: RealmActorBackupUnlockChallengeKind,
    pub purpose: RealmActorBackupUnlockChallengePurpose,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub requesting_device_id: Option<arkret_wire::DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub device_authorize_event_id: Option<arkret_wire::EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub device_generation: Option<u64>,
    pub envelope_digest: arkret_wire::Hash,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_unlock_response_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupUnlockResponseBody {
    pub backup: crate::KeyBackup,
    pub admission: RealmActorContentBackupAdmission,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_content_backup_admission`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupAdmission {
    pub backup_id: arkret_wire::BackupId,
    pub envelope_digest: arkret_wire::Hash,
    pub ciphertext_digest: arkret_wire::Hash,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub device_id: arkret_wire::DeviceId,
    pub device_authorize_ref: arkret_wire::CommittedEventRef,
    pub device_generation: u64,
    pub device_public_key_base64url: String,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    pub service_id: arkret_wire::DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub governance_generation: u64,
    pub authority_ref: arkret_wire::RealmCommitAuthorityRef,
    pub signature: arkret_wire::DetachedObjectSignature,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_content_backup_admission_signature_input`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupAdmissionSignatureInput {
    pub backup_id: arkret_wire::BackupId,
    pub envelope_digest: arkret_wire::Hash,
    pub ciphertext_digest: arkret_wire::Hash,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub device_id: arkret_wire::DeviceId,
    pub device_authorize_ref: arkret_wire::CommittedEventRef,
    pub device_generation: u64,
    pub device_public_key_base64url: String,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    pub service_id: arkret_wire::DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub governance_generation: u64,
    pub authority_ref: arkret_wire::RealmCommitAuthorityRef,
}

/// Counterpart: `realm-actor-material.schema.json#/$defs/content_backup_next_prepare_input`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentBackupNextPrepareInput {
    pub auth_binding: RealmActorBackupAuthBinding,
    pub content_backup_recipient: RealmActorContentBackupRecipient,
    pub active_series_id: arkret_wire::BackupSeriesId,
}

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_replace_response_body/oneOf/1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupPutResponseBody {
    pub status: crate::KeyBackupPutStatus,
    pub backup_id: arkret_wire::BackupId,
    pub ciphertext_digest: arkret_wire::Hash,
    pub admission: RealmActorContentBackupAdmission,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/keys_backups_issue_unlock_challenge_request_body/oneOf/1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(remote = "Self")]
pub struct RealmActorBackupIssueUnlockChallengeRequestBody {
    pub request_id: arkret_wire::Base64UrlString,
    pub kind: RealmActorBackupUnlockChallengeKind,
    pub purpose: RealmActorBackupUnlockChallengePurpose,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub envelope_digest: arkret_wire::Hash,
}

/// Counterpart: `key-backup-unlock-proof.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(remote = "Self")]
pub struct RealmActorDeviceKeyBackupUnlockProof {
    pub schema: String,
    pub requesting_device_id: arkret_wire::DeviceId,
    pub backup_id: arkret_wire::BackupId,
    pub backup_kind: crate::BackupKind,
    pub series_id: arkret_wire::BackupSeriesId,
    pub ciphertext_digest: arkret_wire::Hash,
    pub challenge: arkret_wire::Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub signature_proof: crate::KeyBackupUnlockSignatureProof,
    pub kind: RealmActorBackupUnlockChallengeKind,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub audience: arkret_wire::NonEmptyString,
    pub service_id: arkret_wire::DidCoreId,
    pub challenge_id: arkret_wire::Base64UrlString,
    pub nonce: arkret_wire::Base64UrlString,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    pub device_authorize_event_id: arkret_wire::EventId,
    pub device_generation: u64,
    pub purpose: RealmActorBackupUnlockChallengePurpose,
    pub envelope_digest: arkret_wire::Hash,
}

/// Counterpart: `key-backup-unlock-proof.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(remote = "Self")]
pub struct RealmActorManagerKeyBackupUnlockProof {
    pub schema: String,
    pub backup_id: arkret_wire::BackupId,
    pub backup_kind: crate::BackupKind,
    pub series_id: arkret_wire::BackupSeriesId,
    pub ciphertext_digest: arkret_wire::Hash,
    pub challenge: arkret_wire::Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub signature_proof: crate::KeyBackupUnlockSignatureProof,
    pub kind: RealmActorBackupUnlockChallengeKind,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub audience: arkret_wire::NonEmptyString,
    pub service_id: arkret_wire::DidCoreId,
    pub challenge_id: arkret_wire::Base64UrlString,
    pub nonce: arkret_wire::Base64UrlString,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    pub purpose: RealmActorBackupUnlockChallengePurpose,
    pub envelope_digest: arkret_wire::Hash,
}

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_replace_response_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum KeysBackupsReplaceOperationResponseBody {
    Account(crate::KeysBackupsReplaceResponseBody),
    Native(RealmActorBackupPutResponseBody),
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/keys_backups_issue_unlock_challenge_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum KeysBackupsIssueUnlockChallengeBody {
    Account(crate::KeysBackupsIssueUnlockChallengeRequestBody),
    Native(RealmActorBackupIssueUnlockChallengeRequestBody),
}
