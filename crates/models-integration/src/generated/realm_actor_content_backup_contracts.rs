// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/keys-operations.schema.json
// sha256=8dc3a9556fd7ff9a27bb8ea8014b6b7a859692c94e40b7b7b4202192e3ea7dcf
//
// Input: schemas/authorization-operations.schema.json
// sha256=b367d60aeb13aa9e524c5201cc1857d8ac9defd5c78293f696a4f4c0a5d4450b
//
// Input: schemas/realm-actor-material.schema.json
// sha256=fe13177cf262150b299d101c2cf7e364e2f38fc2fbb8dc6a78ae3c45b1816d1b
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=145ad1e0a66b0548a1e081d8eecb6a8c0f999745dbf1ac50f8039ca1c84b8d0e
//
// Bindings: tools/closed-model-bindings.json
// sha256=bb8c3350621b1f35ac031f7e6919326951b3576cd3c52db20323ba3e6e740687

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_list_response_body`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum KeysBackupsListResponseBody {
    Account(arkret_models_crypto::KeysBackupsPage),
    Device(arkret_models_crypto::RealmActorBackupSeriesHeadResponseBody),
    Manager(RealmActorArchiveInventoryPage),
}

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_unlock_response_body`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum KeysBackupsUnlockResponseBody {
    Account(arkret_models_crypto::KeyBackup),
    Device(arkret_models_crypto::RealmActorBackupUnlockResponseBody),
    Manager(RealmActorArchiveUnlockResponseBody),
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_archive_backup_entry/properties/kind`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorArchiveBackupEntryKind {
    #[serde(rename = "backup")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_archive_backup_entry`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorArchiveBackupEntry {
    pub kind: RealmActorArchiveBackupEntryKind,
    pub backup: arkret_models_crypto::KeyBackup,
    pub native_source: RealmActorContentBackupSource,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_archive_inventory_entry`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum RealmActorArchiveInventoryEntry {
    Backup(RealmActorArchiveBackupEntry),
    Series(RealmActorArchiveSeriesEntry),
    Recipient(RealmActorArchiveRecipientEntry),
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_archive_inventory_manifest`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorArchiveInventoryManifest {
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub archive_revision: u64,
    pub entries: Vec<RealmActorArchiveInventoryEntry>,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_archive_inventory_page/properties/purpose`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorArchiveInventoryPagePurpose {
    #[serde(rename = "archive_inventory")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_archive_inventory_page`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorArchiveInventoryPage {
    pub purpose: RealmActorArchiveInventoryPagePurpose,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub archive_revision: u64,
    pub inventory_digest: arkret_wire::Hash,
    pub entries: Vec<RealmActorArchiveInventoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub next_cursor: Option<arkret_wire::Cursor>,
    pub has_more: bool,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_archive_recipient_entry/properties/kind`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorArchiveRecipientEntryKind {
    #[serde(rename = "recipient")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_archive_recipient_entry`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorArchiveRecipientEntry {
    pub kind: RealmActorArchiveRecipientEntryKind,
    pub recipient_ref: arkret_wire::CommittedEventRef,
    pub content_backup_recipient: arkret_models_crypto::RealmActorContentBackupRecipient,
    pub declaration: RealmActorBackupEventMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub recovery_begin: Option<RealmActorBackupEventMaterial>,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_archive_series_entry/properties/kind`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorArchiveSeriesEntryKind {
    #[serde(rename = "series")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_archive_series_entry`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorArchiveSeriesEntry {
    pub kind: RealmActorArchiveSeriesEntryKind,
    pub effective_scope: arkret_wire::ScopeRef,
    pub record: arkret_models_collaboration::events_payloads::KeyBackupActiveSeries,
    pub source_ref: arkret_wire::CommittedEventRef,
    pub source: RealmActorBackupEventMaterial,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_archive_unlock_response_body`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorArchiveUnlockResponseBody {
    pub backup: arkret_models_crypto::KeyBackup,
    pub native_source: RealmActorContentBackupSource,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_governance_history`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupGovernanceHistory {
    pub genesis: RealmActorBackupGovernanceOriginal,
    pub genesis_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    pub authority_transitions: Vec<RealmActorBackupGovernanceTransition>,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_governance_original`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupGovernanceOriginal {
    pub event: arkret_wire::Event,
    pub commit: arkret_wire::RealmCommit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub producer_signer_fact:
        Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_backup_governance_transition`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupGovernanceTransition {
    pub original: RealmActorBackupGovernanceOriginal,
    pub handoff: arkret_wire::RealmAuthorityHandoff,
    pub from_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    pub to_resolution: arkret_models_identity::AuthenticatedServiceResolution,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_content_backup_handover_confirmation`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupHandoverConfirmation {
    pub offer_digest: arkret_wire::Hash,
    pub inventory_digest: arkret_wire::Hash,
    pub handover_digest: arkret_wire::Hash,
    pub challenge_response_base64url: String,
    pub signature: arkret_wire::DetachedObjectSignature,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/
/// realm_actor_content_backup_handover_confirmation_signature_input`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupHandoverConfirmationSignatureInput {
    pub offer_digest: arkret_wire::Hash,
    pub inventory_digest: arkret_wire::Hash,
    pub handover_digest: arkret_wire::Hash,
    pub challenge_response_base64url: String,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_content_backup_handover_offer`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupHandoverOffer {
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub new_service_id: arkret_wire::DidCoreId,
    pub next_content_backup_recipient: arkret_models_crypto::RealmActorContentBackupRecipient,
    pub inventory_digest: arkret_wire::Hash,
    pub archive_revision: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub nonce: String,
    pub signature: arkret_wire::DetachedObjectSignature,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_content_backup_handover_offer_signature_input`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupHandoverOfferSignatureInput {
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub new_service_id: arkret_wire::DidCoreId,
    pub next_content_backup_recipient: arkret_models_crypto::RealmActorContentBackupRecipient,
    pub inventory_digest: arkret_wire::Hash,
    pub archive_revision: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub nonce: String,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_content_backup_handover_plaintext`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupHandoverPlaintext {
    pub offer_digest: arkret_wire::Hash,
    pub inventory_manifest: RealmActorArchiveInventoryManifest,
    pub recipient_keys: Vec<RealmActorContentBackupPrivateRecipientKey>,
    pub challenge_base64url: arkret_models_crypto::SecretBytes,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_content_backup_private_recipient_key`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupPrivateRecipientKey {
    pub recipient_ref: arkret_wire::CommittedEventRef,
    pub content_backup_recipient: arkret_models_crypto::RealmActorContentBackupRecipient,
    pub private_key_base64url: arkret_models_crypto::SecretBytes,
}

/// Counterpart:
/// `keys-operations.schema.json#/$defs/realm_actor_content_backup_sealed_handover/properties/
/// hpke_suite`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorContentBackupSealedHandoverHpkeSuite {
    #[serde(rename = "ak.hpke_x25519_aead_chacha20poly1305.v1")]
    Value,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_content_backup_sealed_handover`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupSealedHandover {
    pub offer: RealmActorContentBackupHandoverOffer,
    pub hpke_suite: RealmActorContentBackupSealedHandoverHpkeSuite,
    pub enc: String,
    pub ciphertext_base64url: String,
}

/// Counterpart: `keys-operations.schema.json#/$defs/realm_actor_content_backup_source`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorContentBackupSource {
    pub admission: arkret_models_crypto::RealmActorContentBackupAdmission,
    pub device_authorization: RealmActorBackupEventMaterial,
    pub origin_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    pub governance_history: RealmActorBackupGovernanceHistory,
}

/// Counterpart: `realm-actor-material.schema.json#/$defs/event_material`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorBackupEventMaterial {
    pub event: arkret_wire::Event,
    pub commit: arkret_wire::RealmCommit,
    pub producer_signer_fact:
        arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
}
