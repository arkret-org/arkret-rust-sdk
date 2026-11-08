// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/content-encryption.schema.json
// sha256=ccb35fae085d742868258a8ab9b934a8f08c0448058484a4c08439b172d9f25e
//
// Input: schemas/decimal-integers.schema.json
// sha256=7ea09c46f777e010c72a1fd069b7fbefc7d66924e7b3ad5a5961ce9914858987
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Bindings: tools/closed-model-bindings.json
// sha256=c118dc80d3979cf43e74a8ebd793a80ebb67f13c08db276c8d2c87279bae1b20

/// Counterpart: `content-encryption.schema.json#/$defs/root_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRootContext {
    pub effective_scope: arkret_wire::ScopeRef,
    pub genesis_event_ref: arkret_wire::EventId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub epoch: u64,
    pub group_state_ref: arkret_wire::EventId,
    pub cipher_suite: String,
    pub encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy,
    pub backup_strategy_ref: arkret_wire::EventId,
}

/// Counterpart: `content-encryption.schema.json#/$defs/endpoint`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentEndpoint {
    pub actor_id: arkret_wire::ActorId,
    pub endpoint: arkret_wire::MlsWelcomeRecipientEndpoint,
    pub authorization_event_ref: arkret_wire::EventId,
    pub signature_key_base64url: String,
}

/// Counterpart: `content-encryption.schema.json#/$defs/content_context/properties/purpose`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentPurpose {
    #[serde(rename = "event_body")]
    EventBody,
}

/// Counterpart:
/// `content-encryption.schema.json#/$defs/content_context/properties/encryption_algorithm`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentEncryptionAlgorithm {
    #[serde(rename = "aes128_gcm")]
    Aes128Gcm,
}

/// Counterpart: `content-encryption.schema.json#/$defs/content_context`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentContext {
    pub root_context: ContentRootContext,
    pub root_ref: arkret_wire::Hash,
    pub purpose: ContentPurpose,
    pub encryption_scheme: arkret_wire::EncryptedPayloadScheme,
    pub encryption_algorithm: ContentEncryptionAlgorithm,
    pub producer: ContentEndpoint,
    pub content_key_salt: String,
}

/// Counterpart: `content-encryption.schema.json#/$defs/content_epoch_root/properties/item_kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentRootItemKind {
    #[serde(rename = "content_epoch_root")]
    ContentEpochRoot,
}

/// Counterpart: `content-encryption.schema.json#/$defs/content_epoch_root`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRootBackupEntry {
    pub item_kind: ContentRootItemKind,
    pub secret_id: String,
    pub root_context: ContentRootContext,
    pub root_ref: arkret_wire::Hash,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub root_base64url: ContentRootSecret,
}

/// Counterpart: `content-encryption.schema.json#/$defs/coverage_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentCoverageEntry {
    pub source: arkret_wire::CommittedEventRef,
    pub root_refs: Vec<arkret_wire::Hash>,
    pub blob_refs: Vec<arkret_wire::BlobRef>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/coverage`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentCoveragePage {
    pub effective_scope: arkret_wire::ScopeRef,
    pub genesis_event_ref: arkret_wire::EventId,
    pub cut: arkret_wire::CommittedEventRef,
    pub entries: Vec<ContentCoverageEntry>,
    pub backup_refs: Vec<arkret_wire::BackupId>,
    #[serde(deserialize_with = "crate::content_history::required_nullable")]
    pub previous_page_digest: Option<arkret_wire::Hash>,
    pub page_digest: arkret_wire::Hash,
}

/// Counterpart: `content-encryption.schema.json#/$defs/key_selector`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum HistoryKeySelector {
    #[serde(rename = "content_key")]
    ContentKey {
        source_event_ref: arkret_wire::EventId,
        content_path: String,
    },
    #[serde(rename = "epoch_root")]
    EpochRoot {
        root_context: ContentRootContext,
        root_ref: arkret_wire::Hash,
        closed_epoch_cut: arkret_wire::CommittedEventRef,
    },
}

/// Counterpart: `content-encryption.schema.json#/$defs/history_grant/properties/entries/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryGrantEntry {
    pub selector: HistoryKeySelector,
    pub sealed_key_base64url: String,
}

/// Counterpart: `content-encryption.schema.json#/$defs/history_grant`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryGrant {
    pub recipient: ContentEndpoint,
    pub recipient_hpke_key_base64url: String,
    pub recipient_key_event_ref: arkret_wire::EventId,
    pub history_cut: arkret_wire::CommittedEventRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub entries: Vec<HistoryGrantEntry>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_binding`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoveryBinding {
    pub replacement: ContentEndpoint,
    pub authorization_event_ref: arkret_wire::EventId,
    pub base_group_state_ref: arkret_wire::EventId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub expected_epoch: u64,
    pub inventory_digest: arkret_wire::Hash,
}

/// Counterpart: `content-encryption.schema.json#/$defs/custody`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHistoryCustody {
    pub custodian_actor_id: arkret_wire::ActorId,
    pub recovery_policy_ref: crate::RecoveryPolicyRef,
    pub recipient_key_ref: arkret_wire::DidUrl,
}

/// Counterpart: `content-encryption.schema.json#/$defs/history_recovery/properties/state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentRecoveryState {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "ready")]
    Ready,
}

/// Counterpart: `content-encryption.schema.json#/$defs/history_recovery`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoveryCheckpoint {
    pub state: ContentRecoveryState,
    pub pcr_cut: arkret_wire::CommittedEventRef,
    pub coverage_head_digest: arkret_wire::Hash,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub restored_event_count: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub cleanup_inventory_digest: Option<arkret_wire::Hash>,
    pub cleanup_completed: bool,
    pub inventory_blob_ref: arkret_wire::BlobRef,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub cleanup_blob_ref: Option<arkret_wire::BlobRef>,
    pub replacement: ContentEndpoint,
}

/// Counterpart: `content-encryption.schema.json#/$defs/protection`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentProtection {
    pub root_refs: Vec<arkret_wire::Hash>,
    pub blob_refs: Vec<arkret_wire::BlobRef>,
    pub backup_refs: Vec<arkret_wire::BackupId>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/history_request`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRequest {
    pub recipient: ContentEndpoint,
    pub recipient_hpke_key_base64url: String,
    pub history_cut: arkret_wire::CommittedEventRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/history_backup_access`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentHistoryBackupAccess {
    pub source: arkret_wire::CommittedEventRef,
    pub root_refs: Vec<arkret_wire::Hash>,
}

/// Counterpart:
/// `content-encryption.schema.json#/$defs/recovery_inventory_entry/properties/old_leaves/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoveryOldLeaf {
    pub leaf_index: u32,
    pub endpoint: ContentEndpoint,
}

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_inventory_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoveryInventoryEntry {
    pub effective_scope: arkret_wire::ScopeRef,
    pub genesis_event_ref: arkret_wire::EventId,
    pub base_group_state_ref: arkret_wire::EventId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub epoch: u64,
    pub old_leaves: Vec<ContentRecoveryOldLeaf>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_inventory`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoveryInventory {
    pub actor_id: arkret_wire::ActorId,
    pub replacement: ContentEndpoint,
    pub authorization_event_ref: arkret_wire::EventId,
    pub pcr_cut: arkret_wire::CommittedEventRef,
    pub entries: Vec<ContentRecoveryInventoryEntry>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/scope_cleanup`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentScopeCleanup {
    pub effective_scope: arkret_wire::ScopeRef,
    pub genesis_event_ref: arkret_wire::EventId,
    pub winning_commit: arkret_wire::CommittedEventRef,
    pub remaining_old_leaf_count: u32,
    pub root_refs: Vec<arkret_wire::Hash>,
    pub backup_refs: Vec<arkret_wire::BackupId>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/cleanup_inventory`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentCleanupInventory {
    pub inventory_digest: arkret_wire::Hash,
    pub scope_cleanups: Vec<ContentScopeCleanup>,
}

/// Counterpart: `content-encryption.schema.json#/$defs/recovery_source_attestation`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRecoverySourceAttestation {
    pub event_ref: arkret_wire::EventId,
    pub replacement: ContentEndpoint,
    pub effective_scope: arkret_wire::ScopeRef,
    pub base_group_state_ref: arkret_wire::EventId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub previous_epoch: u64,
    pub inventory_digest: arkret_wire::Hash,
    pub verification_method: arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub signature: crate::artifacts_keys::KeyOperationSignature,
}
