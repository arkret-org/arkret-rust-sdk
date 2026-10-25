// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/keys-operations.schema.json
// sha256=d2645beeab92e67cca8924e10310364580de299c04cd12034896ffe43c7c1607
//
// Input: schemas/authorization-operations.schema.json
// sha256=b367d60aeb13aa9e524c5201cc1857d8ac9defd5c78293f696a4f4c0a5d4450b
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Input: schemas/agent-operations.schema.json
// sha256=57acbc5881e4ce66c0742968ae383fe5bda77fe0461abc395560e10fcdca637a
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=107c58e1dbd8a2701005c9cd1dc573b3c5e861cc4f3c68403bae0ff3d579bd03

/// Counterpart: `keys-operations.schema.json#/$defs/backup_active_series_state`.
/// `keys-operations.schema.json#/$defs/backup_active_series_state`.
///
/// v1 registers exactly one backup class, `secret_storage` (key-management
/// Â§7.5.0 / Â§7.6.1). The object is closed: an `mls_history` or private class
/// member is schema-invalid and is rejected rather than ignored.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupActiveSeriesState {
    pub account_id: AccountId,
    pub control_realm_id: arkret_wire::RealmId,
    pub authority_commit_id: RealmCommitId,
    pub secret_storage: BackupActiveSeriesPointer,
}

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_page`.
/// `keys-operations.schema.json#/$defs/keys_backups_page`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsPage {
    pub backups: Vec<KeyBackupSummary>,
    pub active_series: BackupActiveSeriesState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

/// Counterpart: `keys-operations.schema.json#/$defs/backup_metadata/properties/encryption`.
/// `keys-operations.schema.json#/$defs/backup_metadata/properties/encryption`:
/// only the non-secret recipient categorization; AEAD/KDF material is withheld.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupSummaryEncryption {
    pub recipient_method: KeyBackupRecipientMethod,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub recipient_key_ref: Option<String>,
}

/// Counterpart: `keys-operations.schema.json#/$defs/backup_metadata`.
/// `keys-operations.schema.json#/$defs/backup_metadata`: the closed list
/// summary of one stored envelope (key-management Â§7.6.1).
///
/// Field order is the schema `properties` order. Optional members are absent
/// or carry a value; only the schema's tristate members (`supersedes_id`,
/// `expires_at`) accept an explicit `null`, which round-trips as `Some(None)`.
/// Only `retention` is an open object and is carried verbatim. Source and
/// recovery-policy references are read from the complete signed envelope.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupSummary {
    pub backup_id: BackupId,
    pub actor_id: ActorId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub device_id: Option<DeviceId>,
    pub backup_kind: BackupKind,
    pub backup_version: NonEmptyString,
    pub series_id: BackupSeriesId,
    pub series_sequence: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_nullable"
    )]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<BackupId>)))]
    pub supersedes_id: Option<Option<BackupId>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub supersedes_digest: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_tristate_canonical_timestamp",
        deserialize_with = "deserialize_tristate_canonical_timestamp"
    )]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<String>)))]
    pub expires_at: Option<Option<DateTime<Utc>>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_present_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    pub ciphertext_digest: Hash,
    pub encryption: KeyBackupSummaryEncryption,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<Object>)))]
    pub retention: Option<serde_json::Map<String, serde_json::Value>>,
}
