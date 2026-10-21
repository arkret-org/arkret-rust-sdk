// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/keys-operations.schema.json
// sha256=5e48bff39f1e76320970d5abed25e6fdbf0848f1e8f678c83681d6ff6395bcf6
//
// Input: schemas/authz-operations.schema.json
// sha256=a77316365476c8c617f70a84a5bf3f6ee0be723b84b2f4713072cf1ed02e6832
//
// Input: schemas/account-operations.schema.json
// sha256=b4be514e16b4a5154a4cb3bd56cf062f9ffb2cfc29ef25a26777a29f1e3d7644
//
// Input: schemas/common-ids.schema.json
// sha256=14226f0ac83e4d06639ad791cc0e52e0eb1c3b128cd4c8c12308a99b795141e4
//
// Input: schemas/agent-operations.schema.json
// sha256=0d2950977b4b8d7c76137b107fd4dbf11401b0b1e5b480ba6ce34d31b82ad5aa
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=8f43ab7f7fe4be59fd38447b7690378c53af63212ce0eb1df8f8d25fa2a14315

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

/// Counterpart: `keys-operations.schema.json#/$defs/keys_backups_list`.
/// `keys-operations.schema.json#/$defs/keys_backups_list`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsList {
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
    pub series_seq: u64,
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
