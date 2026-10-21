//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/service-operation-dtos.schema.json
//! sha256=cf32adc7dde893269afa676f7f507979b0f1899e2c565185d7a9f752c4f4e2ff
//!
//! Input: schemas/directory-operations.schema.json
//! sha256=89220e1647acb03806220ccd2da3f4e4af805f5907b07d4c2aba6decf6e037ad
//!
//! Input: schemas/time.schema.json
//! sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

/// Counterpart: `service-operation-dtos.schema.json#/$defs/PublicRealmMetadata`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRealmMetadata {
    pub display_name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub summary: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub public_locator: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub avatar_blob_ref: Option<arkret_wire::BlobRef>,
}

/// Counterpart: `directory-operations.schema.json#/$defs/public_realm_directory_entry`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRealmDirectoryEntry {
    pub realm_id: arkret_wire::RealmId,
    pub public_metadata: PublicRealmMetadata,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub indexed_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Counterpart: `directory-operations.schema.json#/$defs/directory_search_realms_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySearchRealmsRequestBody {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub query: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub limit: Option<u8>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub cursor: Option<String>,
}

/// Counterpart: `directory-operations.schema.json#/$defs/directory_realm_search_outcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRealmSearchOutcome {
    pub realms: Vec<PublicRealmDirectoryEntry>,
    pub has_more: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub next_cursor: Option<String>,
}

/// Counterpart: `directory-operations.schema.json#/$defs/directory_resolve_realm_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResolveRealmRequestBody {
    pub realm_id: arkret_wire::RealmId,
}
