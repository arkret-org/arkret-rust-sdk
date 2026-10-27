//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/presence-preference.schema.json
//! sha256=bebb15edd614d8aebd8077333b232caa907f11f8ab4be12b1179dd0caaa5739d
//!
//! Input: schemas/time.schema.json
//! sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//!
//! Input: schemas/presence-visibility.schema.json
//! sha256=da26ef46bdde72ca1bb3cafe972642d595d75cff14ca03331bd0b1c44dd85e67
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=13aff1fc7ba8bd04dc6586b917faf46593a6d0e4beeadb69db75284c9e17a6f7

/// Counterpart: `presence-preference.schema.json#/properties/manual_state`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ManualPresenceState {
    #[serde(rename = "online")]
    Online,
    #[serde(rename = "idle")]
    Idle,
    #[serde(rename = "dnd")]
    Dnd,
}

/// Counterpart: `presence-preference.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresencePreference {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub manual_state: Option<ManualPresenceState>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub status_message: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    pub clears_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Counterpart: `presence-visibility.schema.json#/properties/presence_visibility`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PresenceVisibility {
    #[default]
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "contacts_only")]
    ContactsOnly,
    #[serde(rename = "consent_only")]
    ConsentOnly,
    #[serde(rename = "nobody")]
    Nobody,
}

/// Counterpart: `presence-visibility.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceVisibilityPreference {
    pub presence_visibility: PresenceVisibility,
}
