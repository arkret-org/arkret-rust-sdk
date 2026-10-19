// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=575ea203cf43456045514ea1085603136877fe9313302291f7d573a1eb7055cc
//
// Input: schemas/event-payload.schema.json
// sha256=cc3c0dfe191c29585876c1d6438a28787cf75076690f0ef1d7a999c470499b9a
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=42637b7091c5d9a931ae042b62a3b4b684763d010e044485fc40891314c2f844

/// Counterpart: `typed-current-result.schema.json#/$defs/consent_value`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// Closed `typed-current-result.schema.json#/$defs/consent_value`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentValue {
    pub consent_id: ConsentId,
    pub peer: ConsentPeer,
    pub consent_scope: ConsentScope,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub constraints: Option<Vec<std::collections::BTreeMap<String, serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
    pub status: ConsentState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub revoked_reason: Option<String>,
}
