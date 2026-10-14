// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

/// Counterpart: `event-payload.schema.json#/$defs/consent_grant_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/consent_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantPayload {
    pub consent_id: ConsentId,
    pub peer: ConsentPeer,
    pub consent_scope: ConsentScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub constraints: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}
