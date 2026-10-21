// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=51122d20a1426cc7e23a5e93ea307be964a90e3eaa9e5980d051ae67c2634887
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/common-ids.schema.json
// sha256=14226f0ac83e4d06639ad791cc0e52e0eb1c3b128cd4c8c12308a99b795141e4
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

/// Counterpart: `event-payload.schema.json#/$defs/account_data_set_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/account_data_set_payload`.
///
/// This is the canonical Event payload for `ak.account_data.set`. The
/// self-service HTTP `account_data_replace_request_body` is a separate
/// transport DTO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountDataSetPayload {
    pub key: NonEmptyString,
    #[serde(default, skip_serializing_if = "AccountDataBody::is_absent")]
    pub body: AccountDataBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub encrypted_payload: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tombstone: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub updated_at: Option<DateTime<Utc>>,
    pub expected_server_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub source_pending_event_id: Option<EventId>,
}
