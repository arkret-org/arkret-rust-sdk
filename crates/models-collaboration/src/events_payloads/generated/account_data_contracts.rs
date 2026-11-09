// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=c1b7f6c9f9f4ceb88c4b7c2924da91d09b11c7dd9ef63fe1e1097a133c1d6fe0
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Bindings: tools/closed-model-bindings.json
// sha256=973940c1b2f35b239f2e75b4f8e41fe33a818d78b1b608381b2b70df42e49f18

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
