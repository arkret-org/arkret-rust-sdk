// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mimi-operations.schema.json
// sha256=23bcdb30a0625be95b1f0ed7532962f5406840a9e7c8d81f182457129ce53eef
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Input: schemas/decimal-integers.schema.json
// sha256=7ea09c46f777e010c72a1fd069b7fbefc7d66924e7b3ad5a5961ce9914858987
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=820d763125038f2777a3fc00ba30173c5a5d85cf50f6047457416eff7523d4d3
//
// Bindings: tools/closed-model-bindings.json
// sha256=107c58e1dbd8a2701005c9cd1dc573b3c5e861cc4f3c68403bae0ff3d579bd03

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_submit_message_request_body`.
/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_submit_message_request_body`.
///
/// Operation `ak.open.mimi.command.submit_message.v1`. The facade never sees
/// plaintext: the Arkret side supplies one already-encrypted MIMI ciphertext
/// plus the exact sender coordinates, and `associated_data` carries only the
/// opaque AAD descriptor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiSubmitMessageRequestBody {
    pub sender_actor_id: ActorId,
    pub device_id: DeviceId,
    pub ciphertext: MimiCiphertext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mls_group_id: Option<MlsGroupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub associated_data: Option<MimiOpaquePayload>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_submit_message_response_body`.
/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_submit_message_response_body`.
///
/// `event_ref` is present only when the submission also produced an Arkret
/// Event; a pure outbound relay reports delivery without one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiSubmitMessageResponseBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub event_ref: Option<EventId>,
    pub delivery: MimiDelivery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<MimiFailure>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_identifier_query_response_body`.
/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_identifier_query_response_body`.
///
/// The outcome is a proof-carrying object: its registered proof context is
/// `ak.mimi_identifier_query_outcome_proof.v1`, and the signed transcript is
/// the canonical body with `proofs` removed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifierQueryResponseBody {
    pub matches: Vec<MimiIdentifierMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
    pub has_more: bool,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_proxy_download_response_body`.
/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_proxy_download_response_body`.
///
/// Operation `ak.open.mimi.command.proxy_download.v1`. `download_ref` is the
/// provider's own opaque handle; the SDK never interprets it as a URL or as a
/// typed Arkret identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiProxyDownloadResponseBody {
    pub download_ref: NonEmptyString,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub download_request_headers: BTreeMap<String, NonEmptyString>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_room_update_request_body`.
/// `mimi-operations.schema.json#/$defs/mimi_room_update_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRoomUpdateRequestBody {
    pub mls_group_id: MlsGroupId,
    pub update: MimiRoomUpdate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_uint64_decimal")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub confirmed_transcript_hash: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub sender_actor_id: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<serde_json::Value>)))]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub room_binding_event: Option<EventAdmissionSubmission>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_notify_request_body`.
/// `mimi-operations.schema.json#/$defs/mimi_notify_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiNotifyRequestBody {
    pub notification: MimiNotification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub origin_provider_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub routing: Option<MimiNotificationRouting>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_request_consent_response_body`.
/// `mimi-operations.schema.json#/$defs/mimi_request_consent_response_body`.
/// The old `status` mirror is not part of the closed outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRequestConsentResponseBody {
    pub consent_id: ConsentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub challenge: Option<NonEmptyString>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_update_consent_response_body`.
/// `mimi-operations.schema.json#/$defs/mimi_update_consent_response_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiUpdateConsentResponseBody {
    pub consent_id: ConsentId,
    pub decision: MimiConsentDecision,
    #[serde(with = "canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub event_ref: EventId,
}
