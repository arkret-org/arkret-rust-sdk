// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/mimi-operations.schema.json
// sha256=edfa36ae8bc99cf7017536d7a5ae5d02da2dfcbf8bb5a4ec17cc3701c0869628
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/mimi-interop.schema.json
// sha256=1da40835f537bb2d61f690537162e825b6dc11a8fcb97b8ca7824b02fe137329
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=e0ad298cfeb1fcc4200f4289720d4b0380337d010198cb000a88f7ff3f560a9f
//
// Bindings: tools/closed-model-bindings.json
// sha256=a09494f9b20fd0b06cee86eb504c26b02dab5a7b147a7e5a1034a07d05811aef

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
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub associated_data: Option<MimiOpaquePayload>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_submit_message_outcome`.
/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_submit_message_outcome`.
///
/// `event_ref` is present only when the submission also produced an Arkret
/// Event; a pure outbound relay reports delivery without one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiSubmitMessageOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub event_ref: Option<EventId>,
    pub delivery: MimiDelivery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<MimiFailure>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_identifier_query_outcome`.
/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_identifier_query_outcome`.
///
/// The outcome is a proof-carrying object: its registered proof context is
/// `ak.mimi_identifier_query_outcome_proof.v1`, and the signed transcript is
/// the canonical body with `proofs` removed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifierQueryOutcome {
    pub matches: Vec<MimiIdentifierMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
    pub has_more: bool,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_proxy_download_outcome`.
/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_proxy_download_outcome`.
///
/// Operation `ak.open.mimi.command.proxy_download.v1`. `download_ref` is the
/// provider's own opaque handle; the SDK never interprets it as a URL or as a
/// typed Arkret identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiProxyDownloadOutcome {
    pub download_ref: NonEmptyString,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, NonEmptyString>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_key_material_request_body`.
/// `mimi-operations.schema.json#/$defs/mimi_key_material_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiKeyMaterialRequestBody {
    pub requester_id: DidCoreId,
    pub strand_id: StrandId,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mimi_room_uri: Option<MimiRoomUri>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mls_group_id: Option<MlsGroupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub epoch: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_nonempty_identifier_query_proofs"
    )]
    pub proofs: Vec<PayloadProof>,
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
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
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

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_request_consent_outcome`.
/// `mimi-operations.schema.json#/$defs/mimi_request_consent_outcome`.
/// The old `status` mirror is not part of the closed outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiRequestConsentOutcome {
    pub consent_id: ConsentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub challenge: Option<NonEmptyString>,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_update_consent_outcome`.
/// `mimi-operations.schema.json#/$defs/mimi_update_consent_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiUpdateConsentOutcome {
    pub consent_id: ConsentId,
    pub decision: MimiConsentDecision,
    #[serde(with = "canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub event_ref: EventId,
}

/// Counterpart: `mimi-operations.schema.json#/$defs/mimi_key_material_outcome`.
/// `mimi-operations.schema.json#/$defs/mimi_key_material_outcome`.
/// Presence is preserved for the schema's at-least-one branch constraint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiKeyMaterialOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub keypackages: Option<Vec<MimiKeyPackage>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub group_info: Option<MimiGroupInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub failures: Option<Vec<MimiFailure>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub signature: Option<MimiOperationSignature>,
}
