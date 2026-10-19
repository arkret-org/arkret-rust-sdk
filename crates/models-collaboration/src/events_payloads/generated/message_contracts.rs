// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=cc3c0dfe191c29585876c1d6438a28787cf75076690f0ef1d7a999c470499b9a
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=5f2752ea44fd1fbc9de2b85e1d89524b11ee593a43ddc700d52484230e874397
//
// Bindings: tools/closed-model-bindings.json
// sha256=42637b7091c5d9a931ae042b62a3b4b684763d010e044485fc40891314c2f844

/// Counterpart: `event-payload.schema.json#/$defs/message_redact_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_redact_payload`.
///
/// `message_id` is the single target carrier: the registered
/// `ak.component.object.redaction.v1` cell subject is that typed Message ID, so
/// the same Message cannot be addressed two ways.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRedactPayload {
    pub message_id: MessageId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub track_name: Option<MessageTrackName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub preserve: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mimi_provenance: Option<MimiMessageProvenance>,
}

/// Counterpart: `event-payload.schema.json#/$defs/message_revise_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_revise_payload`.
///
/// `message_id` is the single target carrier: the registered
/// `ak.component.message.revision.v1` cell subject is that typed Message ID.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRevisePayload {
    pub message_id: MessageId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub track_name: Option<MessageTrackName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub metadata: Option<MessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mimi_provenance: Option<MimiMessageProvenance>,
}
