// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/call-recording-artifact.schema.json
// sha256=d8f6f18b12611c37cf56573ef2cffe8d817a978f0df348bfc1d9a003ad576d92
//
// Input: schemas/event-payload.schema.json
// sha256=51122d20a1426cc7e23a5e93ea307be964a90e3eaa9e5980d051ae67c2634887
//
// Input: schemas/typed-current-result.schema.json
// sha256=224f4055e7e30ab5a95a401acc78ea65e9fac2e347ea0fcd0931860a3c6feec1
//
// Input: schemas/../registry/contract-registry.json
// sha256=103ae952f29a7a0e999af294c5fd3c81a7c64e07fc5a466aefc81ddaee81311e
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

/// Counterpart: `call-recording-artifact.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/call-recording-artifact.schema.json`.
///
/// The schema identity `ak.schema.call_recording_artifact.v1` already fixes the
/// recording artifact family, so the artifact carries no `artifact_kind`
/// member (`zh/crypto-media/call-state.md`); the schema is closed and would
/// reject one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingArtifact {
    pub schema: String,
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub recording_id: CallRecordingId,
    pub recording_start_event_id: EventId,
    pub blob_ref: BlobRef,
    pub size_bytes: u64,
    pub duration_ms: u64,
    pub media_type: String,
    pub encryption: CallRecordingEncryption,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub retention_policy_id: Option<PolicyId>,
    pub retention: CallRecordingRetention,
    pub produced_by: DidCoreId,
    pub recording_initiator_capability_ref: GrantId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub deletion_audit: Option<CallRecordingDeletionAudit>,
}

/// Counterpart: `event-payload.schema.json#/$defs/call_state_payload`.
/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStatePayload {
    pub call_id: CallId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub state_transition: Option<CallStateTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub focus: Option<CallFocus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub recording_transition: Option<CallRecordingTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub transcript_transition: Option<CallTranscriptTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub roster_delta: Option<CallRosterDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub moderation_delta: Option<CallModerationDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mute_override: Option<CallMuteOverride>,
}

/// Counterpart: `event-payload.schema.json#/$defs/participant_binding`.
/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_participant`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantBinding {
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub issuer_kid: DidUrl,
    pub sig: String,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/call_roster_source`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRosterSource {
    pub tag_id: String,
    pub source_commit: RealmCommit,
    pub value: CallRosterDelta,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/call_participant_signing_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipantSigningKey {
    pub public_key_b64u: String,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/call_roster_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRosterEntry {
    pub tag_id: String,
    pub source_commit: RealmCommit,
    pub value: CallRosterDelta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub participant_signing_key: Option<CallParticipantSigningKey>,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/call_roster_value`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRosterCurrentValue {
    pub entries: Vec<CallRosterEntry>,
    pub last_source: CallRosterSource,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/call_moderation_source`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallModerationSource {
    pub tag_id: String,
    pub source_commit: RealmCommit,
    pub value: CallModerationDelta,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/call_moderation_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallModerationEntry {
    pub tag_id: String,
    pub source_commit: RealmCommit,
    pub value: CallModerationDelta,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/call_moderation_value`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallModerationCurrentValue {
    pub entries: Vec<CallModerationEntry>,
    pub last_source: CallModerationSource,
}

pub const CALL_ROSTER_WRITE_INDEX: usize = 7;

pub const CALL_MODERATION_WRITE_INDEX: usize = 6;
