// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/call-recording-artifact.schema.json
// sha256=9ba1c589fd39b699197ea8accf07745d87868410f39a3194380062a4700ef48f
//
// Input: schemas/blob-operations.schema.json
// sha256=22ea9fba9b25f14681d440a87a556beed4b74611057513e66a5178d01fdfa094
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Input: schemas/current-state.schema.json
// sha256=303069f3b12147816e080f5948d4877f5444a1ff82f532785c8244cc0a173e34
//
// Input: schemas/../registry/contract-registry.json
// sha256=dde1e7a2a93f9a059a07141fcd458e7d4b2a168306a4af6f59aa7190b0f5d94e
//
// Bindings: tools/closed-model-bindings.json
// sha256=a78e63d1f3a48c87115a3e40e578dc4aeb5f619833613e5eb9fae1be319bff29

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
    pub signature: String,
}

/// Counterpart: `current-state.schema.json#/$defs/call_roster_source`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRosterSource {
    pub tag_id: String,
    pub source_commit: RealmCommit,
    pub value: CallRosterDelta,
}

/// Counterpart: `current-state.schema.json#/$defs/call_participant_signing_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipantSigningKey {
    pub public_key_base64url: String,
}

/// Counterpart: `current-state.schema.json#/$defs/call_roster_entry`.
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

/// Counterpart: `current-state.schema.json#/$defs/call_roster_value`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRosterCurrentValue {
    pub entries: Vec<CallRosterEntry>,
    pub last_source: CallRosterSource,
}

/// Counterpart: `current-state.schema.json#/$defs/call_moderation_source`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallModerationSource {
    pub tag_id: String,
    pub source_commit: RealmCommit,
    pub value: CallModerationDelta,
}

/// Counterpart: `current-state.schema.json#/$defs/call_moderation_entry`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallModerationEntry {
    pub tag_id: String,
    pub source_commit: RealmCommit,
    pub value: CallModerationDelta,
}

/// Counterpart: `current-state.schema.json#/$defs/call_moderation_value`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallModerationCurrentValue {
    pub entries: Vec<CallModerationEntry>,
    pub last_source: CallModerationSource,
}

/// Counterpart: `current-state.schema.json#/$defs/call_capture_result_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallCaptureResultStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "failed")]
    Failed,
}

/// Counterpart:
/// `current-state.schema.json#/$defs/current_call_recording_artifact/properties/value`.
/// Complete capture result; revision belongs to the enclosing CurrentState.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingArtifactCurrentValue {
    pub status: CallCaptureResultStatus,
    pub details: CallRecordingMetadata,
}

/// Counterpart:
/// `current-state.schema.json#/$defs/current_call_transcript_artifact/properties/value`.
/// Complete capture result; revision belongs to the enclosing CurrentState.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallTranscriptArtifactCurrentValue {
    pub status: CallCaptureResultStatus,
    pub details: CallTranscriptMetadata,
}

pub const CALL_ROSTER_WRITE_INDEX: usize = 7;

pub const CALL_MODERATION_WRITE_INDEX: usize = 6;
