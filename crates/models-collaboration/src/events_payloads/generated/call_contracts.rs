// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/call-recording-artifact.schema.json
// sha256=cb62b6ebc010c0a6b7362f6ec3c71b47d1df97d0c3b5252009bd350627cafa7b
//
// Input: schemas/event-payload.schema.json
// sha256=74e26ef25ba5846ba74149c301a7ff5c7f1afc507f2cfd207cfe0edc060507bf
//
// Input: schemas/current-state.schema.json
// sha256=feba0ff19e227c276a3792aaed506b6534bf9ff8ce6c2e91a0ab36c04777785f
//
// Input: schemas/../registry/contract-registry.json
// sha256=41ba0124d0722954caf755d55e28b1ed4faa05f014c2a8e02549035eda4a76e6
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

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

pub const CALL_ROSTER_WRITE_INDEX: usize = 7;

pub const CALL_MODERATION_WRITE_INDEX: usize = 6;
