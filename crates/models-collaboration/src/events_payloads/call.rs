//! Call-state and call-participant payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_participant`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantBinding {
    pub scheme: String,
    pub realm_id: RealmId,
    pub call_id: String,
    pub focus_id: String,
    pub actor_id: Did,
    pub device_id: String,
    pub participant_identity: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub issuer_kid: DidUrl,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipantMedia {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipant {
    pub actor_id: Did,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub joined_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foci_preferred: Option<Vec<String>>,
    pub participant_identity: String,
    pub participant_binding: ParticipantBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<CallParticipantMedia>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallParticipantRemovalAction {
    Kick,
    Ban,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipantRemoval {
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub action: CallParticipantRemovalAction,
    pub removed_by: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub removed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CallRosterDelta {
    Join {
        participant: CallParticipant,
    },
    Leave {
        observed_tag: EventId,
        actor_id: Did,
        device_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CallModerationDelta {
    RemoveParticipant {
        removal: CallParticipantRemoval,
    },
    RestoreParticipant {
        observed_tag: EventId,
        actor_id: Did,
        restored_by: Did,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        restored_at: DateTime<Utc>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallMuteOverrideStatus {
    Active,
    Cleared,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMuteOverride {
    pub status: CallMuteOverrideStatus,
    pub actor_id: Did,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_muted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video_muted: Option<bool>,
    pub changed_by: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl CallMuteOverride {
    pub fn validate(&self) -> Result<()> {
        let active_fields = self.audio_muted.is_some() && self.video_muted.is_some();
        if (self.status == CallMuteOverrideStatus::Active) != active_fields {
            return schema_violation(
                "active mute override requires audio_muted/video_muted; cleared forbids them",
            );
        }
        Ok(())
    }
}

/// Stable opaque recording/transcript lifecycle handle used byte-for-byte in
/// exporter context derivation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallRecordingId(String);

impl CallRecordingId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !recording_id_is_canonical(&value) {
            return schema_violation("recording_id must be ASCII [A-Za-z0-9._-], length 1..=128");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for CallRecordingId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CallRecordingId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Closed failure-code subset used by recording, transcription and artifact
/// deletion. Registered values are stored as the generated [`ReasonCode`];
/// only the schema's `x_...` extension form may remain unknown.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallCaptureFailureReasonCode(ReasonCode);

impl CallCaptureFailureReasonCode {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !call_capture_failure_reason_code_is_valid(&value) {
            return schema_violation("invalid call capture failure_reason_code");
        }
        Ok(Self(ReasonCode::from_wire(&value)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn reason_code(&self) -> &ReasonCode {
        &self.0
    }
}

impl Serialize for CallCaptureFailureReasonCode {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CallCaptureFailureReasonCode {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingMode {
    #[serde(rename = "audio")]
    AudioOnly,
    #[serde(rename = "audio_video")]
    AudioVideo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingCaptureKind {
    Recording,
    Transcript,
}

/// Typed payload for `ak.call.recording.start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingStartPayload {
    pub call_id: CallId,
    pub recording_id: CallRecordingId,
    pub recording_agent: Did,
    pub capture_kind: RecordingCaptureKind,
    pub mode: RecordingMode,
    pub visible_notice: bool,
    pub result: RecordingStartResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingStartResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_start_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_start_event_id: Option<EventId>,
    pub retention: CallRecordingRetention,
}

impl RecordingStartPayload {
    pub fn validate(&self, event_id: &EventId) -> std::result::Result<(), &'static str> {
        if !self.visible_notice || self.result.retention.consent_confirmed != Some(true) {
            return Err(ReasonCode::RECORDING_CONSENT_REQUIRED);
        }
        let valid_ref = match self.capture_kind {
            RecordingCaptureKind::Recording => {
                self.result.recording_start_event_id.as_ref() == Some(event_id)
                    && self.result.transcript_start_event_id.is_none()
            }
            RecordingCaptureKind::Transcript => {
                self.result.transcript_start_event_id.as_ref() == Some(event_id)
                    && self.result.recording_start_event_id.is_none()
            }
        };
        if !valid_ref {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRecordingArtifactKind {
    Recording,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRecordingEncryptionAlg {
    MlsExporterAeadXchacha20poly1305,
    MlsExporterAeadAes256Gcm,
    MlsExporterAeadXchacha20poly1305Stream,
    MlsExporterAeadAes256GcmStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRecordingDeletionTrigger {
    RetentionExpiry,
    Manual,
    RealmPolicy,
    ParticipantErasure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRecordingDeletionOutcome {
    Pending,
    Completed,
    BlockedByLegalHold,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingEncryptionContext {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub recording_id: CallRecordingId,
    pub media_service_id: Did,
    pub recording_start_event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingEncryption {
    pub alg: CallRecordingEncryptionAlg,
    pub exporter_label: String,
    pub context: CallRecordingEncryptionContext,
    pub ciphertext_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingRetention {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub retention_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_trigger: Option<CallRecordingDeletionTrigger>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_lock: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_confirmed: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingDeletionAudit {
    pub trigger: CallRecordingDeletionTrigger,
    pub outcome: CallRecordingDeletionOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_event_id: Option<EventId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub requested_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_receipt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<CallCaptureFailureReasonCode>,
}

/// Counterpart for `spec/v1/artifacts/schemas/call-recording-artifact.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingArtifact {
    pub schema: String,
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub recording_id: CallRecordingId,
    pub recording_start_event_id: EventId,
    pub artifact_kind: CallRecordingArtifactKind,
    pub blob_ref: BlobRef,
    pub content_digest: Hash,
    pub ciphertext_digest: Hash,
    pub size_bytes: u64,
    pub duration_ms: u64,
    pub media_type: String,
    pub encryption: CallRecordingEncryption,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    pub retention: CallRecordingRetention,
    pub produced_by: Did,
    pub recording_initiator_capability_ref: GrantId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_audit: Option<CallRecordingDeletionAudit>,
}

impl CallRecordingArtifact {
    pub fn validate(&self) -> Result<()> {
        if self.schema != CALL_RECORDING_ARTIFACT_SCHEMA {
            return schema_violation(format!(
                "call recording artifact schema must be {CALL_RECORDING_ARTIFACT_SCHEMA}"
            ));
        }
        if !self.blob_ref.as_str().starts_with("ak:blob:") {
            return recording_artifact_pipeline_bypassed(
                "recording artifact blob_ref must be a Arkret blob reference",
            );
        }
        if self.media_type.trim().is_empty() || !self.media_type.contains('/') {
            return schema_violation(
                "recording artifact media_type must be type/constraint_subkind",
            );
        }
        if self.encryption.exporter_label != EXPORTER_LABEL_RTC_RECORDING_KEY {
            return recording_artifact_pipeline_bypassed(format!(
                "recording artifact exporter_label must be {EXPORTER_LABEL_RTC_RECORDING_KEY}"
            ));
        }
        if self.encryption.ciphertext_digest != self.ciphertext_digest {
            return schema_violation(
                "recording artifact ciphertext_digest must match encryption.ciphertext_digest",
            );
        }
        if self.encryption.context.realm_id != self.realm_id
            || self.encryption.context.call_id != self.call_id
            || self.encryption.context.recording_id != self.recording_id
            || self.encryption.context.recording_start_event_id != self.recording_start_event_id
        {
            return schema_violation(
                "recording artifact encryption.context must bind realm_id/call_id/recording_id/recording_start_event_id",
            );
        }
        if self.encryption.context.focus_id.trim().is_empty() {
            return recording_artifact_pipeline_bypassed(
                "recording artifact encryption.context.focus_id is required",
            );
        }
        if self.encryption.context.media_service_id != self.produced_by {
            return schema_violation(
                "recording artifact produced_by must match encryption.context.media_service_id",
            );
        }
        if self.retention_policy_id.is_none() && self.retention.retention_expires_at.is_none() {
            return schema_violation(
                "recording artifact requires retention_policy_id or retention.retention_expires_at",
            );
        }
        if let Some(audit) = &self.deletion_audit {
            validate_recording_deletion_audit(&self.retention, audit)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStatePayloadRecordingResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<CallRecordingRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_start_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<CallRecordingArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<CallCaptureFailureReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

impl CallStatePayloadRecordingResult {
    pub fn validate_ready_artifact(
        &self,
        call_id: &CallId,
        recording_id: &CallRecordingId,
    ) -> std::result::Result<(), &'static str> {
        let Some(artifact) = &self.artifact else {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        };
        if let Err(error) = artifact.validate() {
            let message = error.to_string();
            if message.contains(ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED) {
                return Err(ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED);
            }
            if message.contains(ReasonCode::LEGAL_HOLD_ACTIVE) {
                return Err(ReasonCode::LEGAL_HOLD_ACTIVE);
            }
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if &artifact.call_id != call_id || &artifact.recording_id != recording_id {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self
            .recording_start_event_id
            .as_ref()
            .is_some_and(|id| id != &artifact.recording_start_event_id)
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self
            .content_digest
            .as_ref()
            .is_some_and(|digest| digest != &artifact.content_digest)
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self
            .duration_ms
            .is_some_and(|duration| duration != artifact.duration_ms)
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self
            .media_type
            .as_ref()
            .is_some_and(|media_type| media_type != &artifact.media_type)
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self
            .retention_policy_id
            .as_ref()
            .is_some_and(|policy_id| Some(policy_id) != artifact.retention_policy_id.as_ref())
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self
            .retention
            .as_ref()
            .is_some_and(|retention| retention != &artifact.retention)
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStatePayloadTranscriptResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<CallRecordingRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_start_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<CallCaptureFailureReasonCode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallLifecycleState {
    Scheduled,
    Ringing,
    Connecting,
    Active,
    Ended,
    Missed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStateTransition {
    pub from: Option<CallLifecycleState>,
    pub to: CallLifecycleState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallMode {
    P2p,
    Mesh,
    Sfu,
    Mcu,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallFocus {
    pub mode: CallMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_focus: Option<NonEmptyString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRecordingState {
    Recording,
    Stopped,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingTransition {
    pub recording_id: CallRecordingId,
    pub from: CallRecordingState,
    pub to: CallRecordingState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CallStatePayloadRecordingResult>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallTranscriptState {
    Transcribing,
    Stopped,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallTranscriptTransition {
    pub recording_id: CallRecordingId,
    pub from: CallTranscriptState,
    pub to: CallTranscriptState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CallStatePayloadTranscriptResult>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStatePayload {
    pub call_id: CallId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_transition: Option<CallStateTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focus: Option<CallFocus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_transition: Option<CallRecordingTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_transition: Option<CallTranscriptTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_delta: Option<CallRosterDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moderation_delta: Option<CallModerationDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mute_override: Option<CallMuteOverride>,
}

impl CallStatePayload {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.state_transition.is_none()
            && self.focus.is_none()
            && self.recording_transition.is_none()
            && self.transcript_transition.is_none()
            && self.roster_delta.is_none()
            && self.moderation_delta.is_none()
            && self.mute_override.is_none()
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if let Some(mute_override) = &self.mute_override {
            mute_override
                .validate()
                .map_err(|_| ErrorCode::SCHEMA_VIOLATION)?;
        }
        if let Some(CallModerationDelta::RemoveParticipant { removal }) = &self.moderation_delta {
            let valid_subject = match removal.action {
                CallParticipantRemovalAction::Kick => removal.device_id.is_some(),
                CallParticipantRemovalAction::Ban => removal.device_id.is_none(),
            };
            if !valid_subject {
                return Err(ErrorCode::SCHEMA_VIOLATION);
            }
        }
        self.validate_recording_result_artifact()?;
        self.validate_transcript_result_storage()
    }

    pub fn validate_recording_result_artifact(&self) -> std::result::Result<(), &'static str> {
        let Some(transition) = &self.recording_transition else {
            return Ok(());
        };
        if transition.to == CallRecordingState::Recording {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        match transition.to {
            CallRecordingState::Ready => transition
                .result
                .as_ref()
                .ok_or(ErrorCode::SCHEMA_VIOLATION)?
                .validate_ready_artifact(&self.call_id, &transition.recording_id),
            CallRecordingState::Failed => {
                if let Some(result) = &transition.result
                    && (result.artifact.is_some()
                        || result
                            .failure_message
                            .as_deref()
                            .is_some_and(contains_backend_direct_recording_ref))
                {
                    return Err(ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn validate_transcript_result_storage(&self) -> std::result::Result<(), &'static str> {
        let Some(transition) = &self.transcript_transition else {
            return Ok(());
        };
        if transition.to == CallTranscriptState::Transcribing {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        match transition.to {
            CallTranscriptState::Ready => {
                let result = transition
                    .result
                    .as_ref()
                    .ok_or(ErrorCode::SCHEMA_VIOLATION)?;
                if result.transcript_start_event_id.is_none() {
                    return Err(ErrorCode::SCHEMA_VIOLATION);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn validate_recording_deletion_audit(
    retention: &CallRecordingRetention,
    audit: &CallRecordingDeletionAudit,
) -> Result<()> {
    if retention.audit_lock == Some(true)
        && audit.outcome == CallRecordingDeletionOutcome::Completed
    {
        return Err(Error::Protocol(
            "legal_hold_active: recording deletion cannot complete under audit_lock".to_owned(),
        ));
    }
    let Some(deletion_trigger) = retention.deletion_trigger else {
        return schema_violation("recording deletion_audit requires retention.deletion_trigger");
    };
    if audit.trigger != deletion_trigger {
        return schema_violation(
            "recording deletion_audit.trigger must match retention.deletion_trigger",
        );
    }
    if audit.outcome == CallRecordingDeletionOutcome::Completed
        && audit
            .erasure_receipt_ref
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return schema_violation("completed recording deletion_audit requires erasure_receipt_ref");
    }
    if audit.outcome == CallRecordingDeletionOutcome::BlockedByLegalHold
        && audit.legal_hold_ref.as_deref().is_none_or(str::is_empty)
    {
        return Err(Error::Protocol(
            "legal_hold_active: blocked recording deletion requires legal_hold_ref".to_owned(),
        ));
    }
    Ok(())
}

fn recording_id_is_canonical(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn call_capture_failure_reason_code_is_valid(value: &str) -> bool {
    matches!(
        value,
        ReasonCode::MEDIA_NEGOTIATION_TIMEOUT
            | ReasonCode::PERMISSION_DENIED
            | ReasonCode::BACKEND_UNAVAILABLE
            | ReasonCode::MEDIA_SOURCE_UNAVAILABLE
            | ReasonCode::STORAGE_FAILED
            | ReasonCode::POLICY_REVOKED
            | ReasonCode::CONSENT_WITHDRAWN
            | ReasonCode::INTEGRITY_FAILED
    ) || value.strip_prefix("x_").is_some_and(|extension| {
        (1..=62).contains(&extension.len())
            && extension
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

fn contains_backend_direct_recording_ref(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("s3://")
        || lower.contains("gs://")
        || lower.contains("livekit")
        || lower.contains("gcs")
        || lower.contains("s3.amazonaws.com")
}

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

fn recording_artifact_pipeline_bypassed(message: impl Into<String>) -> Result<()> {
    Err(Error::Protocol(format!(
        "recording_artifact_pipeline_bypassed: {}",
        message.into()
    )))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn recording_start_requires_event_bound_consent_result() {
        let event_id = EventId::new("ak:event:019a7360-0000-7000-8000-000000000003").unwrap();
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "recording_id": "capture-1",
            "recording_agent": "did:webvh:z6mkfixture:recorder.example",
            "capture_kind": "recording",
            "mode": "audio_video",
            "visible_notice": true,
            "result": {
                "recording_start_event_id": event_id,
                "retention": {"consent_confirmed": true}
            }
        });
        let payload: RecordingStartPayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(payload.mode, RecordingMode::AudioVideo);
        payload.validate(&event_id).unwrap();

        let mut missing_result = value.clone();
        missing_result.as_object_mut().unwrap().remove("result");
        assert!(serde_json::from_value::<RecordingStartPayload>(missing_result).is_err());

        let mut invalid_id = value.clone();
        invalid_id["recording_id"] = json!("capture id");
        assert!(serde_json::from_value::<RecordingStartPayload>(invalid_id).is_err());

        let mut missing_consent = value;
        missing_consent["result"]["retention"]["consent_confirmed"] = json!(false);
        let payload: RecordingStartPayload = serde_json::from_value(missing_consent).unwrap();
        assert_eq!(
            payload.validate(&event_id),
            Err(ReasonCode::RECORDING_CONSENT_REQUIRED)
        );
    }

    #[test]
    fn call_capture_failure_reason_is_closed_with_x_extension() {
        let registered =
            serde_json::from_value::<CallCaptureFailureReasonCode>(json!("backend_unavailable"))
                .unwrap();
        assert_eq!(registered.reason_code(), &ReasonCode::BackendUnavailable);
        assert!(
            serde_json::from_value::<CallCaptureFailureReasonCode>(json!("x_vendor_timeout"))
                .is_ok()
        );
        assert!(
            serde_json::from_value::<CallCaptureFailureReasonCode>(json!("call_state_terminal"))
                .is_err()
        );
        assert!(serde_json::from_value::<CallCaptureFailureReasonCode>(json!("x_UPPER")).is_err());
    }

    #[test]
    fn call_state_transcript_result_round_trips_and_validates() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "transcript_transition": {
                "recording_id": "capture-1",
                "from": "transcribing",
                "to": "failed",
                "result": {
                    "content_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "media_type": "text/vtt",
                    "language": "en-US",
                    "retention_policy_id": "ak:policy:019a7360-0000-7000-8000-000000000005",
                    "retention": {
                        "consent_confirmed": true
                    },
                    "transcript_start_event_id": "ak:event:019a7360-0000-7000-8000-000000000003",
                    "failure_reason_code": "storage_failed"
                }
            }
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        payload.validate().unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(
            encoded["transcript_transition"]["result"]["media_type"],
            "text/vtt"
        );
        assert_eq!(
            encoded["transcript_transition"]["result"]["transcript_start_event_id"],
            "ak:event:019a7360-0000-7000-8000-000000000003"
        );
    }

    #[test]
    fn call_state_moderation_delta_round_trips() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "moderation_delta": {
                "op": "remove_participant",
                "removal": {
                    "actor_id": "did:webvh:z6mkfixture:bob.example",
                    "action": "ban",
                    "removed_by": "did:webvh:z6mkfixture:mod.example",
                    "removed_at": "2026-06-22T00:00:00.000Z"
                }
            }
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();
        payload.validate().unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(
            encoded["moderation_delta"]["removal"]["actor_id"],
            "did:webvh:z6mkfixture:bob.example"
        );
    }

    #[test]
    fn call_state_mute_override_enforces_status_shape() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "mute_override": {
                "status": "active",
                "actor_id": "did:webvh:z6mkfixture:bob.example",
                "device_id": "ak:device:019a7360-0000-7000-8000-000000000002",
                "audio_muted": true,
                "video_muted": false,
                "changed_by": "did:webvh:z6mkfixture:mod.example",
                "changed_at": "2026-06-22T00:00:00.000Z",
                "reason": "moderation"
            }
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();
        payload.validate().unwrap();

        let invalid: CallStatePayload = serde_json::from_value(json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "mute_override": {
                "status": "cleared",
                "actor_id": "did:webvh:z6mkfixture:bob.example",
                "device_id": "ak:device:019a7360-0000-7000-8000-000000000002",
                "audio_muted": true,
                "video_muted": false,
                "changed_by": "did:webvh:z6mkfixture:mod.example",
                "changed_at": "2026-06-22T00:00:00.000Z"
            }
        }))
        .unwrap();
        assert_eq!(invalid.validate(), Err(ErrorCode::SCHEMA_VIOLATION));
    }

    #[test]
    fn call_state_transcript_result_rejects_direct_backend_refs() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "transcript_transition": {
                "recording_id": "capture-1",
                "from": "transcribing",
                "to": "ready",
                "result": {
                    "transcript_start_event_id": "ak:event:019a7360-0000-7000-8000-000000000003",
                    "retention": {"consent_confirmed": true},
                    "transcript_artifact_url": "https://backend.example/transcript.vtt"
                }
            }
        });

        assert!(serde_json::from_value::<CallStatePayload>(value).is_err());
    }

    #[test]
    fn call_state_rejects_capture_reentry_without_start() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "transcript_transition": {
                "recording_id": "capture-1",
                "from": "stopped",
                "to": "transcribing"
            }
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        assert_eq!(payload.validate(), Err(ErrorCode::SCHEMA_VIOLATION));
    }
}
