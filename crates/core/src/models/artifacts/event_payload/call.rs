//! Call-state and call-participant payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

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
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer_kid: Did,
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
    pub joined_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foci_preferred: Option<Vec<String>>,
    pub participant_identity: String,
    pub participant_binding: ParticipantBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<CallParticipantMedia>,
}

/// Removed participant trace in `ak.call.state.removed_participants[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedCallParticipant {
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub action: String,
    pub removed_at: DateTime<Utc>,
}

/// Current moderator mute override in `ak.call.state.participant_mute_overrides[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantMuteOverride {
    pub actor_id: Did,
    pub device_id: String,
    pub audio_muted: bool,
    pub video_muted: bool,
    pub muted_by: Did,
    pub muted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<BTreeMap<String, Value>>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_kind: Option<RecordingCaptureKind>,
    pub mode: RecordingMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_notice: Option<bool>,
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
    pub requested_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_audit: Option<CallRecordingDeletionAudit>,
}

impl CallRecordingArtifact {
    pub const SCHEMA: &'static str = CALL_RECORDING_ARTIFACT_SCHEMA;

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return schema_violation(format!(
                "call recording artifact schema must be {}",
                Self::SCHEMA
            ));
        }
        if !self.blob_ref.as_str().starts_with("ak:blob:") {
            return recording_artifact_pipeline_bypassed(
                "recording artifact blob_ref must be a Arkret blob reference",
            );
        }
        if self.media_type.trim().is_empty() || !self.media_type.contains('/') {
            return schema_violation("recording artifact media_type must be type/subtype");
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

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
        if &artifact.call_id != call_id {
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

/// Counterpart for `call_state_payload.transcript_result`.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

impl CallStatePayloadTranscriptResult {
    fn consent_confirmed(&self) -> bool {
        self.retention
            .as_ref()
            .and_then(|retention| retention.consent_confirmed)
            .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStatePayload {
    pub call_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_focus: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participants: Option<Vec<CallParticipant>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_participants: Option<Vec<RemovedCallParticipant>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_mute_overrides: Option<Vec<ParticipantMuteOverride>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_result: Option<CallStatePayloadRecordingResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_result: Option<CallStatePayloadTranscriptResult>,
}

impl CallStatePayload {
    pub fn validate_recording_result_artifact(&self) -> std::result::Result<(), &'static str> {
        let Some(recording_state) = self.recording_state.as_deref() else {
            return Ok(());
        };
        let call_id =
            CallId::new(self.call_id.clone()).map_err(|_| ErrorCode::SCHEMA_VIOLATION)?;
        match recording_state {
            "ready" => self
                .recording_result
                .as_ref()
                .ok_or(ErrorCode::SCHEMA_VIOLATION)?
                .validate_ready_artifact(&call_id),
            "failed" => {
                if let Some(result) = &self.recording_result
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
        let Some(transcript_state) = self.transcript_state.as_deref() else {
            return Ok(());
        };
        match transcript_state {
            "transcribing" => {
                if !self
                    .transcript_result
                    .as_ref()
                    .is_some_and(CallStatePayloadTranscriptResult::consent_confirmed)
                {
                    return Err(ReasonCode::RECORDING_CONSENT_REQUIRED);
                }
                Ok(())
            }
            "stopped" | "ready" | "failed" => {
                let result = self
                    .transcript_result
                    .as_ref()
                    .ok_or(ErrorCode::SCHEMA_VIOLATION)?;
                if result.transcript_start_event_id.is_none() {
                    return Err(ErrorCode::SCHEMA_VIOLATION);
                }
                Ok(())
            }
            _ => Err(ErrorCode::SCHEMA_VIOLATION),
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
        return Err(Error::Protocol(format!(
            "legal_hold_active: recording deletion cannot complete under audit_lock"
        )));
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
        return Err(Error::Protocol(format!(
            "legal_hold_active: blocked recording deletion requires legal_hold_ref"
        )));
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
    fn recording_start_requires_mode_and_valid_recording_id() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "recording_id": "capture-1",
            "recording_agent": "did:webvh:z6mkfixture:recorder.example",
            "mode": "audio_video"
        });
        let payload: RecordingStartPayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(payload.mode, RecordingMode::AudioVideo);

        let mut missing_mode = value.clone();
        missing_mode.as_object_mut().unwrap().remove("mode");
        assert!(serde_json::from_value::<RecordingStartPayload>(missing_mode).is_err());

        let mut invalid_id = value;
        invalid_id["recording_id"] = json!("capture id");
        assert!(serde_json::from_value::<RecordingStartPayload>(invalid_id).is_err());
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
            "state": "ended",
            "transcript_state": "failed",
            "transcript_result": {
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
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        payload.validate_transcript_result_storage().unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(encoded["transcript_result"]["media_type"], "text/vtt");
        assert_eq!(
            encoded["transcript_result"]["transcript_start_event_id"],
            "ak:event:019a7360-0000-7000-8000-000000000003"
        );
        assert_eq!(
            encoded["transcript_result"]["failure_reason_code"],
            "storage_failed"
        );
    }

    #[test]
    fn call_state_removed_participants_round_trips() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "state": "active",
            "removed_participants": [{
                "actor_id": "did:webvh:z6mkfixture:bob.example",
                "action": "ban",
                "removed_at": "2026-06-22T00:00:00Z"
            }]
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        assert_eq!(
            payload
                .removed_participants
                .as_ref()
                .and_then(|removed| removed.first())
                .map(|removed| removed.action.as_str()),
            Some("ban")
        );
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(
            encoded["removed_participants"][0]["actor_id"],
            "did:webvh:z6mkfixture:bob.example"
        );
    }

    #[test]
    fn call_state_participant_mute_overrides_round_trips() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "state": "active",
            "participant_mute_overrides": [{
                "actor_id": "did:webvh:z6mkfixture:bob.example",
                "device_id": "ak:device:019a7360-0000-7000-8000-000000000002",
                "audio_muted": true,
                "video_muted": false,
                "muted_by": "did:webvh:z6mkfixture:mod.example",
                "muted_at": "2026-06-22T00:00:00Z",
                "reason": "moderation"
            }]
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        assert_eq!(
            payload
                .participant_mute_overrides
                .as_ref()
                .and_then(|overrides| overrides.first())
                .map(|override_row| (override_row.audio_muted, override_row.video_muted)),
            Some((true, false))
        );
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(
            encoded["participant_mute_overrides"][0]["device_id"],
            "ak:device:019a7360-0000-7000-8000-000000000002"
        );
    }

    #[test]
    fn call_state_transcript_result_rejects_direct_backend_refs() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "state": "ended",
            "transcript_state": "ready",
            "transcript_result": {
                "transcript_artifact_url": "https://backend.example/transcript.vtt"
            }
        });

        assert!(serde_json::from_value::<CallStatePayload>(value).is_err());
    }

    #[test]
    fn call_state_transcribing_requires_second_consent() {
        let value = json!({
            "call_id": "ak:call:019a7360-0000-7000-8000-000000000001",
            "state": "active",
            "transcript_state": "transcribing"
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        assert_eq!(
            payload.validate_transcript_result_storage(),
            Err(crate::ReasonCode::RECORDING_CONSENT_REQUIRED)
        );
    }
}
