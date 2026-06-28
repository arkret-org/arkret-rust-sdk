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

/// Removed participant trace in `ck.call.state.removed_participants[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedCallParticipant {
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub action: String,
    pub removed_at: DateTime<Utc>,
}

/// Current moderator mute override in `ck.call.state.participant_mute_overrides[]`.
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
    pub recording_id: String,
    pub media_service_did: Did,
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
    pub failure_reason_code: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/call-recording-artifact.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingArtifact {
    pub schema: String,
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub recording_id: String,
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
        if !recording_id_is_canonical(&self.recording_id) {
            return schema_violation("recording_id must be ASCII [A-Za-z0-9._-], length 1..=128");
        }
        if !self.blob_ref.as_str().starts_with("ck:blob:") {
            return recording_artifact_pipeline_bypassed(
                "recording artifact blob_ref must be a Cokret blob reference",
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
        if self.encryption.context.media_service_did != self.produced_by {
            return schema_violation(
                "recording artifact produced_by must match encryption.context.media_service_did",
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
    pub failure_reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

impl CallStatePayloadRecordingResult {
    pub fn validate_ready_artifact(
        &self,
        call_id: &CallId,
    ) -> std::result::Result<(), &'static str> {
        let Some(artifact) = &self.artifact else {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        };
        if let Err(error) = artifact.validate() {
            let message = error.to_string();
            if message.contains(REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED) {
                return Err(REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED);
            }
            if message.contains(REASON_LEGAL_HOLD_ACTIVE) {
                return Err(REASON_LEGAL_HOLD_ACTIVE);
            }
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        }
        if &artifact.call_id != call_id {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        }
        if self
            .recording_start_event_id
            .as_ref()
            .is_some_and(|id| id != &artifact.recording_start_event_id)
        {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        }
        if self
            .content_digest
            .as_ref()
            .is_some_and(|digest| digest != &artifact.content_digest)
        {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        }
        if self
            .duration_ms
            .is_some_and(|duration| duration != artifact.duration_ms)
        {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        }
        if self
            .media_type
            .as_ref()
            .is_some_and(|media_type| media_type != &artifact.media_type)
        {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        }
        if self
            .retention_policy_id
            .as_ref()
            .is_some_and(|policy_id| Some(policy_id) != artifact.retention_policy_id.as_ref())
        {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
        }
        if self
            .retention
            .as_ref()
            .is_some_and(|retention| retention != &artifact.retention)
        {
            return Err(ERROR_CODE_SCHEMA_VIOLATION);
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
    pub session_focus: Option<Value>,
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
        let call_id = CallId::new(self.call_id.clone()).map_err(|_| ERROR_CODE_SCHEMA_VIOLATION)?;
        match recording_state {
            "ready" => self
                .recording_result
                .as_ref()
                .ok_or(ERROR_CODE_SCHEMA_VIOLATION)?
                .validate_ready_artifact(&call_id),
            "failed" => {
                if let Some(result) = &self.recording_result
                    && (result.artifact.is_some()
                        || result
                            .failure_message
                            .as_deref()
                            .is_some_and(contains_backend_direct_recording_ref))
                {
                    return Err(REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED);
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
                    return Err(REASON_RECORDING_CONSENT_REQUIRED);
                }
                Ok(())
            }
            "stopped" | "ready" | "failed" => {
                let result = self
                    .transcript_result
                    .as_ref()
                    .ok_or(ERROR_CODE_SCHEMA_VIOLATION)?;
                if result.transcript_start_event_id.is_none() {
                    return Err(ERROR_CODE_SCHEMA_VIOLATION);
                }
                Ok(())
            }
            _ => Err(ERROR_CODE_SCHEMA_VIOLATION),
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
            "{REASON_LEGAL_HOLD_ACTIVE}: recording deletion cannot complete under audit_lock"
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
            "{REASON_LEGAL_HOLD_ACTIVE}: blocked recording deletion requires legal_hold_ref"
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

fn schema_violation(message: impl Into<String>) -> Result<()> {
    Err(Error::Protocol(format!(
        "{ERROR_CODE_SCHEMA_VIOLATION}: {}",
        message.into()
    )))
}

fn recording_artifact_pipeline_bypassed(message: impl Into<String>) -> Result<()> {
    Err(Error::Protocol(format!(
        "{REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED}: {}",
        message.into()
    )))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn call_state_transcript_result_round_trips_and_validates() {
        let value = json!({
            "call_id": "ck:call:019a7360-0000-7000-8000-000000000001",
            "state": "ended",
            "transcript_state": "ready",
            "transcript_result": {
                "content_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "media_type": "text/vtt",
                "language": "en-US",
                "retention_policy_id": "ck:policy:019a7360-0000-7000-8000-000000000005",
                "retention": {
                    "consent_confirmed": true
                },
                "transcript_start_event_id": "ck:event:019a7360-0000-7000-8000-000000000003"
            }
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        payload.validate_transcript_result_storage().unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(encoded["transcript_result"]["media_type"], "text/vtt");
        assert_eq!(
            encoded["transcript_result"]["transcript_start_event_id"],
            "ck:event:019a7360-0000-7000-8000-000000000003"
        );
    }

    #[test]
    fn call_state_removed_participants_round_trips() {
        let value = json!({
            "call_id": "ck:call:019a7360-0000-7000-8000-000000000001",
            "state": "active",
            "removed_participants": [{
                "actor_id": "did:web:bob.example",
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
            "did:web:bob.example"
        );
    }

    #[test]
    fn call_state_participant_mute_overrides_round_trips() {
        let value = json!({
            "call_id": "ck:call:019a7360-0000-7000-8000-000000000001",
            "state": "active",
            "participant_mute_overrides": [{
                "actor_id": "did:web:bob.example",
                "device_id": "ck:device:019a7360-0000-7000-8000-000000000002",
                "audio_muted": true,
                "video_muted": false,
                "muted_by": "did:web:mod.example",
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
            "ck:device:019a7360-0000-7000-8000-000000000002"
        );
    }

    #[test]
    fn call_state_transcript_result_rejects_direct_backend_refs() {
        let value = json!({
            "call_id": "ck:call:019a7360-0000-7000-8000-000000000001",
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
            "call_id": "ck:call:019a7360-0000-7000-8000-000000000001",
            "state": "active",
            "transcript_state": "transcribing"
        });
        let payload: CallStatePayload = serde_json::from_value(value).unwrap();

        assert_eq!(
            payload.validate_transcript_result_storage(),
            Err(REASON_RECORDING_CONSENT_REQUIRED)
        );
    }
}
