//! Call-state and call-participant payloads.

use arkret_wire::{ActorId, CurrentRevision, DidCoreId, ExporterLabelId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::internal_prelude::*;

impl ParticipantBinding {
    /// AKP-0010 — schema id for the participant_binding signing envelope.
    pub const SCHEMA: &'static str = "ak.media.participant_binding.v1";
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallParticipantMedia {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub audio: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub video: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub screen: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "CallParticipantWire")]
pub struct CallParticipant {
    pub actor_id: ActorId,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub joined_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foci_preferred: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_binding: Option<ParticipantBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<CallParticipantMedia>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focus_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallParticipantWire {
    actor_id: ActorId,
    device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    joined_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    foci_preferred: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    participant_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    participant_binding: Option<ParticipantBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    media: Option<CallParticipantMedia>,
    #[serde(
        default,
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    focus_id: Option<String>,
}

impl TryFrom<CallParticipantWire> for CallParticipant {
    type Error = &'static str;

    fn try_from(value: CallParticipantWire) -> std::result::Result<Self, Self::Error> {
        let participant = Self {
            actor_id: value.actor_id,
            device_id: value.device_id,
            joined_at: value.joined_at,
            foci_preferred: value.foci_preferred,
            participant_id: value.participant_id,
            participant_binding: value.participant_binding,
            media: value.media,
            focus_id: value.focus_id,
        };
        participant.validate_binding_carrier()?;
        Ok(participant)
    }
}

impl CallParticipant {
    pub fn validate_binding_carrier(&self) -> std::result::Result<(), &'static str> {
        if self.participant_binding.is_some() {
            self.signed_media()
                .map_err(|_| "participant binding requires the complete issued media range")?;
        }

        if self
            .joined_at
            .is_some_and(|at| at.timestamp_millis().rem_euclid(300_000) != 0)
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        let present = [
            self.participant_id.is_some(),
            self.participant_binding.is_some(),
            self.focus_id.is_some(),
        ];
        if present.iter().any(|present| *present) && !present.iter().all(|present| *present) {
            return Err(
                "SFU roster entry requires participant_id, participant_binding and focus_id together",
            );
        }
        Ok(())
    }
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
    pub actor_id: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub action: CallParticipantRemovalAction,
    pub removed_by: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub removed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
// Tagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum CallRosterDelta {
    Join {
        participant: CallParticipant,
    },
    Leave {
        actor_id: ActorId,
        device_id: String,
        /// Typed revision of the roster value the producer read. The compare is
        /// field-for-field, not a bare Commit ID and not a counter.
        expected_revision: CurrentRevision,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallModerationDelta {
    RemoveParticipant {
        removal: CallParticipantRemoval,
    },
    RestoreParticipant {
        actor_id: ActorId,
        restored_by: DidCoreId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        restored_at: DateTime<Utc>,
        /// Typed revision of the complete Call moderation axis the producer
        /// read. The compare is field-for-field.
        expected_revision: CurrentRevision,
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
    pub actor_id: ActorId,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_muted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video_muted: Option<bool>,
    pub changed_by: DidCoreId,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisibleCaptureNotice;

impl Serialize for VisibleCaptureNotice {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for VisibleCaptureNotice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("visible_notice must be true"))
        }
    }
}

/// Typed payload for `ak.call.recording.start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingStartPayload {
    pub call_id: CallId,
    pub recording_id: CallRecordingId,
    pub recording_agent_id: DidCoreId,
    pub capture_kind: RecordingCaptureKind,
    pub mode: RecordingMode,
    pub visible_notice: VisibleCaptureNotice,
    pub result: RecordingStartOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingStartOutcome {
    pub retention: CallRecordingRetention,
}

impl<'de> Deserialize<'de> for RecordingStartOutcome {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            retention: CallRecordingRetention,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.retention.consent_confirmed != Some(true) {
            return Err(serde::de::Error::custom(
                "recording start retention.consent_confirmed must be true",
            ));
        }
        Ok(Self {
            retention: wire.retention,
        })
    }
}

impl CallRecordingStartPayload {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.result.retention.consent_confirmed != Some(true) {
            return Err(ReasonCode::RECORDING_CONSENT_REQUIRED);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRecordingEncryptionAlgorithm {
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
    pub media_service_id: DidCoreId,
    pub recording_start_event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecordingEncryption {
    pub encryption_algorithm: CallRecordingEncryptionAlgorithm,
    pub exporter_label: String,
    pub context: CallRecordingEncryptionContext,
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
    pub requested_by: Option<DidCoreId>,
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

impl CallRecordingArtifact {
    pub const SCHEMA: &'static str = SchemaId::CALL_RECORDING_ARTIFACT_V1;
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::CALL_RECORDING_ARTIFACT_V1 {
            return schema_violation(format!(
                "call recording artifact schema must be {schemaid_call_recording_artifact_v1}",
                schemaid_call_recording_artifact_v1 = SchemaId::CALL_RECORDING_ARTIFACT_V1
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
        if self.encryption.exporter_label != ExporterLabelId::RTC_RECORDING_KEY_V1 {
            return recording_artifact_pipeline_bypassed(format!(
                "recording artifact exporter_label must be {exporterlabelid_rtc_recording_key_v1}",
                exporterlabelid_rtc_recording_key_v1 = ExporterLabelId::RTC_RECORDING_KEY_V1
            ));
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
        if self.encryption.context.media_service_id.as_core_id() != self.produced_by.as_core_id() {
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
        if self.content_digest.as_ref().is_some_and(|digest| {
            artifact.blob_ref.as_str().strip_prefix("ak:blob:") != Some(digest.as_str())
        }) {
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

/// Genesis payload for `ak.call.create`. The CallId is derived from the
/// accepted EventId and therefore is deliberately absent here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCreatePayload {
    pub initial_state: CallLifecycleState,
}

impl CallCreatePayload {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if matches!(
            self.initial_state,
            CallLifecycleState::Scheduled
                | CallLifecycleState::Ringing
                | CallLifecycleState::Connecting
        ) {
            Ok(())
        } else {
            Err(ReasonCode::CALL_STATE_TRANSITION_INVALID)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStateTransition {
    pub from: CallLifecycleState,
    pub to: CallLifecycleState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub failure_reason_code: Option<CallCaptureFailureReasonCode>,
}

/// The lifecycle current includes the accepted creation's null predecessor;
/// subsequent Event deltas still require a non-null `from` state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallStateCurrentValue {
    #[serde(deserialize_with = "deserialize_call_current_from")]
    pub from: Option<CallLifecycleState>,
    pub to: CallLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<CallCaptureFailureReasonCode>,
}

fn deserialize_call_current_from<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<CallLifecycleState>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CallLifecycleState>::deserialize(deserializer)
}

impl CallStateCurrentValue {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.from.is_none() {
            CallCreatePayload {
                initial_state: self.to,
            }
            .validate()?;
        }
        if (self.to == CallLifecycleState::Failed) != self.failure_reason_code.is_some() {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        Ok(())
    }
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

impl CallStatePayload {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        // v1 has no per-leg current selector or CAS carrier for moderator mute.
        if self.state_transition.as_ref().is_some_and(|t| {
            (t.to == CallLifecycleState::Failed) != t.failure_reason_code.is_some()
        }) {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self.mute_override.is_some() {
            return Err(ErrorCode::SCHEMA_VIOLATION);
        }
        if self.state_transition.is_none()
            && self.focus.is_none()
            && self.recording_transition.is_none()
            && self.transcript_transition.is_none()
            && self.roster_delta.is_none()
            && self.moderation_delta.is_none()
        {
            return Err(ErrorCode::SCHEMA_VIOLATION);
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
        if let Some(CallRosterDelta::Join { participant }) = &self.roster_delta {
            participant.validate_binding_carrier()?;
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
        return Err(WireError::Protocol(
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
        return Err(WireError::Protocol(
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
    Err(WireError::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

fn recording_artifact_pipeline_bypassed(message: impl Into<String>) -> Result<()> {
    Err(WireError::Protocol(format!(
        "recording_artifact_pipeline_bypassed: {}",
        message.into()
    )))
}

#[cfg(test)]
mod call_current_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn call_current_creation_has_a_required_null_predecessor_only_for_initial_states() {
        for state in ["scheduled", "ringing", "connecting"] {
            let wire = json!({"from":null,"to":state});
            let current: CallStateCurrentValue = serde_json::from_value(wire.clone()).unwrap();
            current.validate().unwrap();
            assert_eq!(serde_json::to_value(current).unwrap(), wire);
        }
        for state in ["active", "ended", "missed", "failed", "cancelled"] {
            let current: CallStateCurrentValue =
                serde_json::from_value(json!({"from":null,"to":state})).unwrap();
            assert_eq!(
                current.validate(),
                Err(ReasonCode::CALL_STATE_TRANSITION_INVALID)
            );
            assert_eq!(
                CallCreatePayload {
                    initial_state: current.to
                }
                .validate(),
                Err(ReasonCode::CALL_STATE_TRANSITION_INVALID)
            );
        }
        assert!(serde_json::from_value::<CallStateCurrentValue>(json!({"to":"ringing"})).is_err());
        assert!(
            serde_json::from_value::<CallStateTransition>(json!({"from":null,"to":"ringing"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<CallStateCurrentValue>(
                json!({"from":null,"to":"ringing","call_id":"extra"})
            )
            .is_err()
        );
    }
}

include!("generated/call_contracts.rs");

/// Validate exact effective-entry provenance against the axis last source.
fn validate_call_sources<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a RealmCommit)>,
    last: (&str, &RealmCommit),
    stream: &CommitStreamRef,
    revision: &CurrentRevision,
    write_index: usize,
) -> Result<()> {
    let validate = |tag: &str, commit: &RealmCommit| -> Result<()> {
        commit.validate_shape()?;
        commit.validate_content_address()?;
        if commit.stream_ref != *stream
            || commit.realm_id != *stream.realm_id()
            || tag != format!("{}:{}", commit.event_ref, write_index)
            || commit.stream_position > revision.stream_position
        {
            return schema_violation("Call source provenance differs from its exact axis");
        }
        Ok(())
    };
    validate(last.0, last.1)?;
    if last.1.commit_id != revision.commit_id || last.1.stream_position != revision.stream_position
    {
        return schema_violation("Call axis revision must equal its last source Commit");
    }
    let mut previous: Option<&str> = None;
    let mut positions = std::collections::BTreeSet::new();
    for (tag, commit) in entries {
        validate(tag, commit)?;
        if previous.is_some_and(|old| old >= tag)
            || !positions.insert(commit.stream_position)
            || (commit.stream_position == revision.stream_position
                && (tag != last.0
                    || serde_json::to_value(commit)? != serde_json::to_value(last.1)?))
        {
            return schema_violation("Call effective entries have conflicting provenance or order");
        }
        previous = Some(tag);
    }
    Ok(())
}

impl CallRosterCurrentValue {
    pub fn validate_sources(
        &self,
        stream: &CommitStreamRef,
        revision: &CurrentRevision,
    ) -> Result<()> {
        validate_call_sources(
            self.entries
                .iter()
                .map(|a| (a.tag_id.as_str(), &a.source_commit)),
            (&self.last_source.tag_id, &self.last_source.source_commit),
            stream,
            revision,
            CALL_ROSTER_WRITE_INDEX,
        )?;
        self.validate_effective_entries()
    }
}
impl CallModerationCurrentValue {
    pub fn validate_sources(
        &self,
        stream: &CommitStreamRef,
        revision: &CurrentRevision,
    ) -> Result<()> {
        validate_call_sources(
            self.entries
                .iter()
                .map(|a| (a.tag_id.as_str(), &a.source_commit)),
            (&self.last_source.tag_id, &self.last_source.source_commit),
            stream,
            revision,
            CALL_MODERATION_WRITE_INDEX,
        )?;
        self.validate_effective_entries()
    }
}

impl CallParticipant {
    pub fn signed_media(&self) -> Result<crate::call_invitation::CallInvitationMedia> {
        let media = self.media.as_ref().ok_or_else(|| {
            WireError::Protocol("signed participant requires media range".to_owned())
        })?;
        match (media.audio, media.video, media.screen) {
            (Some(audio), Some(video), Some(screen)) => {
                Ok(crate::call_invitation::CallInvitationMedia {
                    audio,
                    video,
                    screen,
                })
            }
            _ => schema_violation("signed participant media requires all three non-null flags"),
        }
    }
}

/// Validate and collect the sparse original Commits of complete Call axes.
/// They are signature inputs, never a contiguous replay window or a head.
pub fn call_current_source_commits(rows: &[TypedCurrentRow]) -> Result<Vec<RealmCommit>> {
    let mut commits = BTreeMap::new();
    for row in rows {
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row;
        let sources = match selector {
            CurrentSelector::CallRoster { .. } => {
                let roster: CallRosterCurrentValue = serde_json::from_value(value.clone())?;
                roster.validate_for_axis(source_stream_ref, revision)?;
                roster
                    .entries
                    .into_iter()
                    .map(|entry| entry.source_commit)
                    .chain(std::iter::once(roster.last_source.source_commit))
                    .collect::<Vec<_>>()
            }
            CurrentSelector::CallModeration { .. } => {
                let moderation: CallModerationCurrentValue = serde_json::from_value(value.clone())?;
                moderation.validate_for_axis(source_stream_ref, revision)?;
                moderation
                    .entries
                    .into_iter()
                    .map(|entry| entry.source_commit)
                    .chain(std::iter::once(moderation.last_source.source_commit))
                    .collect::<Vec<_>>()
            }
            _ => continue,
        };
        for commit in sources {
            let key = (commit.stream_ref.clone(), commit.stream_position);
            if let Some(old) = commits.insert(key, commit.clone())
                && old != commit
            {
                return schema_violation("Call axes disagree on one original Commit");
            }
        }
    }
    Ok(commits.into_values().collect())
}
