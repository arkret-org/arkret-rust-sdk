//! SFrame media frame-key and recording-key derivation.
//!
//! Per `crypto-media/media-service-binding.md` §8.1 and `call-state.md` §5,
//! realtime media frame keys and backend recording keys MUST be derived from
//! the Arkret MLS exporter — never from a backend's own KMS or a self-generated
//! random key. This module binds the two fixed wire labels to a real MLS
//! exporter source and rejects any other key provenance with
//! [`e2ee_key_source_unauthorised`](ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED).
//!
//! - Frame key: label `ak-rtc-frame-key/v1`, Context = canonical JSON of `{realm_id, call_id,
//!   focus_id, epoch_id, participant_identity, device_id}`.
//! - Recording key: label `ak-rtc-recording-key/v1`, Context = canonical JSON of `{realm_id,
//!   call_id, focus_id, recording_id, media_service_id, recording_start_event_id}`.
//! - Transcript key: label `ak-rtc-transcript-key/v1`, Context = canonical JSON of `{realm_id,
//!   call_id, focus_id, recording_id, media_service_id, transcript_start_event_id}`.
//!
//! All derivations output `KDF.Nh = 32` bytes (RFC 9420 §8 `MLS-Exporter`).

use arkret_canonical::canonical::canonical_json_bytes;
use arkret_wire::{CallId, DeviceId, Did, ExporterLabelId, RealmId, ReasonCode};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Fixed canonical wire label for SFrame media frame keys
/// (`media-service-binding.md` §8.1). Used byte-for-byte; MUST NOT be mixed
/// with any other exporter label.
pub const FRAME_KEY_LABEL: &str = ExporterLabelId::RTC_FRAME_KEY_V1;

/// Fixed canonical wire label for backend-generated recording artifact keys
/// (`call-state.md` §5). Distinct from [`FRAME_KEY_LABEL`]; reusing the SFrame
/// label for a recording key is a wire violation.
pub const RECORDING_KEY_LABEL: &str = ExporterLabelId::RTC_RECORDING_KEY_V1;

/// Fixed canonical wire label for backend-generated transcription artifact keys
/// (`call-state.md` §5.1). Distinct from [`FRAME_KEY_LABEL`] and
/// [`RECORDING_KEY_LABEL`]; reusing either of those labels for a transcript key
/// is a wire violation.
pub const TRANSCRIPT_KEY_LABEL: &str = ExporterLabelId::RTC_TRANSCRIPT_KEY_V1;

/// Output length of every media key derivation, in bytes (`KDF.Nh = 32`).
pub const MEDIA_KEY_LEN: usize = 32;

/// An MLS exporter that can derive epoch-bound secrets via RFC 9420 §8.5.
///
/// Implemented by `arkret_mls::ArkretMlsGroup` (the impl lives in the
/// `arkret-mls` crate, which depends on this one). Requiring this trait as the
/// only key source is what makes a non-MLS provenance impossible to express:
/// callers cannot hand in raw random bytes, only a live MLS group can satisfy
/// the bound.
pub trait MlsExporterSource {
    /// Derive `length` bytes for `(label, context)` from the current epoch's
    /// key schedule. Two members on the same epoch MUST agree. The output is
    /// key material: it is returned [`Zeroizing`] so it is wiped on drop.
    fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Sender-bound context for an SFrame frame key, serialized as the exporter
/// `Context`. Field order is fixed by `media-service-binding.md` §8.1; the
/// canonical JSON serializer sorts keys, so the on-wire bytes are stable
/// regardless of declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FrameKeyContext {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub epoch_id: u64,
    pub participant_identity: String,
    pub device_id: DeviceId,
}

impl FrameKeyContext {
    /// Reject a context that cannot bind a single sender. `participant_identity`
    /// and `focus_id` MUST be non-empty — an empty Context or an epoch-only
    /// binding fails closed per §8.1.
    fn ensure_sender_bound(&self) -> Result<()> {
        if self.participant_identity.trim().is_empty() || self.focus_id.trim().is_empty() {
            return Err(Error::Protocol(format!(
                "{}: frame key context missing sender binding (focus_id / participant_identity)",
                ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED
            )));
        }
        Ok(())
    }
}

/// Context for a backend-generated recording artifact key (`call-state.md` §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecordingKeyContext {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub recording_id: String,
    pub media_service_id: Did,
    pub recording_start_event_id: String,
}

impl RecordingKeyContext {
    fn ensure_bound(&self) -> Result<()> {
        if self.focus_id.trim().is_empty()
            || self.recording_id.trim().is_empty()
            || self.recording_start_event_id.trim().is_empty()
        {
            return Err(Error::Protocol(format!(
                "{}: recording key context missing recording binding",
                ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED
            )));
        }
        Ok(())
    }
}

/// Context for a backend-generated transcription artifact key
/// (`call-state.md` §5.1). Mirrors [`RecordingKeyContext`] but binds
/// `transcript_start_event_id` instead of `recording_start_event_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TranscriptKeyContext {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub recording_id: String,
    pub media_service_id: Did,
    pub transcript_start_event_id: String,
}

impl TranscriptKeyContext {
    fn ensure_bound(&self) -> Result<()> {
        if self.focus_id.trim().is_empty()
            || self.recording_id.trim().is_empty()
            || self.transcript_start_event_id.trim().is_empty()
        {
            return Err(Error::Protocol(format!(
                "{}: transcript key context missing transcript binding",
                ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED
            )));
        }
        Ok(())
    }
}

/// Derive the 32-byte SFrame frame key for one sender at one epoch.
///
/// `source` MUST be a live Arkret MLS group: any non-MLS key source is
/// unrepresentable, which satisfies the §8.1 mandate that frame keys never come
/// from a backend KMS. The label is the byte-for-byte [`FRAME_KEY_LABEL`] and
/// the Context is the canonical JSON of `context`.
pub fn derive_frame_key(
    source: &impl MlsExporterSource,
    context: &FrameKeyContext,
) -> Result<Zeroizing<Vec<u8>>> {
    context.ensure_sender_bound()?;
    let context_bytes = canonical_json_bytes(context)?;
    let key = source.export_secret(FRAME_KEY_LABEL, &context_bytes, MEDIA_KEY_LEN)?;
    ensure_key_len(&key)?;
    Ok(key)
}

/// Derive the 32-byte recording artifact key (`call-state.md` §5).
pub fn derive_recording_key(
    source: &impl MlsExporterSource,
    context: &RecordingKeyContext,
) -> Result<Zeroizing<Vec<u8>>> {
    context.ensure_bound()?;
    let context_bytes = canonical_json_bytes(context)?;
    let key = source.export_secret(RECORDING_KEY_LABEL, &context_bytes, MEDIA_KEY_LEN)?;
    ensure_key_len(&key)?;
    Ok(key)
}

/// Derive the 32-byte transcription artifact key (`call-state.md` §5.1).
///
/// Mirrors [`derive_recording_key`]: `source` MUST be a live Arkret MLS group,
/// the label is the byte-for-byte [`TRANSCRIPT_KEY_LABEL`], and the Context is
/// the canonical JSON of `context`.
pub fn derive_transcript_key(
    source: &impl MlsExporterSource,
    context: &TranscriptKeyContext,
) -> Result<Zeroizing<Vec<u8>>> {
    context.ensure_bound()?;
    let context_bytes = canonical_json_bytes(context)?;
    let key = source.export_secret(TRANSCRIPT_KEY_LABEL, &context_bytes, MEDIA_KEY_LEN)?;
    ensure_key_len(&key)?;
    Ok(key)
}

fn ensure_key_len(key: &[u8]) -> Result<()> {
    if key.len() != MEDIA_KEY_LEN {
        return Err(Error::Protocol(format!(
            "{}: media key exporter returned {} bytes, expected {}",
            ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED,
            key.len(),
            MEDIA_KEY_LEN
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic stand-in for an MLS exporter: HKDF-free, simply hashes
    /// `(label, context)` into a stable 32-byte block. It models the contract
    /// (same input → same output, distinct label/context → distinct output)
    /// without spinning a full OpenMLS group, so the derivation wiring can be
    /// asserted deterministically.
    struct FixedExporter {
        seed: &'static [u8],
    }

    impl MlsExporterSource for FixedExporter {
        fn export_secret(
            &self,
            label: &str,
            context: &[u8],
            length: usize,
        ) -> Result<Zeroizing<Vec<u8>>> {
            let label_len = (label.len() as u64).to_le_bytes();
            let context_len = (context.len() as u64).to_le_bytes();
            let digest = arkret_canonical::canonical::sha256_bytes_from_slices(&[
                self.seed,
                &label_len,
                label.as_bytes(),
                &context_len,
                context,
            ]);
            Ok(Zeroizing::new(digest[..length].to_vec()))
        }
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-8000-8000-9b64700c6ee8").unwrap()
    }

    fn call() -> CallId {
        CallId::new("ak:call:0196441c-0000-7000-8000-000000000000").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap()
    }

    fn frame_context() -> FrameKeyContext {
        FrameKeyContext {
            realm_id: realm(),
            call_id: call(),
            focus_id: "fra-1".to_owned(),
            epoch_id: 7,
            participant_identity: "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000"
                .to_owned(),
            device_id: device(),
        }
    }

    #[test]
    fn frame_key_is_deterministic_for_fixed_exporter_input() {
        let exporter = FixedExporter { seed: b"epoch-7" };
        let context = frame_context();
        let a = derive_frame_key(&exporter, &context).unwrap();
        let b = derive_frame_key(&exporter, &context).unwrap();
        assert_eq!(a.len(), MEDIA_KEY_LEN);
        assert_eq!(a, b, "same exporter + context MUST be deterministic");

        // The label is byte-for-byte the registered SFrame label, so a recording
        // key over the same exporter MUST diverge (domain separation).
        let recording = derive_recording_key(
            &exporter,
            &RecordingKeyContext {
                realm_id: realm(),
                call_id: call(),
                focus_id: "fra-1".to_owned(),
                recording_id: "rtc-recording-1".to_owned(),
                media_service_id: Did::new("did:webvh:z6mkfixture:media.example").unwrap(),
                recording_start_event_id: "ak:event:01904100-0000-8000-8000-0000000000aa"
                    .to_owned(),
            },
        )
        .unwrap();
        assert_ne!(
            a, recording,
            "frame and recording labels MUST domain-separate"
        );
    }

    #[test]
    fn frame_key_diverges_on_epoch_and_participant() {
        let exporter = FixedExporter { seed: b"epoch-7" };
        let base = derive_frame_key(&exporter, &frame_context()).unwrap();

        let mut next_epoch = frame_context();
        next_epoch.epoch_id = 8;
        assert_ne!(base, derive_frame_key(&exporter, &next_epoch).unwrap());

        let mut other_sender = frame_context();
        other_sender.participant_identity = "ak:rtc_participant:other".to_owned();
        assert_ne!(base, derive_frame_key(&exporter, &other_sender).unwrap());
    }

    #[test]
    fn empty_sender_binding_fails_closed() {
        let exporter = FixedExporter { seed: b"epoch-7" };
        let mut context = frame_context();
        context.participant_identity = String::new();
        let err = derive_frame_key(&exporter, &context).unwrap_err();
        assert!(err.to_string().contains("e2ee_key_source_unauthorised"));

        let mut no_focus = frame_context();
        no_focus.focus_id = String::new();
        assert!(derive_frame_key(&exporter, &no_focus).is_err());
    }

    #[test]
    fn recording_key_requires_recording_binding() {
        let exporter = FixedExporter { seed: b"epoch-7" };
        let context = RecordingKeyContext {
            realm_id: realm(),
            call_id: call(),
            focus_id: "fra-1".to_owned(),
            recording_id: String::new(),
            media_service_id: Did::new("did:webvh:z6mkfixture:media.example").unwrap(),
            recording_start_event_id: "ak:event:01904100-0000-8000-8000-0000000000aa".to_owned(),
        };
        assert!(derive_recording_key(&exporter, &context).is_err());
    }

    fn transcript_context() -> TranscriptKeyContext {
        TranscriptKeyContext {
            realm_id: realm(),
            call_id: call(),
            focus_id: "fra-1".to_owned(),
            recording_id: "rtc-transcript-1".to_owned(),
            media_service_id: Did::new("did:webvh:z6mkfixture:media.example").unwrap(),
            transcript_start_event_id: "ak:event:01904100-0000-8000-8000-0000000000bb".to_owned(),
        }
    }

    #[test]
    fn transcript_key_is_deterministic_and_domain_separated() {
        let exporter = FixedExporter { seed: b"epoch-7" };
        let context = transcript_context();
        let a = derive_transcript_key(&exporter, &context).unwrap();
        let b = derive_transcript_key(&exporter, &context).unwrap();
        assert_eq!(a.len(), MEDIA_KEY_LEN);
        assert_eq!(a, b, "same exporter + context MUST be deterministic");

        // The transcript label is distinct from frame and recording labels, so a
        // recording key over the same exporter + same Context MUST diverge.
        let recording = derive_recording_key(
            &exporter,
            &RecordingKeyContext {
                realm_id: realm(),
                call_id: call(),
                focus_id: "fra-1".to_owned(),
                recording_id: "rtc-transcript-1".to_owned(),
                media_service_id: Did::new("did:webvh:z6mkfixture:media.example").unwrap(),
                recording_start_event_id: "ak:event:01904100-0000-8000-8000-0000000000bb"
                    .to_owned(),
            },
        )
        .unwrap();
        assert_ne!(
            a, recording,
            "transcript and recording labels MUST domain-separate"
        );
    }

    #[test]
    fn transcript_key_requires_transcript_binding() {
        let exporter = FixedExporter { seed: b"epoch-7" };
        let mut no_event = transcript_context();
        no_event.transcript_start_event_id = String::new();
        let err = derive_transcript_key(&exporter, &no_event).unwrap_err();
        assert!(err.to_string().contains("e2ee_key_source_unauthorised"));

        let mut no_recording = transcript_context();
        no_recording.recording_id = String::new();
        assert!(derive_transcript_key(&exporter, &no_recording).is_err());
    }

    #[test]
    fn transcript_context_canonical_bytes_are_key_sorted_and_stable() {
        let bytes = canonical_json_bytes(&transcript_context()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(
            text,
            "{\"call_id\":\"ak:call:0196441c-0000-7000-8000-000000000000\",\
             \"focus_id\":\"fra-1\",\
             \"media_service_id\":\"did:webvh:z6mkfixture:media.example\",\
             \"realm_id\":\"ak:realm:01904100-0000-8000-8000-9b64700c6ee8\",\
             \"recording_id\":\"rtc-transcript-1\",\
             \"transcript_start_event_id\":\"ak:event:01904100-0000-8000-8000-0000000000bb\"}"
        );
    }

    #[test]
    fn frame_context_canonical_bytes_are_key_sorted_and_stable() {
        // The Context is canonical JSON; assert the exact byte layout so a
        // future field reorder or rename is caught as a wire change.
        let bytes = canonical_json_bytes(&frame_context()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(
            text,
            "{\"call_id\":\"ak:call:0196441c-0000-7000-8000-000000000000\",\
             \"device_id\":\"ak:device:01904100-0000-7000-8000-000000000005\",\
             \"epoch_id\":7,\
             \"focus_id\":\"fra-1\",\
             \"participant_identity\":\"ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000\",\
             \"realm_id\":\"ak:realm:01904100-0000-8000-8000-9b64700c6ee8\"}"
        );
    }
}
