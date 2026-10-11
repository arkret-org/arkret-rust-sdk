//! Decrypted `ak.message.stream` Signal payloads.
//!
//! These frames are transient previews carried only inside an encrypted
//! `SignalEnvelope` with `signal_class=session`. They are not durable Events or
//! Content Blocks.

use std::collections::VecDeque;

use arkret_wire::signal::MAX_SIGNAL_PLAINTEXT_BYTES;
use arkret_wire::{EventId, MessageId, MessageStreamId, Result, StrandId, WireError, canonical};
use serde::{Deserialize, Serialize};

pub const MESSAGE_STREAM_KIND: &str = "ak.message.stream";
pub const MAX_MESSAGE_STREAM_PREVIEW_BYTES: usize = 16 * 1024;
pub const MAX_MESSAGE_STREAM_FRAMES_PER_SECOND: u32 = 5;
pub const MAX_MESSAGE_STREAMS_PER_DEVICE: usize = 8;
pub const MAX_MESSAGE_STREAM_LIFETIME_SECONDS: u64 = 10 * 60;
pub const MESSAGE_STREAM_STALLED_AFTER_SECONDS: u64 = 30;
pub const MESSAGE_STREAM_KEYFRAME_INTERVAL_SECONDS: u64 = 15;
const MILLIS_PER_SECOND: u64 = 1_000;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStreamPayloadKind {
    #[serde(rename = "ak.message.stream")]
    MessageStream,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStreamTrackName {
    Discussion,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStreamFormat {
    Plain,
    Markdown,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStreamAbortReason {
    GenerationCancelled,
    GenerationFailed,
    Superseded,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStreamKeyframeKind {
    Keyframe,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStreamDeltaKind {
    Delta,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStreamAbortKind {
    Abort,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageStreamKeyframe {
    pub kind: MessageStreamPayloadKind,
    pub payload_sequence: u64,
    pub strand_id: StrandId,
    pub track_name: MessageStreamTrackName,
    pub message_id: MessageId,
    pub attempt: u32,
    pub stream_id: MessageStreamId,
    pub seq: u64,
    pub frame_kind: MessageStreamKeyframeKind,
    pub format: MessageStreamFormat,
    pub text: String,
    pub truncated: bool,
}

impl MessageStreamKeyframe {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        payload_sequence: u64,
        strand_id: StrandId,
        message_id: MessageId,
        attempt: u32,
        stream_id: MessageStreamId,
        seq: u64,
        format: MessageStreamFormat,
        text: impl Into<String>,
        truncated: bool,
    ) -> Result<Self> {
        let frame = Self {
            kind: MessageStreamPayloadKind::MessageStream,
            payload_sequence,
            strand_id,
            track_name: MessageStreamTrackName::Discussion,
            message_id,
            attempt,
            stream_id,
            seq,
            frame_kind: MessageStreamKeyframeKind::Keyframe,
            format,
            text: text.into(),
            truncated,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<()> {
        validate_preview_text(&self.text, true)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageStreamDelta {
    pub kind: MessageStreamPayloadKind,
    pub payload_sequence: u64,
    pub strand_id: StrandId,
    pub track_name: MessageStreamTrackName,
    pub message_id: MessageId,
    pub attempt: u32,
    pub stream_id: MessageStreamId,
    pub seq: u64,
    pub frame_kind: MessageStreamDeltaKind,
    pub base_seq: u64,
    pub text_append: String,
}

impl MessageStreamDelta {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        payload_sequence: u64,
        strand_id: StrandId,
        message_id: MessageId,
        attempt: u32,
        stream_id: MessageStreamId,
        seq: u64,
        base_seq: u64,
        text_append: impl Into<String>,
    ) -> Result<Self> {
        let frame = Self {
            kind: MessageStreamPayloadKind::MessageStream,
            payload_sequence,
            strand_id,
            track_name: MessageStreamTrackName::Discussion,
            message_id,
            attempt,
            stream_id,
            seq,
            frame_kind: MessageStreamDeltaKind::Delta,
            base_seq,
            text_append: text_append.into(),
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<()> {
        if self.seq == 0 {
            return Err(WireError::Protocol(
                "message stream delta seq must be greater than zero".to_owned(),
            ));
        }
        validate_preview_text(&self.text_append, false)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageStreamAbort {
    pub kind: MessageStreamPayloadKind,
    pub payload_sequence: u64,
    pub strand_id: StrandId,
    pub track_name: MessageStreamTrackName,
    pub message_id: MessageId,
    pub attempt: u32,
    pub stream_id: MessageStreamId,
    pub seq: u64,
    pub frame_kind: MessageStreamAbortKind,
    pub reason_code: MessageStreamAbortReason,
}

impl MessageStreamAbort {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        payload_sequence: u64,
        strand_id: StrandId,
        message_id: MessageId,
        attempt: u32,
        stream_id: MessageStreamId,
        seq: u64,
        reason_code: MessageStreamAbortReason,
    ) -> Result<Self> {
        let frame = Self {
            kind: MessageStreamPayloadKind::MessageStream,
            payload_sequence,
            strand_id,
            track_name: MessageStreamTrackName::Discussion,
            message_id,
            attempt,
            stream_id,
            seq,
            frame_kind: MessageStreamAbortKind::Abort,
            reason_code,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<()> {
        if self.seq == 0 {
            return Err(WireError::Protocol(
                "message stream abort seq must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageStreamFrame {
    Keyframe(MessageStreamKeyframe),
    Delta(MessageStreamDelta),
    Abort(MessageStreamAbort),
}

impl MessageStreamFrame {
    pub fn from_plaintext(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
            return Err(WireError::Protocol(
                "message stream Signal plaintext exceeds 48 KiB".to_owned(),
            ));
        }
        let frame: Self = canonical::from_canonical_json_slice(bytes)?;
        frame.validate()?;
        Ok(frame)
    }

    pub fn canonical_plaintext(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = canonical::canonical_json_bytes(self)?;
        if bytes.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
            return Err(WireError::Protocol(
                "message stream Signal plaintext exceeds 48 KiB".to_owned(),
            ));
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Keyframe(frame) => frame.validate(),
            Self::Delta(frame) => frame.validate(),
            Self::Abort(frame) => frame.validate(),
        }
    }

    pub fn payload_sequence(&self) -> u64 {
        match self {
            Self::Keyframe(frame) => frame.payload_sequence,
            Self::Delta(frame) => frame.payload_sequence,
            Self::Abort(frame) => frame.payload_sequence,
        }
    }

    pub fn strand_id(&self) -> &StrandId {
        match self {
            Self::Keyframe(frame) => &frame.strand_id,
            Self::Delta(frame) => &frame.strand_id,
            Self::Abort(frame) => &frame.strand_id,
        }
    }

    pub fn message_id(&self) -> &MessageId {
        match self {
            Self::Keyframe(frame) => &frame.message_id,
            Self::Delta(frame) => &frame.message_id,
            Self::Abort(frame) => &frame.message_id,
        }
    }

    pub fn attempt(&self) -> u32 {
        match self {
            Self::Keyframe(frame) => frame.attempt,
            Self::Delta(frame) => frame.attempt,
            Self::Abort(frame) => frame.attempt,
        }
    }

    pub fn stream_id(&self) -> &MessageStreamId {
        match self {
            Self::Keyframe(frame) => &frame.stream_id,
            Self::Delta(frame) => &frame.stream_id,
            Self::Abort(frame) => &frame.stream_id,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            Self::Keyframe(frame) => frame.seq,
            Self::Delta(frame) => frame.seq,
            Self::Abort(frame) => frame.seq,
        }
    }
}

/// Producer-side state for one transient generation preview.
///
/// The durable message identity is fixed before the first frame: `message_id`
/// is the final 33-byte `EventId` token retyped as a `MessageId`.
#[derive(Clone, Debug)]
pub struct MessageStreamProducer {
    event_id: EventId,
    message_id: MessageId,
    strand_id: StrandId,
    attempt: u32,
    stream_id: MessageStreamId,
    format: MessageStreamFormat,
    preview: String,
    emitted_bytes: usize,
    seq: u64,
    started_at_ms: u64,
    last_keyframe_at_ms: u64,
    last_keyframe_bytes: usize,
    emitted_at_ms: VecDeque<u64>,
    truncated: bool,
    finished: bool,
}

impl MessageStreamProducer {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        payload_sequence: u64,
        event_id: EventId,
        strand_id: StrandId,
        attempt: u32,
        stream_id: MessageStreamId,
        format: MessageStreamFormat,
        now_ms: u64,
    ) -> Result<(Self, MessageStreamFrame)> {
        let message_id = MessageId::from_event_id(&event_id);
        let frame = MessageStreamFrame::Keyframe(MessageStreamKeyframe::new(
            payload_sequence,
            strand_id.clone(),
            message_id.clone(),
            attempt,
            stream_id.clone(),
            0,
            format,
            "",
            false,
        )?);
        let mut emitted_at_ms = VecDeque::new();
        emitted_at_ms.push_back(now_ms);
        Ok((
            Self {
                event_id,
                message_id,
                strand_id,
                attempt,
                stream_id,
                format,
                preview: String::new(),
                emitted_bytes: 0,
                seq: 0,
                started_at_ms: now_ms,
                last_keyframe_at_ms: now_ms,
                last_keyframe_bytes: 0,
                emitted_at_ms,
                truncated: false,
                finished: false,
            },
            frame,
        ))
    }

    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    pub fn stream_id(&self) -> &MessageStreamId {
        &self.stream_id
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn preview(&self) -> &str {
        &self.preview
    }

    /// Appends newly generated text and emits a frame when rate limits allow.
    ///
    /// Text received while throttled is retained and is emitted by the next
    /// call to `append` or `tick`.
    pub fn append(
        &mut self,
        payload_sequence: u64,
        text_append: &str,
        now_ms: u64,
    ) -> Result<Option<MessageStreamFrame>> {
        self.ensure_active(now_ms)?;
        validate_text_controls(text_append)?;
        let was_truncated = self.truncated;
        let remaining = MAX_MESSAGE_STREAM_PREVIEW_BYTES.saturating_sub(self.preview.len());
        append_utf8_prefix(
            &mut self.preview,
            text_append,
            MAX_MESSAGE_STREAM_PREVIEW_BYTES,
        );
        self.truncated |= text_append.len() > remaining;
        self.emit_pending(payload_sequence, now_ms, !was_truncated && self.truncated)
    }

    /// Emits accumulated text or a periodic self-contained keyframe.
    pub fn tick(
        &mut self,
        payload_sequence: u64,
        now_ms: u64,
    ) -> Result<Option<MessageStreamFrame>> {
        self.ensure_active(now_ms)?;
        self.emit_pending(payload_sequence, now_ms, false)
    }

    pub fn abort(
        &mut self,
        payload_sequence: u64,
        reason: MessageStreamAbortReason,
        now_ms: u64,
    ) -> Result<Option<MessageStreamFrame>> {
        self.ensure_active(now_ms)?;
        if !self.reserve_frame(now_ms) {
            return Ok(None);
        }
        self.seq = self.seq.saturating_add(1);
        self.finished = true;
        Ok(Some(MessageStreamFrame::Abort(MessageStreamAbort::new(
            payload_sequence,
            self.strand_id.clone(),
            self.message_id.clone(),
            self.attempt,
            self.stream_id.clone(),
            self.seq,
            reason,
        )?)))
    }

    /// Marks the preview complete after the matching durable Event is queued.
    pub fn finish(&mut self) {
        self.finished = true;
    }

    fn emit_pending(
        &mut self,
        payload_sequence: u64,
        now_ms: u64,
        reached_cap: bool,
    ) -> Result<Option<MessageStreamFrame>> {
        let keyframe_due = reached_cap
            || self.preview.len() >= self.last_keyframe_bytes.saturating_mul(2).max(1)
            || now_ms.saturating_sub(self.last_keyframe_at_ms)
                >= MESSAGE_STREAM_KEYFRAME_INTERVAL_SECONDS * MILLIS_PER_SECOND;
        let has_pending = self.preview.len() > self.emitted_bytes;
        if !has_pending && !keyframe_due {
            return Ok(None);
        }
        if self.truncated && !keyframe_due {
            return Ok(None);
        }
        if !self.reserve_frame(now_ms) {
            return Ok(None);
        }

        self.seq = self.seq.saturating_add(1);
        if keyframe_due {
            self.emitted_bytes = self.preview.len();
            self.last_keyframe_bytes = self.preview.len();
            self.last_keyframe_at_ms = now_ms;
            return Ok(Some(MessageStreamFrame::Keyframe(
                MessageStreamKeyframe::new(
                    payload_sequence,
                    self.strand_id.clone(),
                    self.message_id.clone(),
                    self.attempt,
                    self.stream_id.clone(),
                    self.seq,
                    self.format,
                    self.preview.clone(),
                    self.truncated,
                )?,
            )));
        }

        let base_seq = self.seq.saturating_sub(1);
        let text_append = self.preview[self.emitted_bytes..].to_owned();
        self.emitted_bytes = self.preview.len();
        Ok(Some(MessageStreamFrame::Delta(MessageStreamDelta::new(
            payload_sequence,
            self.strand_id.clone(),
            self.message_id.clone(),
            self.attempt,
            self.stream_id.clone(),
            self.seq,
            base_seq,
            text_append,
        )?)))
    }

    fn ensure_active(&mut self, now_ms: u64) -> Result<()> {
        if self.finished {
            return Err(WireError::Protocol(
                "message stream producer is already finished".to_owned(),
            ));
        }
        if now_ms.saturating_sub(self.started_at_ms)
            >= MAX_MESSAGE_STREAM_LIFETIME_SECONDS * MILLIS_PER_SECOND
        {
            self.finished = true;
            return Err(WireError::Protocol(
                "message stream producer exceeded its 10 minute lifetime".to_owned(),
            ));
        }
        Ok(())
    }

    fn reserve_frame(&mut self, now_ms: u64) -> bool {
        if let Some(window_start) = now_ms.checked_sub(MILLIS_PER_SECOND) {
            while self
                .emitted_at_ms
                .front()
                .is_some_and(|emitted_at| *emitted_at <= window_start)
            {
                self.emitted_at_ms.pop_front();
            }
        }
        if self.emitted_at_ms.len() >= MAX_MESSAGE_STREAM_FRAMES_PER_SECOND as usize {
            return false;
        }
        self.emitted_at_ms.push_back(now_ms);
        true
    }
}

fn append_utf8_prefix(target: &mut String, append: &str, max_bytes: usize) {
    let remaining = max_bytes.saturating_sub(target.len());
    if append.len() <= remaining {
        target.push_str(append);
        return;
    }
    let mut end = remaining;
    while end > 0 && !append.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&append[..end]);
}

fn validate_preview_text(text: &str, empty_allowed: bool) -> Result<()> {
    if !empty_allowed && text.is_empty() {
        return Err(WireError::Protocol(
            "message stream delta text_append must not be empty".to_owned(),
        ));
    }
    if text.len() > MAX_MESSAGE_STREAM_PREVIEW_BYTES {
        return Err(WireError::Protocol(
            "message stream preview exceeds 16 KiB UTF-8".to_owned(),
        ));
    }
    validate_text_controls(text)
}

fn validate_text_controls(text: &str) -> Result<()> {
    if text.chars().any(|character| {
        (character <= '\u{001f}' && !matches!(character, '\n' | '\r' | '\t'))
            || character == '\u{007f}'
    }) {
        return Err(WireError::Protocol(
            "message stream preview contains a forbidden control character".to_owned(),
        ));
    }
    Ok(())
}
