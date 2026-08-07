//! Decrypted `ak.message.stream` Signal payloads.
//!
//! These frames are transient previews carried only inside an encrypted
//! `SignalEnvelope` with `signal_class=session`. They are not durable Events or
//! Content Blocks.

use std::collections::{BTreeMap, VecDeque};

use arkret_wire::signal::MAX_SIGNAL_PLAINTEXT_BYTES;
use arkret_wire::{Error, EventId, MessageId, MessageStreamId, Result, StrandId, canonical};
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
            return Err(Error::Protocol(
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
            return Err(Error::Protocol(
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
            return Err(Error::Protocol(
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
            return Err(Error::Protocol(
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
/// is the final `EventId` UUID retyped as a `MessageId`.
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
            return Err(Error::Protocol(
                "message stream producer is already finished".to_owned(),
            ));
        }
        if now_ms.saturating_sub(self.started_at_ms)
            >= MAX_MESSAGE_STREAM_LIFETIME_SECONDS * MILLIS_PER_SECOND
        {
            self.finished = true;
            return Err(Error::Protocol(
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

/// Per-device producer registry enforcing the protocol's concurrency ceiling.
#[derive(Clone, Debug, Default)]
pub struct MessageStreamProducerRegistry {
    streams: BTreeMap<String, MessageStreamProducer>,
}

impl MessageStreamProducerRegistry {
    pub fn insert(&mut self, producer: MessageStreamProducer) -> Result<()> {
        self.retain_active();
        let key = producer.stream_id().as_str().to_owned();
        if self.streams.contains_key(&key) {
            return Err(Error::Protocol(
                "message stream_id is already active on this device".to_owned(),
            ));
        }
        if self.streams.len() >= MAX_MESSAGE_STREAMS_PER_DEVICE {
            return Err(Error::Protocol(
                "device already has 8 active message streams".to_owned(),
            ));
        }
        self.streams.insert(key, producer);
        Ok(())
    }

    pub fn get_mut(&mut self, stream_id: &MessageStreamId) -> Option<&mut MessageStreamProducer> {
        self.streams.get_mut(stream_id.as_str())
    }

    pub fn remove(&mut self, stream_id: &MessageStreamId) -> Option<MessageStreamProducer> {
        self.streams.remove(stream_id.as_str())
    }

    pub fn active_len(&mut self) -> usize {
        self.retain_active();
        self.streams.len()
    }

    fn retain_active(&mut self) {
        self.streams.retain(|_, producer| !producer.is_finished());
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
        return Err(Error::Protocol(
            "message stream delta text_append must not be empty".to_owned(),
        ));
    }
    if text.len() > MAX_MESSAGE_STREAM_PREVIEW_BYTES {
        return Err(Error::Protocol(
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
        return Err(Error::Protocol(
            "message stream preview contains a forbidden control character".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strand_id() -> StrandId {
        StrandId::new("ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
    }

    fn message_id() -> MessageId {
        MessageId::new("ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap()
    }

    fn event_id() -> EventId {
        EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap()
    }

    fn stream_id() -> MessageStreamId {
        MessageStreamId::new("ak:message_stream:01904100-0000-7000-8000-000000000003").unwrap()
    }

    #[test]
    fn keyframe_round_trips_as_closed_wire_shape() {
        let frame = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                7,
                strand_id(),
                message_id(),
                0,
                stream_id(),
                0,
                MessageStreamFormat::Markdown,
                "hello",
                false,
            )
            .unwrap(),
        );
        let bytes = frame.canonical_plaintext().unwrap();
        let decoded = MessageStreamFrame::from_plaintext(&bytes).unwrap();

        assert_eq!(decoded, frame);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["frame_kind"],
            "keyframe"
        );
    }

    #[test]
    fn delta_and_abort_reject_seq_zero() {
        assert!(
            MessageStreamDelta::new(8, strand_id(), message_id(), 0, stream_id(), 0, 0, "next",)
                .is_err()
        );
        assert!(
            MessageStreamAbort::new(
                9,
                strand_id(),
                message_id(),
                0,
                stream_id(),
                0,
                MessageStreamAbortReason::GenerationFailed,
            )
            .is_err()
        );
    }

    #[test]
    fn preview_text_enforces_utf8_bytes_and_controls() {
        assert!(validate_preview_text(&"é".repeat(8_192), true).is_ok());
        assert!(validate_preview_text(&"é".repeat(8_193), true).is_err());
        assert!(validate_preview_text("line\ncolumn\tvalue\r", true).is_ok());
        assert!(validate_preview_text("bad\u{0000}", true).is_err());
        assert!(validate_preview_text("bad\u{007f}", true).is_err());
        assert!(validate_preview_text("", false).is_err());
    }

    #[test]
    fn unknown_and_mixed_fields_fail_closed() {
        let mut value = serde_json::to_value(
            MessageStreamKeyframe::new(
                7,
                strand_id(),
                message_id(),
                0,
                stream_id(),
                0,
                MessageStreamFormat::Plain,
                "hello",
                false,
            )
            .unwrap(),
        )
        .unwrap();
        value["base_seq"] = serde_json::json!(0);

        assert!(serde_json::from_value::<MessageStreamFrame>(value).is_err());
    }

    #[test]
    fn worst_case_escaped_keyframe_fits_signal_plaintext_limit() {
        let frame = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                7,
                strand_id(),
                message_id(),
                0,
                stream_id(),
                0,
                MessageStreamFormat::Plain,
                "\"\\".repeat(MAX_MESSAGE_STREAM_PREVIEW_BYTES / 2),
                true,
            )
            .unwrap(),
        );

        assert!(frame.canonical_plaintext().unwrap().len() <= MAX_SIGNAL_PLAINTEXT_BYTES);
    }

    #[test]
    fn producer_predeclares_final_identity_and_schedules_keyframes() {
        let event_id = event_id();
        let (mut producer, initial) = MessageStreamProducer::start(
            10,
            event_id.clone(),
            strand_id(),
            0,
            stream_id(),
            MessageStreamFormat::Markdown,
            1_000,
        )
        .unwrap();

        assert_eq!(initial.seq(), 0);
        assert_eq!(producer.event_id(), &event_id);
        assert_eq!(producer.message_id(), &MessageId::from_event_id(&event_id));

        let first = producer.append(11, "hello", 1_001).unwrap().unwrap();
        assert!(matches!(first, MessageStreamFrame::Keyframe(_)));
        let delta = producer.append(12, "!", 1_002).unwrap().unwrap();
        assert!(matches!(delta, MessageStreamFrame::Delta(_)));
        let doubled = producer.append(13, " world", 1_003).unwrap().unwrap();
        assert!(matches!(doubled, MessageStreamFrame::Keyframe(_)));
    }

    #[test]
    fn producer_throttles_to_five_frames_and_flushes_pending_text() {
        let (mut producer, _) = MessageStreamProducer::start(
            20,
            event_id(),
            strand_id(),
            0,
            stream_id(),
            MessageStreamFormat::Plain,
            0,
        )
        .unwrap();

        for sequence in 21..25 {
            assert!(
                producer
                    .append(sequence, "0123456789", sequence)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(producer.append(25, "pending", 25).unwrap().is_none());
        let flushed = producer.tick(26, 1_000).unwrap().unwrap();
        assert!(producer.preview().ends_with("pending"));
        assert!(matches!(
            flushed,
            MessageStreamFrame::Keyframe(_) | MessageStreamFrame::Delta(_)
        ));
    }

    #[test]
    fn producer_truncates_on_utf8_boundary_and_repeats_keyframe() {
        let (mut producer, _) = MessageStreamProducer::start(
            30,
            event_id(),
            strand_id(),
            0,
            stream_id(),
            MessageStreamFormat::Plain,
            0,
        )
        .unwrap();
        let capped = producer
            .append(31, &"é".repeat(MAX_MESSAGE_STREAM_PREVIEW_BYTES), 1)
            .unwrap()
            .unwrap();
        let MessageStreamFrame::Keyframe(capped) = capped else {
            panic!("cap must force a keyframe");
        };
        assert!(capped.truncated);
        assert_eq!(capped.text.len(), MAX_MESSAGE_STREAM_PREVIEW_BYTES);

        assert!(producer.tick(32, 14_999).unwrap().is_none());
        let repeated = producer.tick(33, 15_001).unwrap().unwrap();
        assert!(matches!(repeated, MessageStreamFrame::Keyframe(_)));
    }

    #[test]
    fn registry_enforces_eight_active_streams() {
        let mut registry = MessageStreamProducerRegistry::default();
        for index in 0..MAX_MESSAGE_STREAMS_PER_DEVICE {
            let event_id = EventId::from_event_digest(
                &arkret_wire::Hash::new(arkret_canonical::sha256_digest(index.to_be_bytes()))
                    .unwrap(),
            )
            .unwrap();
            let stream_id = MessageStreamId::new(format!(
                "ak:message_stream:01904100-0000-7000-8000-{index:012}"
            ))
            .unwrap();
            let (producer, _) = MessageStreamProducer::start(
                index as u64,
                event_id,
                strand_id(),
                0,
                stream_id,
                MessageStreamFormat::Plain,
                0,
            )
            .unwrap();
            registry.insert(producer).unwrap();
        }
        assert_eq!(registry.active_len(), MAX_MESSAGE_STREAMS_PER_DEVICE);

        let (overflow, _) = MessageStreamProducer::start(
            99,
            EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk").unwrap(),
            strand_id(),
            0,
            MessageStreamId::new("ak:message_stream:01904100-0000-7000-8000-000000000099").unwrap(),
            MessageStreamFormat::Plain,
            0,
        )
        .unwrap();
        assert!(registry.insert(overflow).is_err());
    }
}
