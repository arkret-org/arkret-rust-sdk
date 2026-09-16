//! Per-Realm authority-committed Event subscription frames.
//!
//! Counterpart of `events-subscribe-frame.schema.json`, the closed frame union
//! emitted by `ak.self.events.stream.subscribe.v1` over NDJSON and as the
//! `payload` of a WebSocket channel frame.
//!
//! Every positional frame names its own `realm_id` and carries a cursor scoped
//! to that subscription. There is no Realm-global position: a client resuming a
//! subscription passes back the cursor it last saw, and per-stream continuity
//! is re-established through [`arkret_wire::StreamScanRequest`], which is
//! addressed by [`arkret_wire::CommitStreamRef`] and `stream_position`.

use arkret_wire::{Event, RealmId, Result, WireError};
use serde::{Deserialize, Serialize};

/// Largest `reconnect_after_ms` the schema admits.
pub const EVENTS_SUBSCRIBE_MAX_RECONNECT_AFTER_MS: u64 = 300_000;

fn protocol_error(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

fn validate_cursor(value: &str) -> Result<()> {
    let tail = value
        .strip_prefix("ak:cursor:")
        .ok_or_else(|| protocol_error("invalid events stream cursor prefix"))?;
    if tail.is_empty()
        || value.len() > 2048
        || !tail
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(protocol_error("invalid bounded events stream cursor"));
    }
    Ok(())
}

/// Closed `kind` discriminator of `events-subscribe-frame.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventsSubscribeFrameKind {
    Event,
    Checkpoint,
    Heartbeat,
    CatchupComplete,
    EpochRotation,
    Dropped,
    ResyncRequired,
    Unauthorized,
}

/// Payload of an `epoch_rotation` frame.
// Field declaration order is byte-for-byte the `properties` order of
// `events-subscribe-frame.schema.json#/$defs/epoch_rotation_payload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRotationPayload {
    pub new_epoch: u32,
}

/// The `payload` member, typed by the frame kind that may carry it.
///
/// Only `event` and `epoch_rotation` admit a payload, and they admit different
/// ones, so this is an untagged union of exactly those two shapes rather than a
/// free JSON value: a control frame cannot express a payload at all.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventsSubscribeFramePayload {
    Event(Box<Event>),
    EpochRotation(EpochRotationPayload),
}

/// One frame of `ak.self.events.stream.subscribe.v1`.
// Field declaration order is byte-for-byte the `properties` order of
// `events-subscribe-frame.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubscribeFrame {
    pub kind: EventsSubscribeFrameKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<EventsSubscribeFramePayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_after_ms: Option<u64>,
}

/// What a terminal frame tells the client to do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventsStreamInterrupt {
    /// Frames were lost; resume the subscription from `cursor` with catch-up.
    Dropped {
        realm_id: RealmId,
        cursor: String,
        reconnect_after_ms: Option<u64>,
    },
    /// The client's position is no longer resumable; re-bootstrap from a
    /// signed typed snapshot plus each stream's authorized tail.
    ResyncRequired { reconnect_after_ms: Option<u64> },
    /// The subscription is no longer authorized. Not retryable by delay.
    Unauthorized,
}

impl EventsSubscribeFrame {
    /// Parse one NDJSON line, returning `Ok(None)` for a blank keep-alive line.
    pub fn from_ndjson_line(line: &str) -> Result<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let frame: Self = serde_json::from_str(trimmed)
            .map_err(|error| protocol_error(format!("invalid events subscribe frame: {error}")))?;
        frame.validate()?;
        Ok(Some(frame))
    }

    /// Enforce the schema's `oneOf`: each kind admits an exact field set.
    ///
    /// The schema expresses this as seven mutually exclusive branches with
    /// explicit `not: {required: [...]}` clauses, so a frame that merely omits
    /// a forbidden member is not enough — carrying one at all is the
    /// violation. This mirrors that branch by branch.
    pub fn validate(&self) -> Result<()> {
        if let Some(cursor) = &self.cursor {
            validate_cursor(cursor)?;
        }
        if let Some(reconnect_after_ms) = self.reconnect_after_ms
            && !(1..=EVENTS_SUBSCRIBE_MAX_RECONNECT_AFTER_MS).contains(&reconnect_after_ms)
        {
            return Err(protocol_error(
                "events frame reconnect_after_ms must be 1..=300000",
            ));
        }

        let has_realm = self.realm_id.is_some();
        let has_cursor = self.cursor.is_some();
        let has_reconnect = self.reconnect_after_ms.is_some();
        let payload_shape = match &self.payload {
            None => PayloadShape::Absent,
            Some(EventsSubscribeFramePayload::Event(_)) => PayloadShape::Event,
            Some(EventsSubscribeFramePayload::EpochRotation(_)) => PayloadShape::EpochRotation,
        };

        let valid = match self.kind {
            EventsSubscribeFrameKind::Event => {
                has_realm && has_cursor && payload_shape == PayloadShape::Event && !has_reconnect
            }
            EventsSubscribeFrameKind::EpochRotation => {
                has_realm
                    && !has_cursor
                    && payload_shape == PayloadShape::EpochRotation
                    && !has_reconnect
            }
            EventsSubscribeFrameKind::Checkpoint | EventsSubscribeFrameKind::CatchupComplete => {
                has_cursor && payload_shape == PayloadShape::Absent && !has_reconnect
            }
            EventsSubscribeFrameKind::Dropped => {
                has_realm && has_cursor && payload_shape == PayloadShape::Absent
            }
            EventsSubscribeFrameKind::ResyncRequired => {
                !has_cursor && payload_shape == PayloadShape::Absent
            }
            EventsSubscribeFrameKind::Unauthorized => {
                !has_cursor && payload_shape == PayloadShape::Absent && !has_reconnect
            }
            EventsSubscribeFrameKind::Heartbeat => {
                !has_realm && !has_cursor && payload_shape == PayloadShape::Absent && !has_reconnect
            }
        };
        if !valid {
            return Err(protocol_error(
                "invalid fields for events subscribe frame kind",
            ));
        }

        // An `event` frame carries a real authority-committed Event: bind the
        // envelope's own Realm to the frame's, so a frame cannot route one
        // Realm's Event under another Realm's subscription coordinate.
        if let Some(EventsSubscribeFramePayload::Event(event)) = &self.payload {
            let realm_id = self
                .realm_id
                .as_ref()
                .ok_or_else(|| protocol_error("event frame requires realm_id"))?;
            if &event.realm_id != realm_id {
                return Err(protocol_error(
                    "events frame realm_id does not match the carried Event",
                ));
            }
        }
        Ok(())
    }

    /// The committed Event this frame delivers, if it is an `event` frame.
    pub fn event(&self) -> Option<&Event> {
        match &self.payload {
            Some(EventsSubscribeFramePayload::Event(event)) => Some(event),
            _ => None,
        }
    }

    /// The rotated epoch this frame announces, if it is an `epoch_rotation`.
    pub fn new_epoch(&self) -> Option<u32> {
        match &self.payload {
            Some(EventsSubscribeFramePayload::EpochRotation(payload)) => Some(payload.new_epoch),
            _ => None,
        }
    }

    /// True for the three kinds after which no further frame may arrive.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.kind,
            EventsSubscribeFrameKind::Dropped
                | EventsSubscribeFrameKind::ResyncRequired
                | EventsSubscribeFrameKind::Unauthorized
        )
    }

    /// Typed terminal disposition, or `None` for a non-terminal frame.
    pub fn interrupt(&self) -> Result<Option<EventsStreamInterrupt>> {
        Ok(match self.kind {
            EventsSubscribeFrameKind::Dropped => Some(EventsStreamInterrupt::Dropped {
                realm_id: self
                    .realm_id
                    .clone()
                    .ok_or_else(|| protocol_error("dropped frame requires realm_id"))?,
                cursor: self
                    .cursor
                    .clone()
                    .ok_or_else(|| protocol_error("dropped frame requires a cursor"))?,
                reconnect_after_ms: self.reconnect_after_ms,
            }),
            EventsSubscribeFrameKind::ResyncRequired => {
                Some(EventsStreamInterrupt::ResyncRequired {
                    reconnect_after_ms: self.reconnect_after_ms,
                })
            }
            EventsSubscribeFrameKind::Unauthorized => Some(EventsStreamInterrupt::Unauthorized),
            _ => None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PayloadShape {
    Absent,
    Event,
    EpochRotation,
}

/// Local trace of one events subscription, mirroring the account rail's
/// [`crate::sync_frames::account_subscribe::StreamTraceValidator`].
///
/// It holds a single resume cursor for this subscription, never a Realm-global
/// position: two Realms subscribed over one connection each advance their own
/// frames, and the cursor is the subscription's opaque resume token.
#[derive(Clone, Debug)]
pub struct EventsStreamTrace {
    catchup: bool,
    data_seen: bool,
    catchup_complete_seen: bool,
    resume_cursor: Option<String>,
    terminal: Option<EventsSubscribeFrameKind>,
    rejected: bool,
}

/// Why an events subscription trace was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EventsStreamTraceError {
    #[error("events frame `{kind}` requires a non-empty cursor")]
    MissingCursor { kind: &'static str },
    #[error("catchup_complete arrived before any replayed frame")]
    CatchupCompleteBeforeData,
    #[error("catchup_complete is forbidden when catchup=false")]
    UnexpectedCatchupComplete,
    #[error("events frame arrived after terminal `{terminal}`")]
    FrameAfterTerminal { terminal: &'static str },
    #[error("events stream trace was already rejected")]
    TraceAlreadyRejected,
    #[error("events stream ended before catchup_complete")]
    CatchupIncomplete,
}

impl EventsSubscribeFrameKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Checkpoint => "checkpoint",
            Self::Heartbeat => "heartbeat",
            Self::CatchupComplete => "catchup_complete",
            Self::EpochRotation => "epoch_rotation",
            Self::Dropped => "dropped",
            Self::ResyncRequired => "resync_required",
            Self::Unauthorized => "unauthorized",
        }
    }
}

impl EventsStreamTrace {
    pub fn new(catchup: bool, resume_cursor: Option<String>) -> Self {
        Self {
            catchup,
            data_seen: false,
            catchup_complete_seen: false,
            resume_cursor,
            terminal: None,
            rejected: false,
        }
    }

    pub fn push(
        &mut self,
        frame: &EventsSubscribeFrame,
    ) -> std::result::Result<(), EventsStreamTraceError> {
        if self.rejected {
            return Err(EventsStreamTraceError::TraceAlreadyRejected);
        }
        if let Some(terminal) = self.terminal {
            self.rejected = true;
            return Err(EventsStreamTraceError::FrameAfterTerminal {
                terminal: terminal.as_str(),
            });
        }
        if matches!(
            frame.kind,
            EventsSubscribeFrameKind::Event
                | EventsSubscribeFrameKind::Checkpoint
                | EventsSubscribeFrameKind::CatchupComplete
                | EventsSubscribeFrameKind::Dropped
        ) && frame.cursor.as_deref().is_none_or(str::is_empty)
        {
            self.rejected = true;
            return Err(EventsStreamTraceError::MissingCursor {
                kind: frame.kind.as_str(),
            });
        }
        if frame.kind == EventsSubscribeFrameKind::CatchupComplete {
            if !self.catchup {
                self.rejected = true;
                return Err(EventsStreamTraceError::UnexpectedCatchupComplete);
            }
            if !self.data_seen {
                self.rejected = true;
                return Err(EventsStreamTraceError::CatchupCompleteBeforeData);
            }
            self.catchup_complete_seen = true;
        }
        if matches!(
            frame.kind,
            EventsSubscribeFrameKind::Event | EventsSubscribeFrameKind::Checkpoint
        ) {
            self.data_seen = true;
        }
        match frame.kind {
            EventsSubscribeFrameKind::Event
            | EventsSubscribeFrameKind::Checkpoint
            | EventsSubscribeFrameKind::CatchupComplete
            | EventsSubscribeFrameKind::Dropped => self.resume_cursor = frame.cursor.clone(),
            EventsSubscribeFrameKind::ResyncRequired => self.resume_cursor = None,
            _ => {}
        }
        if frame.is_terminal() {
            self.terminal = Some(frame.kind);
        }
        Ok(())
    }

    pub fn finish(&mut self) -> std::result::Result<(), EventsStreamTraceError> {
        if self.rejected {
            return Err(EventsStreamTraceError::TraceAlreadyRejected);
        }
        if self.catchup && !self.catchup_complete_seen && self.terminal.is_none() {
            self.rejected = true;
            return Err(EventsStreamTraceError::CatchupIncomplete);
        }
        Ok(())
    }

    pub fn resume_cursor(&self) -> Option<&str> {
        self.resume_cursor.as_deref()
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }
}
