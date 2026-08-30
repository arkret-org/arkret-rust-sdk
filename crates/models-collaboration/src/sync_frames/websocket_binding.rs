//! `ak.profile.binding.websocket.v1` connection frames
//! (`zh/sync/websocket-binding.md` §4–§6).
//!
//! The frame union lives here rather than in `arkret-wire` because a `data` /
//! `control` payload is a canonical account, events or Signal frame, and those
//! three types do not share one crate.
//!
//! ## Two-stage payload validation
//!
//! §6 is explicit that a receiver first resolves the channel's operation from
//! connection state and only then validates the payload with **that**
//! operation's canonical schema: matching some other operation's union branch
//! is still a rejection. A `payload` field therefore cannot be an untagged
//! union — `{"kind":"heartbeat"}` is a legal control payload for all three
//! operations and an untagged parse would silently pick the first branch.
//!
//! So the frames carry the payload as raw JSON and the operation-directed
//! typed views ([`WebSocketDataPayload::parse`],
//! [`WebSocketChannelControlPayload::parse`]) are the only way to read one.
//! Producers never hand-build the JSON: the constructors on
//! [`WebSocketServerFrame`] take the typed payload.

use arkret_wire::ActorId;
use arkret_wire::websocket_binding::{
    WEBSOCKET_HARD_MAX_FRAME_BYTES, WEBSOCKET_MAX_RETRY_AFTER_MS, WebSocketOperationId,
    WebSocketTransportError, validate_websocket_channel_id, validate_websocket_opaque_id,
    validate_websocket_ping_id, validate_websocket_session_grant,
};

use crate::http_bodies::{EventsSubscribeFrame, EventsSubscribeFrameKind};
use crate::internal_prelude::*;
use crate::sync_frames::account_subscribe::{AccountSubscribeFrame, AccountSubscribeFrameKind};

/// `frame_scope` discriminator of a `control` / `error` frame (§4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketFrameScope {
    Channel,
    Connection,
}

/// Closed `close.reason` set (client → server, §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketCloseReason {
    ClientRequest,
    TransportSwitch,
}

/// Closed `closed.reason` set (server → client, §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketClosedReason {
    Completed,
    ClientRequest,
    Error,
    Drain,
    Unauthorized,
}

/// Closed `reauth_required.reason` set (§3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketReauthReason {
    GrantExpiring,
}

// ── Open parameters ─────────────────────────────────────────────────────────

/// `open.parameters.filter` for the account operation (§5). Closed: the six
/// members are exactly the canonical HTTP filter selectors this binding
/// carries, spelled as the frame schema spells them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketAccountFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline_limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lazy_load_members: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_redundant_members: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_event_kinds: Option<Vec<String>>,
}

/// Maximum length of every selector array in an `open` frame (frame schema).
pub const WEBSOCKET_MAX_SELECTOR_ITEMS: usize = 256;
/// Maximum `filter.timeline_limit` (frame schema).
pub const WEBSOCKET_MAX_TIMELINE_LIMIT: u32 = 1000;

impl WebSocketAccountFilter {
    fn validate(&self) -> Result<()> {
        for (field, len) in [
            ("realm_ids", self.realm_ids.as_ref().map(Vec::len)),
            ("event_kinds", self.event_kinds.as_ref().map(Vec::len)),
            (
                "not_event_kinds",
                self.not_event_kinds.as_ref().map(Vec::len),
            ),
        ] {
            if len.is_some_and(|len| len > WEBSOCKET_MAX_SELECTOR_ITEMS) {
                return Err(WireError::Protocol(format!(
                    "WebSocket account filter {field} exceeds {WEBSOCKET_MAX_SELECTOR_ITEMS} items"
                )));
            }
        }
        if self
            .timeline_limit
            .is_some_and(|limit| limit > WEBSOCKET_MAX_TIMELINE_LIMIT)
        {
            return Err(WireError::Protocol(format!(
                "WebSocket account filter timeline_limit exceeds {WEBSOCKET_MAX_TIMELINE_LIMIT}"
            )));
        }
        Ok(())
    }
}

/// `open.parameters` for `ak.self.account.stream.subscribe.v1` (§5).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketAccountOpenParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<WebSocketAccountFilter>,
    /// Corresponds to the canonical `X-Arkret-Wait-For` request header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<Cursor>,
}

/// `open.parameters` for `ak.self.events.stream.subscribe.v1` (§5). At least one
/// of `realm_ids` / `actor_ids` MUST be present.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketEventsOpenParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ids: Option<Vec<ActorId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
}

/// Operation-discriminated `open.parameters` union (§5).
#[derive(Clone, Debug, PartialEq)]
pub enum WebSocketOpenParameters {
    Account(WebSocketAccountOpenParameters),
    Events(WebSocketEventsOpenParameters),
    /// The Signal channel takes no selector at all: `parameters` is `{}`.
    Signal,
}

impl WebSocketOpenParameters {
    pub const fn operation(&self) -> WebSocketOperationId {
        match self {
            Self::Account(_) => WebSocketOperationId::AccountStreamSubscribe,
            Self::Events(_) => WebSocketOperationId::EventsStreamSubscribe,
            Self::Signal => WebSocketOperationId::SignalStreamSubscribe,
        }
    }

    /// Parse the raw `parameters` object with the schema branch selected by
    /// the frame's own `operation_id`.
    pub fn parse(operation: WebSocketOperationId, value: &Value) -> Result<Self> {
        let parsed = match operation {
            WebSocketOperationId::AccountStreamSubscribe => {
                Self::Account(serde_json::from_value(value.clone())?)
            }
            WebSocketOperationId::EventsStreamSubscribe => {
                Self::Events(serde_json::from_value(value.clone())?)
            }
            WebSocketOperationId::SignalStreamSubscribe => {
                let object = value.as_object().ok_or_else(|| {
                    WireError::Protocol("WebSocket open parameters must be an object".to_owned())
                })?;
                if !object.is_empty() {
                    return Err(WireError::Protocol(
                        "the Signal channel takes no open parameters".to_owned(),
                    ));
                }
                Self::Signal
            }
        };
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        Ok(match self {
            Self::Account(parameters) => serde_json::to_value(parameters)?,
            Self::Events(parameters) => serde_json::to_value(parameters)?,
            Self::Signal => Value::Object(serde_json::Map::new()),
        })
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Account(parameters) => match &parameters.filter {
                Some(filter) => filter.validate(),
                None => Ok(()),
            },
            Self::Events(parameters) => {
                let realm_ids = parameters.realm_ids.as_deref().unwrap_or_default();
                let actor_ids = parameters.actor_ids.as_deref().unwrap_or_default();
                if realm_ids.is_empty() && actor_ids.is_empty() {
                    return Err(WireError::Protocol(
                        "WebSocket events open parameters require realm_ids or actor_ids"
                            .to_owned(),
                    ));
                }
                if realm_ids.len() > WEBSOCKET_MAX_SELECTOR_ITEMS
                    || actor_ids.len() > WEBSOCKET_MAX_SELECTOR_ITEMS
                {
                    return Err(WireError::Protocol(format!(
                        "WebSocket events selector exceeds {WEBSOCKET_MAX_SELECTOR_ITEMS} items"
                    )));
                }
                Ok(())
            }
            Self::Signal => Ok(()),
        }
    }
}

// ── Data and control payloads ───────────────────────────────────────────────

/// `data.payload`, resolved against the channel's operation (§6).
///
/// Only the three data-bearing kinds are admissible here: account `delta`,
/// events `event` and Signal `signal`.
#[derive(Clone, Debug)]
pub enum WebSocketDataPayload {
    Account(Box<AccountSubscribeFrame>),
    Events(Box<EventsSubscribeFrame>),
    Signal(Box<SignalStreamFrame>),
}

impl WebSocketDataPayload {
    pub const fn operation(&self) -> WebSocketOperationId {
        match self {
            Self::Account(_) => WebSocketOperationId::AccountStreamSubscribe,
            Self::Events(_) => WebSocketOperationId::EventsStreamSubscribe,
            Self::Signal(_) => WebSocketOperationId::SignalStreamSubscribe,
        }
    }

    pub fn parse(operation: WebSocketOperationId, value: &Value) -> Result<Self> {
        let parsed = match operation {
            WebSocketOperationId::AccountStreamSubscribe => {
                Self::Account(Box::new(serde_json::from_value(value.clone())?))
            }
            WebSocketOperationId::EventsStreamSubscribe => {
                Self::Events(Box::new(serde_json::from_value(value.clone())?))
            }
            WebSocketOperationId::SignalStreamSubscribe => {
                Self::Signal(Box::new(serde_json::from_value(value.clone())?))
            }
        };
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        Ok(match self {
            Self::Account(frame) => serde_json::to_value(frame)?,
            Self::Events(frame) => serde_json::to_value(frame)?,
            Self::Signal(frame) => serde_json::to_value(frame)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Account(frame) => {
                if !matches!(frame.kind, AccountSubscribeFrameKind::Delta) {
                    return Err(WireError::Protocol(
                        "a WebSocket data frame only carries the account delta kind".to_owned(),
                    ));
                }
                frame.validate()
            }
            Self::Events(frame) => {
                if !matches!(frame.kind(), EventsSubscribeFrameKind::Event) {
                    return Err(WireError::Protocol(
                        "a WebSocket data frame only carries the events event kind".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::Signal(frame) => {
                if !matches!(frame.as_ref(), SignalStreamFrame::Signal { .. }) {
                    return Err(WireError::Protocol(
                        "a WebSocket data frame only carries the signal kind".to_owned(),
                    ));
                }
                frame.validate()
            }
        }
    }
}

/// Channel-scoped `control.payload`, resolved against the channel's operation
/// (§6). Only the control kinds the operation itself defines are admissible;
/// a data-bearing kind belongs in a `data` frame.
#[derive(Clone, Debug)]
pub enum WebSocketChannelControlPayload {
    Account(Box<AccountSubscribeFrame>),
    Events(Box<EventsSubscribeFrame>),
    Signal(Box<SignalStreamFrame>),
}

impl WebSocketChannelControlPayload {
    pub const fn operation(&self) -> WebSocketOperationId {
        match self {
            Self::Account(_) => WebSocketOperationId::AccountStreamSubscribe,
            Self::Events(_) => WebSocketOperationId::EventsStreamSubscribe,
            Self::Signal(_) => WebSocketOperationId::SignalStreamSubscribe,
        }
    }

    pub fn parse(operation: WebSocketOperationId, value: &Value) -> Result<Self> {
        let parsed = match operation {
            WebSocketOperationId::AccountStreamSubscribe => {
                Self::Account(Box::new(serde_json::from_value(value.clone())?))
            }
            WebSocketOperationId::EventsStreamSubscribe => {
                Self::Events(Box::new(serde_json::from_value(value.clone())?))
            }
            WebSocketOperationId::SignalStreamSubscribe => {
                Self::Signal(Box::new(serde_json::from_value(value.clone())?))
            }
        };
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        Ok(match self {
            Self::Account(frame) => serde_json::to_value(frame)?,
            Self::Events(frame) => serde_json::to_value(frame)?,
            Self::Signal(frame) => serde_json::to_value(frame)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Account(frame) => {
                if matches!(frame.kind, AccountSubscribeFrameKind::Delta) {
                    return Err(WireError::Protocol(
                        "the account delta kind belongs in a WebSocket data frame".to_owned(),
                    ));
                }
                frame.validate()
            }
            Self::Events(frame) => {
                if matches!(frame.kind(), EventsSubscribeFrameKind::Event) {
                    return Err(WireError::Protocol(
                        "the events event kind belongs in a WebSocket data frame".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::Signal(frame) => {
                if matches!(frame.as_ref(), SignalStreamFrame::Signal { .. }) {
                    return Err(WireError::Protocol(
                        "the signal kind belongs in a WebSocket data frame".to_owned(),
                    ));
                }
                frame.validate()
            }
        }
    }
}

/// The only connection-scoped `control.payload` (§6): a service drain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebSocketConnectionControlPayload {
    Drain {
        reconnect_after_ms: u32,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        deadline: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// Maximum `reason` length of a connection drain payload (frame schema).
pub const WEBSOCKET_MAX_DRAIN_REASON_CHARS: usize = 128;

impl WebSocketConnectionControlPayload {
    pub fn validate(&self) -> Result<()> {
        let Self::Drain {
            reconnect_after_ms,
            reason,
            ..
        } = self;
        if *reconnect_after_ms > WEBSOCKET_MAX_RETRY_AFTER_MS {
            return Err(WireError::Protocol(format!(
                "WebSocket drain reconnect_after_ms exceeds {WEBSOCKET_MAX_RETRY_AFTER_MS}"
            )));
        }
        if reason.as_ref().is_some_and(|reason| {
            reason.is_empty() || reason.chars().count() > WEBSOCKET_MAX_DRAIN_REASON_CHARS
        }) {
            return Err(WireError::Protocol(format!(
                "WebSocket drain reason must be 1..={WEBSOCKET_MAX_DRAIN_REASON_CHARS} characters"
            )));
        }
        Ok(())
    }
}

// ── Connection frames ───────────────────────────────────────────────────────

/// Advertised and negotiated connection limits carried by `welcome` (§3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketConnectionLimits {
    pub max_frame_bytes: u32,
    pub max_channels: u32,
    pub max_connection_pending_bytes: u64,
    pub max_channel_pending_bytes: u64,
    pub max_connection_pending_frames: u32,
    pub max_channel_pending_frames: u32,
    pub heartbeat_interval_ms: u32,
}

impl WebSocketConnectionLimits {
    pub fn validate(&self) -> Result<()> {
        let ranges: [(&str, u64, u64, u64); 7] = [
            (
                "max_frame_bytes",
                u64::from(self.max_frame_bytes),
                1024,
                WEBSOCKET_HARD_MAX_FRAME_BYTES as u64,
            ),
            ("max_channels", u64::from(self.max_channels), 1, 256),
            (
                "max_connection_pending_bytes",
                self.max_connection_pending_bytes,
                1024,
                67_108_864,
            ),
            (
                "max_channel_pending_bytes",
                self.max_channel_pending_bytes,
                1024,
                16_777_216,
            ),
            (
                "max_connection_pending_frames",
                u64::from(self.max_connection_pending_frames),
                1,
                65_536,
            ),
            (
                "max_channel_pending_frames",
                u64::from(self.max_channel_pending_frames),
                1,
                16_384,
            ),
            (
                "heartbeat_interval_ms",
                u64::from(self.heartbeat_interval_ms),
                1_000,
                300_000,
            ),
        ];
        for (field, value, min, max) in ranges {
            if value < min || value > max {
                return Err(WireError::Protocol(format!(
                    "WebSocket welcome {field} must be {min}..={max}"
                )));
            }
        }
        Ok(())
    }
}

/// Server → client connection frame (`ak.schema.websocket_server_frame.v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebSocketServerFrame {
    Challenge {
        connection_id: String,
        nonce: String,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
    },
    Welcome {
        connection_id: String,
        max_frame_bytes: u32,
        max_channels: u32,
        max_connection_pending_bytes: u64,
        max_channel_pending_bytes: u64,
        max_connection_pending_frames: u32,
        max_channel_pending_frames: u32,
        heartbeat_interval_ms: u32,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        auth_expires_at: DateTime<Utc>,
    },
    Opened {
        channel_id: String,
        operation_id: WebSocketOperationId,
    },
    Data {
        channel_id: String,
        /// Validated with [`WebSocketDataPayload::parse`] once the receiver has
        /// resolved this channel's operation from connection state.
        payload: Value,
    },
    Control {
        frame_scope: WebSocketFrameScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel_id: Option<String>,
        payload: Value,
    },
    Error {
        frame_scope: WebSocketFrameScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel_id: Option<String>,
        error: WebSocketTransportError,
    },
    Closed {
        channel_id: String,
        reason: WebSocketClosedReason,
    },
    Ping {
        ping_id: String,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        sent_at: DateTime<Utc>,
    },
    ReauthRequired {
        connection_id: String,
        nonce: String,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        reason: WebSocketReauthReason,
    },
}

impl WebSocketServerFrame {
    /// Build the `welcome` frame from the connection's effective limits.
    pub fn welcome(
        connection_id: impl Into<String>,
        limits: WebSocketConnectionLimits,
        auth_expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        limits.validate()?;
        Ok(Self::Welcome {
            connection_id: connection_id.into(),
            max_frame_bytes: limits.max_frame_bytes,
            max_channels: limits.max_channels,
            max_connection_pending_bytes: limits.max_connection_pending_bytes,
            max_channel_pending_bytes: limits.max_channel_pending_bytes,
            max_connection_pending_frames: limits.max_connection_pending_frames,
            max_channel_pending_frames: limits.max_channel_pending_frames,
            heartbeat_interval_ms: limits.heartbeat_interval_ms,
            auth_expires_at,
        })
    }

    /// The limits a `welcome` frame carries.
    pub fn connection_limits(&self) -> Option<WebSocketConnectionLimits> {
        let Self::Welcome {
            max_frame_bytes,
            max_channels,
            max_connection_pending_bytes,
            max_channel_pending_bytes,
            max_connection_pending_frames,
            max_channel_pending_frames,
            heartbeat_interval_ms,
            ..
        } = self
        else {
            return None;
        };
        Some(WebSocketConnectionLimits {
            max_frame_bytes: *max_frame_bytes,
            max_channels: *max_channels,
            max_connection_pending_bytes: *max_connection_pending_bytes,
            max_channel_pending_bytes: *max_channel_pending_bytes,
            max_connection_pending_frames: *max_connection_pending_frames,
            max_channel_pending_frames: *max_channel_pending_frames,
            heartbeat_interval_ms: *heartbeat_interval_ms,
        })
    }

    /// Build a channel `data` frame from a typed payload.
    pub fn data(channel_id: impl Into<String>, payload: &WebSocketDataPayload) -> Result<Self> {
        Ok(Self::Data {
            channel_id: channel_id.into(),
            payload: payload.to_value()?,
        })
    }

    /// Build a channel-scoped `control` frame from a typed payload.
    pub fn channel_control(
        channel_id: impl Into<String>,
        payload: &WebSocketChannelControlPayload,
    ) -> Result<Self> {
        Ok(Self::Control {
            frame_scope: WebSocketFrameScope::Channel,
            channel_id: Some(channel_id.into()),
            payload: payload.to_value()?,
        })
    }

    /// Build the connection-scoped drain `control` frame.
    pub fn connection_control(payload: &WebSocketConnectionControlPayload) -> Result<Self> {
        payload.validate()?;
        Ok(Self::Control {
            frame_scope: WebSocketFrameScope::Connection,
            channel_id: None,
            payload: serde_json::to_value(payload)?,
        })
    }

    pub fn channel_error(channel_id: impl Into<String>, error: WebSocketTransportError) -> Self {
        Self::Error {
            frame_scope: WebSocketFrameScope::Channel,
            channel_id: Some(channel_id.into()),
            error,
        }
    }

    /// The channel this frame belongs to, if it is channel-scoped.
    pub fn channel_id(&self) -> Option<&str> {
        match self {
            Self::Opened { channel_id, .. }
            | Self::Data { channel_id, .. }
            | Self::Closed { channel_id, .. } => Some(channel_id.as_str()),
            Self::Control { channel_id, .. } | Self::Error { channel_id, .. } => {
                channel_id.as_deref()
            }
            Self::Challenge { .. }
            | Self::Welcome { .. }
            | Self::Ping { .. }
            | Self::ReauthRequired { .. } => None,
        }
    }

    /// Structural validation that does not need connection state. The
    /// operation-directed payload check is a separate step (see the module
    /// documentation).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Challenge {
                connection_id,
                nonce,
                ..
            }
            | Self::ReauthRequired {
                connection_id,
                nonce,
                ..
            } => {
                validate_websocket_opaque_id(connection_id, "connection_id")?;
                validate_websocket_opaque_id(nonce, "nonce")
            }
            Self::Welcome { connection_id, .. } => {
                validate_websocket_opaque_id(connection_id, "connection_id")?;
                self.connection_limits()
                    .expect("the welcome variant always carries limits")
                    .validate()
            }
            Self::Opened { channel_id, .. } | Self::Closed { channel_id, .. } => {
                validate_websocket_channel_id(channel_id)
            }
            Self::Data {
                channel_id,
                payload,
            } => {
                validate_websocket_channel_id(channel_id)?;
                require_object(payload, "data payload")
            }
            Self::Control {
                frame_scope,
                channel_id,
                payload,
            } => {
                validate_frame_scope(*frame_scope, channel_id.as_deref())?;
                if matches!(frame_scope, WebSocketFrameScope::Connection) {
                    let drain: WebSocketConnectionControlPayload =
                        serde_json::from_value(payload.clone())?;
                    return drain.validate();
                }
                require_object(payload, "control payload")
            }
            Self::Error {
                frame_scope,
                channel_id,
                error,
            } => {
                validate_frame_scope(*frame_scope, channel_id.as_deref())?;
                error.validate()
            }
            Self::Ping { ping_id, .. } => validate_websocket_ping_id(ping_id),
        }
    }
}

/// Client → server connection frame (`ak.schema.websocket_client_frame.v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebSocketClientFrame {
    Authenticate {
        connection_id: String,
        session_grant: String,
        dpop_proof: String,
    },
    Open {
        channel_id: String,
        operation_id: WebSocketOperationId,
        parameters: Value,
    },
    Close {
        channel_id: String,
        reason: WebSocketCloseReason,
    },
    Pong {
        ping_id: String,
    },
}

impl WebSocketClientFrame {
    /// Build an `open` frame; the operation discriminator is taken from the
    /// typed parameters so the two can never disagree.
    pub fn open(
        channel_id: impl Into<String>,
        parameters: &WebSocketOpenParameters,
    ) -> Result<Self> {
        Ok(Self::Open {
            channel_id: channel_id.into(),
            operation_id: parameters.operation(),
            parameters: parameters.to_value()?,
        })
    }

    /// The typed `open.parameters`, resolved with this frame's own
    /// `operation_id`.
    pub fn open_parameters(&self) -> Result<WebSocketOpenParameters> {
        let Self::Open {
            operation_id,
            parameters,
            ..
        } = self
        else {
            return Err(WireError::Protocol(
                "open parameters are only carried by an open frame".to_owned(),
            ));
        };
        WebSocketOpenParameters::parse(*operation_id, parameters)
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Authenticate {
                connection_id,
                session_grant,
                dpop_proof,
            } => {
                validate_websocket_opaque_id(connection_id, "connection_id")?;
                validate_websocket_session_grant(session_grant)?;
                validate_compact_jws(dpop_proof)
            }
            Self::Open { channel_id, .. } => {
                validate_websocket_channel_id(channel_id)?;
                self.open_parameters().map(|_| ())
            }
            Self::Close { channel_id, .. } => validate_websocket_channel_id(channel_id),
            Self::Pong { ping_id } => validate_websocket_ping_id(ping_id),
        }
    }
}

/// Minimum / maximum `dpop_proof` length (frame schema).
pub const WEBSOCKET_MIN_PROOF_CHARS: usize = 32;
pub const WEBSOCKET_MAX_PROOF_CHARS: usize = 16_384;

fn validate_compact_jws(value: &str) -> Result<()> {
    let length = value.chars().count();
    let segments: Vec<&str> = value.split('.').collect();
    let shaped = segments.len() == 3
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        });
    if !shaped || !(WEBSOCKET_MIN_PROOF_CHARS..=WEBSOCKET_MAX_PROOF_CHARS).contains(&length) {
        return Err(WireError::Protocol(
            "WebSocket dpop_proof must be a compact JWS of base64url segments".to_owned(),
        ));
    }
    Ok(())
}

fn validate_frame_scope(scope: WebSocketFrameScope, channel_id: Option<&str>) -> Result<()> {
    match (scope, channel_id) {
        (WebSocketFrameScope::Channel, Some(channel_id)) => {
            validate_websocket_channel_id(channel_id)
        }
        (WebSocketFrameScope::Channel, None) => Err(WireError::Protocol(
            "a channel-scoped WebSocket frame requires channel_id".to_owned(),
        )),
        (WebSocketFrameScope::Connection, None) => Ok(()),
        (WebSocketFrameScope::Connection, Some(_)) => Err(WireError::Protocol(
            "a connection-scoped WebSocket frame must not carry channel_id".to_owned(),
        )),
    }
}

fn require_object(value: &Value, what: &str) -> Result<()> {
    if value.is_object() {
        return Ok(());
    }
    Err(WireError::Protocol(format!(
        "WebSocket {what} must be a JSON object"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_open_parameters_stay_empty() {
        let frame = WebSocketClientFrame::open("signal-1", &WebSocketOpenParameters::Signal)
            .expect("signal open builds");
        let encoded = serde_json::to_string(&frame).unwrap();
        assert_eq!(
            encoded,
            "{\"kind\":\"open\",\"channel_id\":\"signal-1\",\
             \"operation_id\":\"ak.self.signal.stream.subscribe.v1\",\"parameters\":{}}"
        );
        WebSocketOpenParameters::parse(
            WebSocketOperationId::SignalStreamSubscribe,
            &serde_json::json!({"catchup": true}),
        )
        .expect_err("the Signal channel takes no selector");
    }

    #[test]
    fn events_open_parameters_require_a_selector() {
        WebSocketOpenParameters::parse(
            WebSocketOperationId::EventsStreamSubscribe,
            &serde_json::json!({"catchup": false}),
        )
        .expect_err("events require realm_ids or actor_ids");
    }

    #[test]
    fn a_control_payload_is_rejected_by_the_wrong_operation() {
        let events_frontier = serde_json::json!({
            "kind": "frontier",
            "cursor": "ak:cursor:ZXZlbnRzLWN1cnNvci0wMDAx",
        });
        WebSocketChannelControlPayload::parse(
            WebSocketOperationId::EventsStreamSubscribe,
            &events_frontier,
        )
        .expect("the events channel defines frontier");
        WebSocketChannelControlPayload::parse(
            WebSocketOperationId::SignalStreamSubscribe,
            &events_frontier,
        )
        .expect_err("the Signal channel has no frontier control payload");
    }

    #[test]
    fn frame_scope_and_channel_id_are_mutually_constrained() {
        let orphan = WebSocketServerFrame::Control {
            frame_scope: WebSocketFrameScope::Channel,
            channel_id: None,
            payload: serde_json::json!({"kind": "heartbeat"}),
        };
        orphan.validate().unwrap_err();

        let stray = WebSocketServerFrame::Error {
            frame_scope: WebSocketFrameScope::Connection,
            channel_id: Some("events-1".to_owned()),
            error: WebSocketTransportError::new(
                ErrorCode::InternalError,
                "connection state unavailable",
            ),
        };
        stray.validate().unwrap_err();
    }
}
