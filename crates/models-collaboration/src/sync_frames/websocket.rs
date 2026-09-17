//! `ak.profile.binding.websocket.v1` application frames.
//!
//! Counterpart of `websocket-frame.schema.json`: one closed union of server
//! frames and one of client frames. The connection-level primitives — profile
//! constants, the DPoP challenge shapes, the transport error body and the close
//! codes — live in [`arkret_wire::websocket_binding`]; this module owns the
//! frames, because their `data` and `control` payloads are the canonical
//! account, events and Signal frames.
//!
//! The socket is a **delivery rail only**. It multiplexes channels, it does not
//! own durable coordinates: an account frame keeps the account subscribe
//! cursor, an events frame keeps its own per-subscription cursor and
//! `realm_id`, and durable stream continuity is always
//! [`arkret_wire::CommitStreamRef`] plus `stream_position`. Nothing on this
//! rail expresses a Realm-global position, and `channel_id` is a per-connection
//! multiplexing handle with no protocol meaning outside the socket.

use std::collections::BTreeSet;

use arkret_wire::websocket_binding::{
    validate_websocket_channel_id, validate_websocket_opaque_id, validate_websocket_ping_id,
    validate_websocket_session_grant,
};
use arkret_wire::{
    ActorId, RealmId, Result, SignalStreamFrame, WebSocketOperationId, WebSocketTransportError,
    WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::string_marker;
use crate::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, RealmListRequest, SyncFilter,
};
use crate::sync_frames::events_subscribe::{EventsSubscribeFrame, EventsSubscribeFrameKind};

/// Ceiling on either `events` open-parameter selector array.
pub const WEBSOCKET_MAX_SELECTOR_ITEMS: usize = 256;
/// Ceiling on a connection drain `reason`.
pub const WEBSOCKET_MAX_DRAIN_REASON_CHARS: usize = 128;
/// Ceiling on a connection drain `reconnect_after_ms`.
pub const WEBSOCKET_MAX_DRAIN_RECONNECT_AFTER_MS: u32 = 300_000;

fn protocol_error(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

string_marker!(WebSocketChannelScope, Channel, "channel");
string_marker!(WebSocketConnectionScope, Connection, "connection");
string_marker!(WebSocketDrainMarker, Drain, "drain");

/// Which half of the connection a `control` or `error` frame addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketFrameScope {
    Channel,
    Connection,
}

/// Why a client closed one channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketCloseReason {
    ClientRequest,
    TransportSwitch,
}

/// Why the server closed one channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketClosedReason {
    Completed,
    ClientRequest,
    Error,
    Drain,
    Unauthorized,
}

/// The only reason the server may demand re-authentication mid-connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketReauthReason {
    GrantExpiring,
}

/// Open parameters for the account channel.
///
/// `wait_for` is the long-poll variant: the server holds the channel until the
/// account stream reaches that cursor. `replace_filter` rewrites the live
/// filter and therefore requires both `after` and an explicit `filter` —
/// replacing a filter without restating the position would silently change
/// which frames the cursor means.
// Field declaration order is byte-for-byte the `properties` order of
// `websocket-frame.schema.json#/$defs/account_open_parameters`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketAccountOpenParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SyncFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_list: Option<RealmListRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_filter: Option<bool>,
}

fn validate_cursor(value: &str, field: &str) -> Result<()> {
    let tail = value
        .strip_prefix("ak:cursor:")
        .ok_or_else(|| protocol_error(format!("{field} is not an ak:cursor: value")))?;
    if tail.is_empty()
        || value.len() > 2048
        || !tail
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(protocol_error(format!("{field} is not a bounded cursor")));
    }
    Ok(())
}

impl WebSocketAccountOpenParameters {
    pub fn validate(&self) -> Result<()> {
        if let Some(after) = &self.after {
            validate_cursor(after, "account open after")?;
        }
        if let Some(wait_for) = &self.wait_for {
            validate_cursor(wait_for, "account open wait_for")?;
        }
        if let Some(filter) = &self.filter {
            filter.validate()?;
        }
        if let Some(realm_list) = &self.realm_list {
            realm_list.validate()?;
        }
        if self.replace_filter == Some(true) && (self.after.is_none() || self.filter.is_none()) {
            return Err(protocol_error(
                "replace_filter requires after and an explicit filter",
            ));
        }
        Ok(())
    }
}

/// Open parameters for the events channel.
///
/// At least one selector array must be present: an unscoped Event channel has
/// no authorization to evaluate.
// Field declaration order is byte-for-byte the `properties` order of
// `websocket-frame.schema.json#/$defs/events_open_parameters`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketEventsOpenParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ids: Option<Vec<ActorId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catchup: Option<bool>,
}

impl WebSocketEventsOpenParameters {
    pub fn validate(&self) -> Result<()> {
        let realms = self.realm_ids.as_deref().unwrap_or_default();
        let actors = self.actor_ids.as_deref().unwrap_or_default();
        if realms.is_empty() && actors.is_empty() {
            return Err(protocol_error(
                "events channel requires realm_ids or actor_ids",
            ));
        }
        if realms.len() > WEBSOCKET_MAX_SELECTOR_ITEMS
            || actors.len() > WEBSOCKET_MAX_SELECTOR_ITEMS
        {
            return Err(protocol_error(
                "events channel selector exceeds 256 entries",
            ));
        }
        if realms
            .iter()
            .map(RealmId::as_str)
            .collect::<BTreeSet<_>>()
            .len()
            != realms.len()
        {
            return Err(protocol_error("events channel realm_ids repeat a Realm"));
        }
        let mut seen = BTreeSet::new();
        for actor_id in actors {
            if !seen.insert(arkret_canonical::canonical_json_bytes(actor_id)?) {
                return Err(protocol_error("events channel actor_ids repeat an actor"));
            }
        }
        if let Some(after) = &self.after {
            validate_cursor(after, "events open after")?;
        }
        Ok(())
    }
}

/// Open parameters for the Signal channel: closed and empty by schema.
///
/// Signals are momentary and cursorless, so there is nothing to parameterise;
/// the empty object is the whole contract and any member is a violation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketSignalOpenParameters {}

/// The `parameters` member, selected by the channel's `operation_id`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebSocketOpenParameters {
    Account(WebSocketAccountOpenParameters),
    Events(WebSocketEventsOpenParameters),
    Signal(WebSocketSignalOpenParameters),
}

impl WebSocketOpenParameters {
    /// Parameters and operation must agree: opening the events channel with
    /// account parameters would authorize one thing and deliver another.
    pub fn validate_for(&self, operation_id: WebSocketOperationId) -> Result<()> {
        match (self, operation_id) {
            (Self::Account(parameters), WebSocketOperationId::AccountStreamSubscribe) => {
                parameters.validate()
            }
            (Self::Events(parameters), WebSocketOperationId::EventsStreamSubscribe) => {
                parameters.validate()
            }
            (Self::Signal(_), WebSocketOperationId::SignalStreamSubscribe) => Ok(()),
            _ => Err(protocol_error(
                "websocket open parameters do not match the channel operation",
            )),
        }
    }
}

/// The `data` frame payload: one positional frame of the channel's operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebSocketDataPayload {
    Account(Box<AccountSubscribeFrame>),
    Events(Box<EventsSubscribeFrame>),
    Signal(Box<SignalStreamFrame>),
}

impl WebSocketDataPayload {
    /// A `data` frame carries only the positional kind of its rail: an account
    /// `delta`, an events `event`, or a Signal `signal`. Every other kind is a
    /// control frame and must travel as `control`, or a client counting data
    /// frames would count heartbeats as history.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Account(frame) => {
                frame.validate()?;
                if frame.kind != AccountSubscribeFrameKind::Delta {
                    return Err(protocol_error("account data payload must be a delta frame"));
                }
            }
            Self::Events(frame) => {
                frame.validate()?;
                if frame.kind != EventsSubscribeFrameKind::Event {
                    return Err(protocol_error("events data payload must be an event frame"));
                }
            }
            Self::Signal(frame) => {
                frame.validate()?;
                if !matches!(frame.as_ref(), SignalStreamFrame::Signal { .. }) {
                    return Err(protocol_error("signal data payload must be a signal frame"));
                }
            }
        }
        Ok(())
    }
}

/// The channel-scoped `control` payload: any non-positional frame of the rail.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebSocketChannelControlPayload {
    Account(Box<AccountSubscribeFrame>),
    Events(Box<EventsSubscribeFrame>),
    Signal(Box<SignalStreamFrame>),
}

impl WebSocketChannelControlPayload {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Account(frame) => {
                frame.validate()?;
                if frame.kind == AccountSubscribeFrameKind::Delta {
                    return Err(protocol_error(
                        "account delta is data, not a control payload",
                    ));
                }
            }
            Self::Events(frame) => {
                frame.validate()?;
                if frame.kind == EventsSubscribeFrameKind::Event {
                    return Err(protocol_error(
                        "events event is data, not a control payload",
                    ));
                }
            }
            Self::Signal(frame) => {
                frame.validate()?;
                if matches!(frame.as_ref(), SignalStreamFrame::Signal { .. }) {
                    return Err(protocol_error("signal is data, not a control payload"));
                }
            }
        }
        Ok(())
    }

    /// True for a payload after which the channel is finished.
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Account(frame) => matches!(
                frame.kind,
                AccountSubscribeFrameKind::Dropped
                    | AccountSubscribeFrameKind::ResyncRequired
                    | AccountSubscribeFrameKind::Unauthorized
            ),
            Self::Events(frame) => frame.is_terminal(),
            Self::Signal(frame) => matches!(
                frame.as_ref(),
                SignalStreamFrame::Drain { .. } | SignalStreamFrame::Unauthorized { .. }
            ),
        }
    }
}

/// The connection-scoped `control` payload: the server is draining the socket.
// Field declaration order is byte-for-byte the `properties` order of
// `websocket-frame.schema.json#/$defs/connection_drain_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketConnectionDrainPayload {
    pub kind: WebSocketDrainMarker,
    pub reconnect_after_ms: u32,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub deadline: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WebSocketConnectionDrainPayload {
    pub fn validate(&self) -> Result<()> {
        if self.reconnect_after_ms > WEBSOCKET_MAX_DRAIN_RECONNECT_AFTER_MS {
            return Err(protocol_error(
                "websocket drain reconnect_after_ms must be <= 300000",
            ));
        }
        if self.reason.as_ref().is_some_and(|reason| {
            reason.is_empty() || reason.chars().count() > WEBSOCKET_MAX_DRAIN_REASON_CHARS
        }) {
            return Err(protocol_error(
                "websocket drain reason must be 1..=128 code points",
            ));
        }
        Ok(())
    }
}

/// Connection limits the server advertises in `welcome`.
///
/// They are the server's authoritative budget; a client that ignores them is
/// closed rather than throttled, so they are carried as required members.
// Field declaration order is byte-for-byte the `properties` order of
// `websocket-frame.schema.json#/$defs/welcome` after `connection_id`.
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
        for (field, value, low, high) in [
            (
                "max_frame_bytes",
                u64::from(self.max_frame_bytes),
                1024,
                1_048_576,
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
        ] {
            if !(low..=high).contains(&value) {
                return Err(protocol_error(format!(
                    "websocket welcome {field} must be {low}..={high}"
                )));
            }
        }
        Ok(())
    }
}

/// One frame the server may send.
// Variant order is the `server_frame` `oneOf` order of
// `websocket-frame.schema.json`.
//
// The wire format lives on `ServerFrameWire` below rather than on a derive
// here: `control` and `error` each tag two schema shapes, and an internally
// tagged derive resolves a tag to exactly one variant, which left every
// connection-scoped control and error frame undecodable. Keeping the four
// scoped variants public means callers still match on the scope directly.
#[derive(Clone, Debug)]
pub enum WebSocketServerFrame {
    Challenge {
        connection_id: String,
        nonce: String,
        expires_at: DateTime<Utc>,
    },
    Welcome {
        connection_id: String,
        limits: WebSocketConnectionLimits,
        auth_expires_at: DateTime<Utc>,
    },
    Opened {
        channel_id: String,
        operation_id: WebSocketOperationId,
    },
    Data {
        channel_id: String,
        payload: WebSocketDataPayload,
    },
    ChannelControl {
        frame_scope: WebSocketChannelScope,
        channel_id: String,
        payload: WebSocketChannelControlPayload,
    },
    ConnectionControl {
        frame_scope: WebSocketConnectionScope,
        payload: WebSocketConnectionDrainPayload,
    },
    ChannelError {
        frame_scope: WebSocketChannelScope,
        channel_id: String,
        error: WebSocketTransportError,
    },
    ConnectionError {
        frame_scope: WebSocketConnectionScope,
        error: WebSocketTransportError,
    },
    Closed {
        channel_id: String,
        reason: WebSocketClosedReason,
    },
    Ping {
        ping_id: String,
        sent_at: DateTime<Utc>,
    },
    ReauthRequired {
        connection_id: String,
        nonce: String,
        expires_at: DateTime<Utc>,
        reason: WebSocketReauthReason,
    },
}

/// Serialization mirror for [`WebSocketServerFrame`].
///
/// One variant per `kind` on the wire. The two tags the schema shares across
/// scopes carry an untagged body whose arms are told apart by `frame_scope`,
/// exactly as `websocket-frame.schema.json` tells them apart.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ServerFrameWire {
    Challenge {
        connection_id: String,
        nonce: String,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
    },
    Welcome {
        connection_id: String,
        #[serde(flatten)]
        limits: WebSocketConnectionLimits,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        auth_expires_at: DateTime<Utc>,
    },
    Opened {
        channel_id: String,
        operation_id: WebSocketOperationId,
    },
    Data {
        channel_id: String,
        payload: WebSocketDataPayload,
    },
    Control(ControlBodyWire),
    Error(ErrorBodyWire),
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

// Both `frame_scope` types are single-valued string markers, so neither arm can
// absorb the other scope, and the channel arm additionally requires its
// `channel_id`.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum ControlBodyWire {
    Channel {
        frame_scope: WebSocketChannelScope,
        channel_id: String,
        payload: WebSocketChannelControlPayload,
    },
    Connection {
        frame_scope: WebSocketConnectionScope,
        payload: WebSocketConnectionDrainPayload,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum ErrorBodyWire {
    Channel {
        frame_scope: WebSocketChannelScope,
        channel_id: String,
        error: WebSocketTransportError,
    },
    Connection {
        frame_scope: WebSocketConnectionScope,
        error: WebSocketTransportError,
    },
}

impl From<WebSocketServerFrame> for ServerFrameWire {
    fn from(frame: WebSocketServerFrame) -> Self {
        match frame {
            WebSocketServerFrame::Challenge {
                connection_id,
                nonce,
                expires_at,
            } => Self::Challenge {
                connection_id,
                nonce,
                expires_at,
            },
            WebSocketServerFrame::Welcome {
                connection_id,
                limits,
                auth_expires_at,
            } => Self::Welcome {
                connection_id,
                limits,
                auth_expires_at,
            },
            WebSocketServerFrame::Opened {
                channel_id,
                operation_id,
            } => Self::Opened {
                channel_id,
                operation_id,
            },
            WebSocketServerFrame::Data {
                channel_id,
                payload,
            } => Self::Data {
                channel_id,
                payload,
            },
            WebSocketServerFrame::ChannelControl {
                frame_scope,
                channel_id,
                payload,
            } => Self::Control(ControlBodyWire::Channel {
                frame_scope,
                channel_id,
                payload,
            }),
            WebSocketServerFrame::ConnectionControl {
                frame_scope,
                payload,
            } => Self::Control(ControlBodyWire::Connection {
                frame_scope,
                payload,
            }),
            WebSocketServerFrame::ChannelError {
                frame_scope,
                channel_id,
                error,
            } => Self::Error(ErrorBodyWire::Channel {
                frame_scope,
                channel_id,
                error,
            }),
            WebSocketServerFrame::ConnectionError { frame_scope, error } => {
                Self::Error(ErrorBodyWire::Connection { frame_scope, error })
            }
            WebSocketServerFrame::Closed { channel_id, reason } => {
                Self::Closed { channel_id, reason }
            }
            WebSocketServerFrame::Ping { ping_id, sent_at } => Self::Ping { ping_id, sent_at },
            WebSocketServerFrame::ReauthRequired {
                connection_id,
                nonce,
                expires_at,
                reason,
            } => Self::ReauthRequired {
                connection_id,
                nonce,
                expires_at,
                reason,
            },
        }
    }
}

impl From<ServerFrameWire> for WebSocketServerFrame {
    fn from(wire: ServerFrameWire) -> Self {
        match wire {
            ServerFrameWire::Challenge {
                connection_id,
                nonce,
                expires_at,
            } => Self::Challenge {
                connection_id,
                nonce,
                expires_at,
            },
            ServerFrameWire::Welcome {
                connection_id,
                limits,
                auth_expires_at,
            } => Self::Welcome {
                connection_id,
                limits,
                auth_expires_at,
            },
            ServerFrameWire::Opened {
                channel_id,
                operation_id,
            } => Self::Opened {
                channel_id,
                operation_id,
            },
            ServerFrameWire::Data {
                channel_id,
                payload,
            } => Self::Data {
                channel_id,
                payload,
            },
            ServerFrameWire::Control(ControlBodyWire::Channel {
                frame_scope,
                channel_id,
                payload,
            }) => Self::ChannelControl {
                frame_scope,
                channel_id,
                payload,
            },
            ServerFrameWire::Control(ControlBodyWire::Connection {
                frame_scope,
                payload,
            }) => Self::ConnectionControl {
                frame_scope,
                payload,
            },
            ServerFrameWire::Error(ErrorBodyWire::Channel {
                frame_scope,
                channel_id,
                error,
            }) => Self::ChannelError {
                frame_scope,
                channel_id,
                error,
            },
            ServerFrameWire::Error(ErrorBodyWire::Connection { frame_scope, error }) => {
                Self::ConnectionError { frame_scope, error }
            }
            ServerFrameWire::Closed { channel_id, reason } => Self::Closed { channel_id, reason },
            ServerFrameWire::Ping { ping_id, sent_at } => Self::Ping { ping_id, sent_at },
            ServerFrameWire::ReauthRequired {
                connection_id,
                nonce,
                expires_at,
                reason,
            } => Self::ReauthRequired {
                connection_id,
                nonce,
                expires_at,
                reason,
            },
        }
    }
}

impl Serialize for WebSocketServerFrame {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        ServerFrameWire::from(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WebSocketServerFrame {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        ServerFrameWire::deserialize(deserializer).map(Self::from)
    }
}

impl WebSocketServerFrame {
    /// The channel this frame addresses, when it addresses one.
    pub fn channel_id(&self) -> Option<&str> {
        match self {
            Self::Opened { channel_id, .. }
            | Self::Data { channel_id, .. }
            | Self::ChannelControl { channel_id, .. }
            | Self::ChannelError { channel_id, .. }
            | Self::Closed { channel_id, .. } => Some(channel_id),
            _ => None,
        }
    }

    /// The scope a `control` / `error` frame declares.
    pub const fn frame_scope(&self) -> Option<WebSocketFrameScope> {
        match self {
            Self::ChannelControl { .. } | Self::ChannelError { .. } => {
                Some(WebSocketFrameScope::Channel)
            }
            Self::ConnectionControl { .. } | Self::ConnectionError { .. } => {
                Some(WebSocketFrameScope::Connection)
            }
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(channel_id) = self.channel_id() {
            validate_websocket_channel_id(channel_id)?;
        }
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
                validate_websocket_opaque_id(nonce, "nonce")?;
            }
            Self::Welcome {
                connection_id,
                limits,
                ..
            } => {
                validate_websocket_opaque_id(connection_id, "connection_id")?;
                limits.validate()?;
            }
            Self::Data { payload, .. } => payload.validate()?,
            Self::ChannelControl { payload, .. } => payload.validate()?,
            Self::ConnectionControl { payload, .. } => payload.validate()?,
            Self::ChannelError { error, .. } | Self::ConnectionError { error, .. } => {
                error.validate()?;
            }
            Self::Ping { ping_id, .. } => validate_websocket_ping_id(ping_id)?,
            Self::Opened { .. } | Self::Closed { .. } => {}
        }
        Ok(())
    }
}

/// One frame the client may send.
// Variant order is the `client_frame` `oneOf` order of
// `websocket-frame.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
        parameters: WebSocketOpenParameters,
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
    pub fn channel_id(&self) -> Option<&str> {
        match self {
            Self::Open { channel_id, .. } | Self::Close { channel_id, .. } => Some(channel_id),
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(channel_id) = self.channel_id() {
            validate_websocket_channel_id(channel_id)?;
        }
        match self {
            Self::Authenticate {
                connection_id,
                session_grant,
                dpop_proof,
            } => {
                validate_websocket_opaque_id(connection_id, "connection_id")?;
                validate_websocket_session_grant(session_grant)?;
                validate_compact_jws(dpop_proof)?;
            }
            Self::Open {
                operation_id,
                parameters,
                ..
            } => parameters.validate_for(*operation_id)?,
            Self::Close { .. } => {}
            Self::Pong { ping_id } => validate_websocket_ping_id(ping_id)?,
        }
        Ok(())
    }
}

/// Minimum and maximum compact-JWS length the frame schema admits.
pub const WEBSOCKET_MIN_PROOF_CHARS: usize = 32;
/// Upper bound on a DPoP proof carried in an `authenticate` frame.
pub const WEBSOCKET_MAX_PROOF_CHARS: usize = 16_384;

fn validate_compact_jws(value: &str) -> Result<()> {
    let parts = value.split('.').collect::<Vec<_>>();
    let base64url = |segment: &str| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    if parts.len() != 3
        || !parts.iter().all(|segment| base64url(segment))
        || !(WEBSOCKET_MIN_PROOF_CHARS..=WEBSOCKET_MAX_PROOF_CHARS).contains(&value.len())
    {
        return Err(protocol_error(
            "websocket dpop_proof must be a bounded compact JWS",
        ));
    }
    Ok(())
}

/// Where one connection stands in the binding's handshake.
///
/// The order is fixed and one-way: a socket cannot open a channel before it is
/// authenticated, and a drained connection never returns to `Ready`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WebSocketConnectionPhase {
    /// Opened; the server has not yet issued its challenge.
    AwaitingChallenge,
    /// Challenged; the client has not yet authenticated.
    AwaitingAuthentication,
    /// Authenticated and welcomed; channels may be opened.
    Ready,
    /// The server is draining; existing channels finish, none may open.
    Draining,
    /// Closed. Terminal.
    Closed,
}

/// One multiplexed channel of a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketChannel {
    pub channel_id: String,
    pub operation_id: WebSocketOperationId,
    /// Last cursor this channel delivered, for the rails that have one.
    ///
    /// It is the channel's own resume token, never a connection-wide or
    /// Realm-wide position: two channels on one socket resume independently.
    pub resume_cursor: Option<String>,
    pub closed: bool,
}

/// Local view of one WebSocket connection's protocol state.
///
/// This is the client-side half of the binding: it accepts the server frames
/// in the order the profile allows and refuses the ones it does not, so an
/// out-of-order or cross-channel frame is a typed error instead of corrupt
/// local state.
#[derive(Clone, Debug)]
pub struct WebSocketConnectionState {
    phase: WebSocketConnectionPhase,
    connection_id: Option<String>,
    limits: Option<WebSocketConnectionLimits>,
    channels: Vec<WebSocketChannel>,
}

impl Default for WebSocketConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketConnectionState {
    pub const fn new() -> Self {
        Self {
            phase: WebSocketConnectionPhase::AwaitingChallenge,
            connection_id: None,
            limits: None,
            channels: Vec::new(),
        }
    }

    pub const fn phase(&self) -> WebSocketConnectionPhase {
        self.phase
    }

    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_deref()
    }

    pub const fn limits(&self) -> Option<&WebSocketConnectionLimits> {
        self.limits.as_ref()
    }

    pub fn channel(&self, channel_id: &str) -> Option<&WebSocketChannel> {
        self.channels
            .iter()
            .find(|channel| channel.channel_id == channel_id)
    }

    pub fn open_channels(&self) -> impl Iterator<Item = &WebSocketChannel> {
        self.channels.iter().filter(|channel| !channel.closed)
    }

    /// Record one client frame the local side is about to send.
    pub fn observe_client(&mut self, frame: &WebSocketClientFrame) -> Result<()> {
        frame.validate()?;
        match frame {
            WebSocketClientFrame::Authenticate { connection_id, .. } => {
                if self.phase != WebSocketConnectionPhase::AwaitingAuthentication {
                    return Err(protocol_error(
                        "authenticate is only valid after a challenge",
                    ));
                }
                if self.connection_id.as_deref() != Some(connection_id.as_str()) {
                    return Err(protocol_error(
                        "authenticate names a different connection_id than the challenge",
                    ));
                }
            }
            WebSocketClientFrame::Open {
                channel_id,
                operation_id,
                ..
            } => {
                if self.phase != WebSocketConnectionPhase::Ready {
                    return Err(protocol_error(
                        "channels may only be opened on a ready connection",
                    ));
                }
                if self.channel(channel_id).is_some() {
                    return Err(protocol_error("channel_id is already in use"));
                }
                if let Some(limits) = &self.limits
                    && self.open_channels().count() >= limits.max_channels as usize
                {
                    return Err(protocol_error(
                        "opening this channel would exceed max_channels",
                    ));
                }
                self.channels.push(WebSocketChannel {
                    channel_id: channel_id.clone(),
                    operation_id: *operation_id,
                    resume_cursor: None,
                    closed: false,
                });
            }
            WebSocketClientFrame::Close { channel_id, .. } => {
                self.require_open_channel(channel_id)?;
            }
            WebSocketClientFrame::Pong { .. } => {}
        }
        Ok(())
    }

    /// Record one server frame the local side just received.
    pub fn observe_server(&mut self, frame: &WebSocketServerFrame) -> Result<()> {
        frame.validate()?;
        match frame {
            WebSocketServerFrame::Challenge { connection_id, .. } => {
                if self.phase != WebSocketConnectionPhase::AwaitingChallenge {
                    return Err(protocol_error("challenge arrived out of order"));
                }
                self.connection_id = Some(connection_id.clone());
                self.phase = WebSocketConnectionPhase::AwaitingAuthentication;
            }
            WebSocketServerFrame::Welcome {
                connection_id,
                limits,
                ..
            } => {
                if self.phase != WebSocketConnectionPhase::AwaitingAuthentication {
                    return Err(protocol_error("welcome arrived out of order"));
                }
                if self.connection_id.as_deref() != Some(connection_id.as_str()) {
                    return Err(protocol_error(
                        "welcome names a different connection_id than the challenge",
                    ));
                }
                self.limits = Some(*limits);
                self.phase = WebSocketConnectionPhase::Ready;
            }
            WebSocketServerFrame::Opened {
                channel_id,
                operation_id,
            } => {
                let channel = self.require_open_channel_mut(channel_id)?;
                if channel.operation_id != *operation_id {
                    return Err(protocol_error(
                        "opened names a different operation than the open request",
                    ));
                }
            }
            WebSocketServerFrame::Data {
                channel_id,
                payload,
            } => {
                let cursor = data_payload_cursor(payload);
                let channel = self.require_open_channel_mut(channel_id)?;
                if let Some(cursor) = cursor {
                    channel.resume_cursor = Some(cursor);
                }
            }
            WebSocketServerFrame::ChannelControl {
                channel_id,
                payload,
                ..
            } => {
                let cursor = channel_control_cursor(payload);
                let terminal = payload.is_terminal();
                let channel = self.require_open_channel_mut(channel_id)?;
                if let Some(cursor) = cursor {
                    channel.resume_cursor = Some(cursor);
                }
                if terminal {
                    channel.closed = true;
                }
            }
            WebSocketServerFrame::ConnectionControl { .. } => {
                if self.phase == WebSocketConnectionPhase::Closed {
                    return Err(protocol_error("drain arrived after close"));
                }
                self.phase = WebSocketConnectionPhase::Draining;
            }
            WebSocketServerFrame::ChannelError { channel_id, .. } => {
                self.require_open_channel_mut(channel_id)?.closed = true;
            }
            WebSocketServerFrame::ConnectionError { .. } => {
                self.phase = WebSocketConnectionPhase::Closed;
                for channel in &mut self.channels {
                    channel.closed = true;
                }
            }
            WebSocketServerFrame::Closed { channel_id, .. } => {
                self.require_channel_mut(channel_id)?.closed = true;
            }
            WebSocketServerFrame::Ping { .. } => {}
            WebSocketServerFrame::ReauthRequired { connection_id, .. } => {
                if self.connection_id.as_deref() != Some(connection_id.as_str()) {
                    return Err(protocol_error(
                        "reauth_required names a different connection_id",
                    ));
                }
                self.phase = WebSocketConnectionPhase::AwaitingAuthentication;
            }
        }
        Ok(())
    }

    fn require_channel_mut(&mut self, channel_id: &str) -> Result<&mut WebSocketChannel> {
        self.channels
            .iter_mut()
            .find(|channel| channel.channel_id == channel_id)
            .ok_or_else(|| protocol_error("frame names a channel this connection never opened"))
    }

    fn require_open_channel_mut(&mut self, channel_id: &str) -> Result<&mut WebSocketChannel> {
        let channel = self.require_channel_mut(channel_id)?;
        if channel.closed {
            return Err(protocol_error("frame arrived on a closed channel"));
        }
        Ok(channel)
    }

    fn require_open_channel(&self, channel_id: &str) -> Result<&WebSocketChannel> {
        let channel = self
            .channel(channel_id)
            .ok_or_else(|| protocol_error("frame names a channel this connection never opened"))?;
        if channel.closed {
            return Err(protocol_error("frame arrived on a closed channel"));
        }
        Ok(channel)
    }
}

fn data_payload_cursor(payload: &WebSocketDataPayload) -> Option<String> {
    match payload {
        WebSocketDataPayload::Account(frame) => frame.cursor.clone(),
        WebSocketDataPayload::Events(frame) => frame.cursor.clone(),
        WebSocketDataPayload::Signal(_) => None,
    }
}

fn channel_control_cursor(payload: &WebSocketChannelControlPayload) -> Option<String> {
    match payload {
        WebSocketChannelControlPayload::Account(frame) => frame.cursor.clone(),
        WebSocketChannelControlPayload::Events(frame) => frame.cursor.clone(),
        WebSocketChannelControlPayload::Signal(_) => None,
    }
}

/// Cursor for one channel of one connection, so a caller can resume every rail
/// independently after a drain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketChannelResume {
    pub channel_id: String,
    pub operation_id: WebSocketOperationId,
    pub resume_cursor: Option<String>,
}

impl WebSocketConnectionState {
    /// Snapshot every live channel's own resume position.
    ///
    /// The result is a *list*, never one value: the socket carried several
    /// independent rails and collapsing them to a single position would lose
    /// exactly the independence the protocol relies on.
    pub fn resume_plan(&self) -> Vec<WebSocketChannelResume> {
        self.open_channels()
            .map(|channel| WebSocketChannelResume {
                channel_id: channel.channel_id.clone(),
                operation_id: channel.operation_id,
                resume_cursor: channel.resume_cursor.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn limits() -> WebSocketConnectionLimits {
        WebSocketConnectionLimits {
            max_frame_bytes: 65_536,
            max_channels: 2,
            max_connection_pending_bytes: 1_048_576,
            max_channel_pending_bytes: 262_144,
            max_connection_pending_frames: 256,
            max_channel_pending_frames: 64,
            heartbeat_interval_ms: 30_000,
        }
    }

    fn instant() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 16, 12, 0, 0).unwrap()
    }

    fn connection_id() -> String {
        "conn-00000000000000000001".to_owned()
    }

    fn nonce() -> String {
        "nonce-0000000000000000001".to_owned()
    }

    fn challenge() -> WebSocketServerFrame {
        WebSocketServerFrame::Challenge {
            connection_id: connection_id(),
            nonce: nonce(),
            expires_at: instant(),
        }
    }

    fn welcome() -> WebSocketServerFrame {
        WebSocketServerFrame::Welcome {
            connection_id: connection_id(),
            limits: limits(),
            auth_expires_at: instant(),
        }
    }

    fn events_open(channel: &str) -> WebSocketClientFrame {
        WebSocketClientFrame::Open {
            channel_id: channel.to_owned(),
            operation_id: WebSocketOperationId::EventsStreamSubscribe,
            parameters: WebSocketOpenParameters::Events(WebSocketEventsOpenParameters {
                realm_ids: Some(vec![
                    RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs").unwrap(),
                ]),
                actor_ids: None,
                after: None,
                catchup: None,
            }),
        }
    }

    fn ready() -> WebSocketConnectionState {
        let mut state = WebSocketConnectionState::new();
        state.observe_server(&challenge()).unwrap();
        state.observe_server(&welcome()).unwrap();
        state
    }

    #[test]
    fn welcome_before_challenge_is_refused() {
        let mut state = WebSocketConnectionState::new();
        assert!(state.observe_server(&welcome()).is_err());
    }

    #[test]
    fn challenge_then_welcome_reaches_ready_and_records_limits() {
        let state = ready();
        assert_eq!(state.phase(), WebSocketConnectionPhase::Ready);
        assert_eq!(state.limits(), Some(&limits()));
        assert_eq!(state.connection_id(), Some(connection_id().as_str()));
    }

    #[test]
    fn channels_cannot_be_opened_before_ready() {
        let mut state = WebSocketConnectionState::new();
        state.observe_server(&challenge()).unwrap();
        assert!(state.observe_client(&events_open("c1")).is_err());
    }

    #[test]
    fn max_channels_is_enforced_locally() {
        let mut state = ready();
        state.observe_client(&events_open("c1")).unwrap();
        state.observe_client(&events_open("c2")).unwrap();
        assert!(
            state
                .observe_client(&events_open("c3"))
                .unwrap_err()
                .to_string()
                .contains("max_channels")
        );
    }

    #[test]
    fn a_frame_for_an_unopened_channel_is_refused() {
        let mut state = ready();
        let frame = WebSocketServerFrame::Opened {
            channel_id: "c9".to_owned(),
            operation_id: WebSocketOperationId::EventsStreamSubscribe,
        };
        assert!(
            state
                .observe_server(&frame)
                .unwrap_err()
                .to_string()
                .contains("never opened")
        );
    }

    #[test]
    fn open_parameters_must_match_the_channel_operation() {
        let frame = WebSocketClientFrame::Open {
            channel_id: "c1".to_owned(),
            operation_id: WebSocketOperationId::SignalStreamSubscribe,
            parameters: WebSocketOpenParameters::Events(WebSocketEventsOpenParameters::default()),
        };
        assert!(frame.validate().is_err());
    }

    #[test]
    fn signal_open_parameters_are_a_closed_empty_object() {
        let value = json!({});
        let parameters: WebSocketSignalOpenParameters =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(parameters).unwrap(), value);
        assert!(
            serde_json::from_value::<WebSocketSignalOpenParameters>(json!({"after": "x"})).is_err()
        );
    }

    #[test]
    fn events_channel_requires_a_selector() {
        assert!(WebSocketEventsOpenParameters::default().validate().is_err());
    }

    #[test]
    fn a_drain_moves_the_connection_out_of_ready_but_keeps_per_channel_cursors() {
        let mut state = ready();
        state.observe_client(&events_open("c1")).unwrap();
        state
            .observe_server(&WebSocketServerFrame::Opened {
                channel_id: "c1".to_owned(),
                operation_id: WebSocketOperationId::EventsStreamSubscribe,
            })
            .unwrap();
        state
            .observe_server(&WebSocketServerFrame::ChannelControl {
                frame_scope: WebSocketChannelScope::Channel,
                channel_id: "c1".to_owned(),
                payload: WebSocketChannelControlPayload::Events(Box::new(EventsSubscribeFrame {
                    kind: EventsSubscribeFrameKind::Checkpoint,
                    realm_id: None,
                    cursor: Some("ak:cursor:abc".to_owned()),
                    payload: None,
                    reconnect_after_ms: None,
                })),
            })
            .unwrap();
        state
            .observe_server(&WebSocketServerFrame::ConnectionControl {
                frame_scope: WebSocketConnectionScope::Connection,
                payload: WebSocketConnectionDrainPayload {
                    kind: WebSocketDrainMarker::Drain,
                    reconnect_after_ms: 2_000,
                    deadline: instant(),
                    reason: Some("rotation".to_owned()),
                },
            })
            .unwrap();
        assert_eq!(state.phase(), WebSocketConnectionPhase::Draining);
        let plan = state.resume_plan();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].resume_cursor.as_deref(), Some("ak:cursor:abc"));
    }

    #[test]
    fn a_control_payload_may_not_be_a_positional_frame() {
        let payload = WebSocketChannelControlPayload::Events(Box::new(EventsSubscribeFrame {
            kind: EventsSubscribeFrameKind::Heartbeat,
            realm_id: None,
            cursor: None,
            payload: None,
            reconnect_after_ms: None,
        }));
        payload.validate().unwrap();

        let signal = WebSocketChannelControlPayload::Signal(Box::new(SignalStreamFrame::Heartbeat));
        signal.validate().unwrap();
    }

    #[test]
    fn drain_reason_and_delay_are_bounded() {
        let mut payload = WebSocketConnectionDrainPayload {
            kind: WebSocketDrainMarker::Drain,
            reconnect_after_ms: 2_000,
            deadline: instant(),
            reason: Some("a".repeat(129)),
        };
        assert!(payload.validate().is_err());
        payload.reason = None;
        payload.reconnect_after_ms = 300_001;
        assert!(payload.validate().is_err());
    }

    #[test]
    fn welcome_limits_are_range_checked() {
        let mut over = limits();
        over.max_channels = 257;
        assert!(over.validate().is_err());
        let mut under = limits();
        under.heartbeat_interval_ms = 999;
        assert!(under.validate().is_err());
    }

    #[test]
    fn server_frame_kind_tags_match_the_schema() {
        let value = serde_json::to_value(challenge()).unwrap();
        assert_eq!(value["kind"], json!("challenge"));
        let control = serde_json::to_value(WebSocketServerFrame::ConnectionControl {
            frame_scope: WebSocketConnectionScope::Connection,
            payload: WebSocketConnectionDrainPayload {
                kind: WebSocketDrainMarker::Drain,
                reconnect_after_ms: 0,
                deadline: instant(),
                reason: None,
            },
        })
        .unwrap();
        assert_eq!(control["kind"], json!("control"));
        assert_eq!(control["frame_scope"], json!("connection"));
        assert_eq!(control["payload"]["kind"], json!("drain"));
    }

    /// `control` and `error` each tag two variants in the schema, and
    /// `frame_scope` -- not `kind` -- says which. A reader that resolves on the
    /// tag alone routes every connection-scoped drain into the channel arm,
    /// where it fails for a missing `channel_id` that was never meant to be
    /// there, so the connection scope is round-tripped explicitly.
    #[test]
    fn a_shared_kind_tag_is_disambiguated_by_frame_scope() {
        let frame = WebSocketServerFrame::ConnectionControl {
            frame_scope: WebSocketConnectionScope::Connection,
            payload: WebSocketConnectionDrainPayload {
                kind: WebSocketDrainMarker::Drain,
                reconnect_after_ms: 0,
                deadline: instant(),
                reason: None,
            },
        };
        let encoded = serde_json::to_value(&frame).unwrap();
        let decoded: WebSocketServerFrame = serde_json::from_value(encoded.clone()).unwrap();
        assert!(matches!(
            decoded,
            WebSocketServerFrame::ConnectionControl { .. }
        ));
        assert_eq!(serde_json::to_value(&decoded).unwrap(), encoded);
    }

    #[test]
    fn client_frame_kind_tags_match_the_schema() {
        let value = serde_json::to_value(WebSocketClientFrame::Pong {
            ping_id: "ping-0000000000001".to_owned(),
        })
        .unwrap();
        assert_eq!(value["kind"], json!("pong"));
        let open = serde_json::to_value(events_open("c1")).unwrap();
        assert_eq!(open["kind"], json!("open"));
        assert_eq!(
            open["operation_id"],
            json!("ak.self.events.stream.subscribe.v1")
        );
    }
}
