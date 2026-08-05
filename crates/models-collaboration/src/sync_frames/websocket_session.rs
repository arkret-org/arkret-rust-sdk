//! Connection and channel state machine for
//! `ak.profile.binding.websocket.v1` (`zh/sync/websocket-binding.md` §4–§8).
//!
//! One physical connection multiplexes up to three kinds of logical channel
//! whose authorization, cursor, filter and completion semantics stay
//! independent (§1). Everything that decides *whether a frame is admissible
//! given connection state* lives here, so the service, the client engine and
//! the conformance runner share one implementation:
//!
//! - which frame kinds are legal in which phase (§3: nothing but `challenge` / `authenticate`
//!   before `welcome`);
//! - channel admission, the permanent `channel_id` reservation and the `max_channels` ceiling (§5);
//! - the operation-directed payload resolution and the isolation rule that a channel failure must
//!   not disturb its siblings (§6, §7);
//! - which durable cursor a frame may advance, and the fact that the Signal channel has none (§6.1
//!   / §6.2);
//! - the close-code → retry / HTTP-fallback decision table (§8.1).

use std::collections::BTreeMap;

use arkret_wire::ErrorCode;
use arkret_wire::websocket_binding::{
    WEBSOCKET_HARD_MAX_FRAME_BYTES, WebSocketCloseCode, WebSocketOperationId,
    WebSocketTransportError, validate_websocket_channel_id,
};

use crate::internal_prelude::*;
use crate::sync_frames::stream_trace::{StreamTraceFrame, StreamTraceFrameKind};
use crate::sync_frames::websocket_binding::{
    WebSocketChannelControlPayload, WebSocketClientFrame, WebSocketConnectionControlPayload,
    WebSocketConnectionLimits, WebSocketDataPayload, WebSocketFrameScope, WebSocketServerFrame,
};

/// Where the connection is in the §3 handshake / drain lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebSocketConnectionPhase {
    /// Upgraded and challenged, not yet authenticated. No `open` / `data` /
    /// business control frame may cross in either direction.
    AwaitingAuthenticate,
    Authenticated,
    /// `reauth_required` was sent. Already-admitted channels keep being served
    /// under the old authorization; no new channel is admitted.
    Reauthenticating,
    /// A connection-scoped drain was sent: existing durable channels get until
    /// the deadline to checkpoint, new channels are refused.
    Draining,
    Closed,
}

/// One logical channel inside the connection.
#[derive(Clone, Debug)]
pub struct WebSocketChannel {
    pub channel_id: String,
    pub operation: WebSocketOperationId,
    pub open: bool,
    /// The last cursor the receiver has actually checkpointed. Only this value
    /// may be used to resume on the next connection (§6.1).
    pub durable_cursor: Option<String>,
    /// A cursor observed on an accepted frame that is not checkpointed yet.
    pub pending_cursor: Option<String>,
}

impl WebSocketChannel {
    /// Promote the observed cursor to the durable resume point. The client
    /// calls this only after its own local durable write succeeded.
    pub fn checkpoint(&mut self) -> Option<&str> {
        if let Some(cursor) = self.pending_cursor.take() {
            self.durable_cursor = Some(cursor);
        }
        self.durable_cursor.as_deref()
    }
}

/// Why a frame was refused, and how far the refusal reaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketRejection {
    /// `None` for a channel-scoped refusal: the connection stays open and only
    /// that channel gets `error` + `closed` (§7 / §8).
    pub close_code: Option<WebSocketCloseCode>,
    pub channel_id: Option<String>,
    pub error: WebSocketTransportError,
}

impl WebSocketRejection {
    fn connection(close_code: WebSocketCloseCode, code: ErrorCode, message: &str) -> Self {
        Self {
            close_code: Some(close_code),
            channel_id: None,
            error: WebSocketTransportError::new(code, message),
        }
    }

    fn channel(channel_id: &str, code: ErrorCode, message: &str) -> Self {
        Self {
            close_code: None,
            channel_id: Some(channel_id.to_owned()),
            error: WebSocketTransportError::new(code, message),
        }
    }

    /// True when the refusal terminates the whole physical connection.
    pub fn is_connection_scoped(&self) -> bool {
        self.close_code.is_some()
    }
}

/// Byte gate + duplicate-member gate + direction schema for one reassembled
/// text message (§4).
///
/// The order is normative and load-bearing: the effective byte limit is
/// checked on the accumulated bytes **before** the JSON parser is called, so an
/// oversize message can never make the receiver allocate an unbounded buffer or
/// run a parse. Only that check closes with `1009`; every other failure here is
/// `1002`.
#[derive(Clone, Copy, Debug)]
pub struct WebSocketFrameCodec {
    effective_max_frame_bytes: usize,
}

impl WebSocketFrameCodec {
    /// The effective limit is the minimum of the discovery value, the
    /// `welcome` value when one has arrived, and the 1 MiB hard ceiling.
    pub fn new(advertised_max_frame_bytes: u32, welcome_max_frame_bytes: Option<u32>) -> Self {
        let advertised = advertised_max_frame_bytes as usize;
        let welcome = welcome_max_frame_bytes
            .map(|value| value as usize)
            .unwrap_or(usize::MAX);
        Self {
            effective_max_frame_bytes: advertised.min(welcome).min(WEBSOCKET_HARD_MAX_FRAME_BYTES),
        }
    }

    pub fn effective_max_frame_bytes(&self) -> usize {
        self.effective_max_frame_bytes
    }

    /// A binary message is refused outright (§4).
    pub fn reject_binary_message(&self) -> WebSocketRejection {
        WebSocketRejection::connection(
            WebSocketCloseCode::ProtocolError,
            ErrorCode::InvalidParam,
            "this binding carries only UTF-8 text messages",
        )
    }

    /// True while a partially reassembled message is still under the limit.
    /// A fragmenting receiver calls this per chunk and closes with `1009` the
    /// moment it returns `false`, before buffering more.
    pub fn accepts_accumulated(&self, accumulated_bytes: usize) -> bool {
        accumulated_bytes <= self.effective_max_frame_bytes
    }

    pub fn decode_server_frame(
        &self,
        bytes: &[u8],
    ) -> std::result::Result<WebSocketServerFrame, WebSocketRejection> {
        self.decode(bytes)
    }

    pub fn decode_client_frame(
        &self,
        bytes: &[u8],
    ) -> std::result::Result<WebSocketClientFrame, WebSocketRejection> {
        self.decode(bytes)
    }

    fn decode<T>(&self, bytes: &[u8]) -> std::result::Result<T, WebSocketRejection>
    where
        T: serde::de::DeserializeOwned,
    {
        if !self.accepts_accumulated(bytes.len()) {
            return Err(WebSocketRejection::connection(
                WebSocketCloseCode::MessageTooBig,
                ErrorCode::PayloadTooLarge,
                "the reassembled message exceeds the effective frame limit",
            ));
        }
        // §4 — duplicate members are rejected before schema validation. The
        // frames are schema-ordered, not canonically ordered, so this is the
        // duplicate-only ingress parser, not the canonical-bytes one.
        let value = arkret_canonical::canonical::parse_json_rejecting_duplicate_keys(bytes)
            .map_err(|error| {
                WebSocketRejection::connection(
                    WebSocketCloseCode::ProtocolError,
                    ErrorCode::InvalidParam,
                    &error.to_string(),
                )
            })?;
        serde_json::from_value(value).map_err(|error| {
            WebSocketRejection::connection(
                WebSocketCloseCode::ProtocolError,
                ErrorCode::InvalidParam,
                &error.to_string(),
            )
        })
    }

    /// Serialise one frame and refuse to emit it over the effective limit.
    pub fn encode<T>(&self, frame: &T) -> Result<String>
    where
        T: Serialize,
    {
        let encoded = serde_json::to_string(frame)?;
        if !self.accepts_accumulated(encoded.len()) {
            return Err(Error::Protocol(
                "a WebSocket frame may not be emitted over the effective frame limit".to_owned(),
            ));
        }
        Ok(encoded)
    }
}

/// What an accepted server frame meant to the receiver.
#[derive(Debug)]
pub enum WebSocketServerEvent {
    Challenge {
        connection_id: String,
        nonce: String,
        expires_at: DateTime<Utc>,
    },
    Welcome {
        limits: WebSocketConnectionLimits,
    },
    Opened {
        channel_id: String,
        operation: WebSocketOperationId,
    },
    Data {
        channel_id: String,
        payload: WebSocketDataPayload,
        /// Present only for a durable channel whose payload carried a cursor.
        observed_cursor: Option<String>,
    },
    ChannelControl {
        channel_id: String,
        payload: WebSocketChannelControlPayload,
    },
    ConnectionControl {
        payload: WebSocketConnectionControlPayload,
    },
    ChannelError {
        channel_id: String,
        error: WebSocketTransportError,
    },
    ConnectionError {
        error: WebSocketTransportError,
    },
    ChannelClosed {
        channel_id: String,
    },
    Ping {
        ping_id: String,
    },
    ReauthRequired {
        nonce: String,
    },
}

/// The outcome of admitting one client `open` frame.
#[derive(Debug)]
pub enum WebSocketOpenAdmission {
    Opened {
        channel_id: String,
        operation: WebSocketOperationId,
    },
    /// The `channel_id` was already used on this connection. §5: the id stays
    /// permanently occupied even after the channel failed or closed.
    Conflict(WebSocketRejection),
    /// `max_channels` reached. §5 forbids evicting an existing channel.
    RateLimited(WebSocketRejection),
}

/// Multiplexed connection state, driven identically by the service and by the
/// client engine.
#[derive(Debug)]
pub struct WebSocketConnectionState {
    connection_id: String,
    limits: WebSocketConnectionLimits,
    phase: WebSocketConnectionPhase,
    /// Every `channel_id` ever admitted, open or not — the reservation is
    /// permanent for the lifetime of the connection.
    channels: BTreeMap<String, WebSocketChannel>,
}

impl WebSocketConnectionState {
    pub fn new(connection_id: impl Into<String>, limits: WebSocketConnectionLimits) -> Self {
        Self {
            connection_id: connection_id.into(),
            limits,
            phase: WebSocketConnectionPhase::AwaitingAuthenticate,
            channels: BTreeMap::new(),
        }
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn limits(&self) -> WebSocketConnectionLimits {
        self.limits
    }

    pub fn phase(&self) -> WebSocketConnectionPhase {
        self.phase
    }

    /// Channels that are currently open, in `channel_id` order.
    pub fn open_channel_ids(&self) -> Vec<&str> {
        self.channels
            .values()
            .filter(|channel| channel.open)
            .map(|channel| channel.channel_id.as_str())
            .collect()
    }

    pub fn channel(&self, channel_id: &str) -> Option<&WebSocketChannel> {
        self.channels.get(channel_id).filter(|channel| channel.open)
    }

    pub fn channel_mut(&mut self, channel_id: &str) -> Option<&mut WebSocketChannel> {
        self.channels
            .get_mut(channel_id)
            .filter(|channel| channel.open)
    }

    /// A channel that was admitted and has since closed. §5 keeps its id
    /// reserved for the lifetime of the connection, and a retired durable
    /// channel still holds the resume point the receiver checkpointed, which is
    /// what the next connection reopens from.
    pub fn retired_channel(&self, channel_id: &str) -> Option<&WebSocketChannel> {
        self.channels
            .get(channel_id)
            .filter(|channel| !channel.open)
    }

    pub fn operation_for(&self, channel_id: &str) -> Option<WebSocketOperationId> {
        self.channel(channel_id).map(|channel| channel.operation)
    }

    /// `authenticate` succeeded; `welcome` may now be sent.
    pub fn authenticated(&mut self) {
        self.phase = WebSocketConnectionPhase::Authenticated;
    }

    /// `reauth_required` was sent. §3: the old authorization may still serve
    /// already-admitted channels, and nothing new is admitted.
    pub fn reauth_required(&mut self) {
        if matches!(self.phase, WebSocketConnectionPhase::Authenticated) {
            self.phase = WebSocketConnectionPhase::Reauthenticating;
        }
    }

    /// The reauth `authenticate` was accepted; channels continue.
    pub fn reauthenticated(&mut self) {
        if matches!(self.phase, WebSocketConnectionPhase::Reauthenticating) {
            self.phase = WebSocketConnectionPhase::Authenticated;
        }
    }

    /// A connection-scoped drain was sent (§8).
    pub fn draining(&mut self) {
        self.phase = WebSocketConnectionPhase::Draining;
    }

    pub fn closed(&mut self) {
        self.phase = WebSocketConnectionPhase::Closed;
        for channel in self.channels.values_mut() {
            channel.open = false;
        }
    }

    /// Service-side admission of a client `open` frame.
    pub fn admit_open(&mut self, frame: &WebSocketClientFrame) -> Result<WebSocketOpenAdmission> {
        let WebSocketClientFrame::Open {
            channel_id,
            operation_id,
            ..
        } = frame
        else {
            return Err(Error::Protocol(
                "admit_open requires an open frame".to_owned(),
            ));
        };
        frame.validate()?;
        if !matches!(self.phase, WebSocketConnectionPhase::Authenticated) {
            return Ok(WebSocketOpenAdmission::RateLimited(
                WebSocketRejection::channel(
                    channel_id,
                    ErrorCode::RateLimited,
                    "the connection is not admitting new channels",
                ),
            ));
        }
        if self.channels.contains_key(channel_id) {
            return Ok(WebSocketOpenAdmission::Conflict(
                WebSocketRejection::channel(
                    channel_id,
                    ErrorCode::Conflict,
                    "this channel_id is already used on this connection",
                ),
            ));
        }
        if self.open_channel_ids().len() >= self.limits.max_channels as usize {
            return Ok(WebSocketOpenAdmission::RateLimited(
                WebSocketRejection::channel(
                    channel_id,
                    ErrorCode::RateLimited,
                    "max_channels reached",
                ),
            ));
        }
        self.channels.insert(
            channel_id.clone(),
            WebSocketChannel {
                channel_id: channel_id.clone(),
                operation: *operation_id,
                open: true,
                durable_cursor: None,
                pending_cursor: None,
            },
        );
        Ok(WebSocketOpenAdmission::Opened {
            channel_id: channel_id.clone(),
            operation: *operation_id,
        })
    }

    /// Record a locally initiated `opened` on the client side, so the client
    /// resolves payload operations from the same table the service uses.
    pub fn record_opened(
        &mut self,
        channel_id: &str,
        operation: WebSocketOperationId,
    ) -> Result<()> {
        validate_websocket_channel_id(channel_id)?;
        if let Some(existing) = self.channels.get(channel_id) {
            if existing.operation != operation || !existing.open {
                return Err(Error::Protocol(
                    "a channel_id is never reused on one connection".to_owned(),
                ));
            }
            return Ok(());
        }
        self.channels.insert(
            channel_id.to_owned(),
            WebSocketChannel {
                channel_id: channel_id.to_owned(),
                operation,
                open: true,
                durable_cursor: None,
                pending_cursor: None,
            },
        );
        Ok(())
    }

    /// Terminate one channel. The id stays reserved.
    pub fn close_channel(&mut self, channel_id: &str) {
        if let Some(channel) = self.channels.get_mut(channel_id) {
            channel.open = false;
        }
    }

    /// Validate an inbound server frame against connection and channel state,
    /// then resolve its payload with the channel's own operation (§6).
    pub fn accept_server_frame(
        &mut self,
        frame: &WebSocketServerFrame,
    ) -> std::result::Result<WebSocketServerEvent, WebSocketRejection> {
        frame.validate().map_err(|error| {
            WebSocketRejection::connection(
                WebSocketCloseCode::ProtocolError,
                ErrorCode::InvalidParam,
                &error.to_string(),
            )
        })?;
        // §3 — before `welcome` the only admissible server frames are the
        // handshake pair itself. `open` / `data` / a business control frame
        // arriving early is a connection state violation.
        if matches!(self.phase, WebSocketConnectionPhase::AwaitingAuthenticate)
            && !matches!(
                frame,
                WebSocketServerFrame::Challenge { .. } | WebSocketServerFrame::Welcome { .. }
            )
        {
            return Err(WebSocketRejection::connection(
                WebSocketCloseCode::ProtocolError,
                ErrorCode::InvalidParam,
                "no business frame may cross before welcome",
            ));
        }

        match frame {
            WebSocketServerFrame::Challenge {
                connection_id,
                nonce,
                expires_at,
            } => {
                // §3 — exactly one challenge opens the connection. A second one
                // in any later phase is a state violation.
                if !matches!(self.phase, WebSocketConnectionPhase::AwaitingAuthenticate) {
                    return Err(WebSocketRejection::connection(
                        WebSocketCloseCode::ProtocolError,
                        ErrorCode::InvalidParam,
                        "a second challenge is not part of the connection lifecycle",
                    ));
                }
                if connection_id != &self.connection_id {
                    return Err(WebSocketRejection::connection(
                        WebSocketCloseCode::ProtocolError,
                        ErrorCode::InvalidParam,
                        "challenge connection_id does not match this connection",
                    ));
                }
                Ok(WebSocketServerEvent::Challenge {
                    connection_id: connection_id.clone(),
                    nonce: nonce.clone(),
                    expires_at: *expires_at,
                })
            }
            WebSocketServerFrame::Welcome { connection_id, .. } => {
                if connection_id != &self.connection_id {
                    return Err(WebSocketRejection::connection(
                        WebSocketCloseCode::ProtocolError,
                        ErrorCode::InvalidParam,
                        "welcome connection_id does not match the challenge",
                    ));
                }
                let limits = frame
                    .connection_limits()
                    .expect("the welcome variant always carries limits");
                self.limits = limits;
                self.authenticated();
                Ok(WebSocketServerEvent::Welcome { limits })
            }
            WebSocketServerFrame::Opened {
                channel_id,
                operation_id,
            } => {
                self.record_opened(channel_id, *operation_id)
                    .map_err(|error| {
                        WebSocketRejection::connection(
                            WebSocketCloseCode::ProtocolError,
                            ErrorCode::InvalidParam,
                            &error.to_string(),
                        )
                    })?;
                Ok(WebSocketServerEvent::Opened {
                    channel_id: channel_id.clone(),
                    operation: *operation_id,
                })
            }
            WebSocketServerFrame::Data {
                channel_id,
                payload,
            } => {
                let operation = self.require_open_channel(channel_id)?;
                let payload = WebSocketDataPayload::parse(operation, payload)
                    .map_err(|error| Self::channel_payload_rejection(channel_id, &error))?;
                let observed_cursor = operation
                    .is_durable()
                    .then(|| data_payload_cursor(&payload))
                    .flatten();
                if let Some(cursor) = &observed_cursor
                    && let Some(channel) = self.channel_mut(channel_id)
                {
                    channel.pending_cursor = Some(cursor.clone());
                }
                Ok(WebSocketServerEvent::Data {
                    channel_id: channel_id.clone(),
                    payload,
                    observed_cursor,
                })
            }
            WebSocketServerFrame::Control {
                frame_scope,
                channel_id,
                payload,
            } => match frame_scope {
                WebSocketFrameScope::Connection => {
                    let payload: WebSocketConnectionControlPayload =
                        serde_json::from_value(payload.clone()).map_err(|error| {
                            WebSocketRejection::connection(
                                WebSocketCloseCode::ProtocolError,
                                ErrorCode::InvalidParam,
                                &error.to_string(),
                            )
                        })?;
                    self.draining();
                    Ok(WebSocketServerEvent::ConnectionControl { payload })
                }
                WebSocketFrameScope::Channel => {
                    let channel_id = channel_id
                        .as_deref()
                        .expect("frame validation required channel_id");
                    let operation = self.require_open_channel(channel_id)?;
                    let payload = WebSocketChannelControlPayload::parse(operation, payload)
                        .map_err(|error| Self::channel_payload_rejection(channel_id, &error))?;
                    // §6 — connection-level ping/pong and channel control never
                    // advance a business cursor; only a cursor-bearing durable
                    // control payload does.
                    if let Some(cursor) = operation
                        .is_durable()
                        .then(|| channel_control_cursor(&payload))
                        .flatten()
                        && let Some(channel) = self.channel_mut(channel_id)
                    {
                        channel.pending_cursor = Some(cursor);
                    }
                    Ok(WebSocketServerEvent::ChannelControl {
                        channel_id: channel_id.to_owned(),
                        payload,
                    })
                }
            },
            WebSocketServerFrame::Error {
                frame_scope,
                channel_id,
                error,
            } => match frame_scope {
                WebSocketFrameScope::Connection => Ok(WebSocketServerEvent::ConnectionError {
                    error: error.clone(),
                }),
                WebSocketFrameScope::Channel => {
                    let channel_id = channel_id
                        .as_deref()
                        .expect("frame validation required channel_id");
                    self.require_open_channel(channel_id)?;
                    Ok(WebSocketServerEvent::ChannelError {
                        channel_id: channel_id.to_owned(),
                        error: error.clone(),
                    })
                }
            },
            WebSocketServerFrame::Closed { channel_id, .. } => {
                self.close_channel(channel_id);
                Ok(WebSocketServerEvent::ChannelClosed {
                    channel_id: channel_id.clone(),
                })
            }
            WebSocketServerFrame::Ping { ping_id, .. } => Ok(WebSocketServerEvent::Ping {
                ping_id: ping_id.clone(),
            }),
            WebSocketServerFrame::ReauthRequired { nonce, .. } => {
                self.reauth_required();
                Ok(WebSocketServerEvent::ReauthRequired {
                    nonce: nonce.clone(),
                })
            }
        }
    }

    fn require_open_channel(
        &self,
        channel_id: &str,
    ) -> std::result::Result<WebSocketOperationId, WebSocketRejection> {
        self.operation_for(channel_id).ok_or_else(|| {
            // §4 — a frame naming a channel that was never opened is a
            // connection state violation, not a channel-level error.
            WebSocketRejection::connection(
                WebSocketCloseCode::ProtocolError,
                ErrorCode::InvalidParam,
                "frame names a channel that is not open on this connection",
            )
        })
    }

    /// §6 — a payload that does not match the channel's operation kills that
    /// channel (`error` then `closed`) and leaves the connection open.
    fn channel_payload_rejection(channel_id: &str, error: &Error) -> WebSocketRejection {
        WebSocketRejection::channel(channel_id, ErrorCode::InvalidParam, &error.to_string())
    }
}

fn data_payload_cursor(payload: &WebSocketDataPayload) -> Option<String> {
    match payload {
        WebSocketDataPayload::Account(frame) => frame.cursor.clone(),
        WebSocketDataPayload::Events(frame) => frame
            .cursor
            .as_ref()
            .map(|cursor| cursor.as_str().to_owned()),
        WebSocketDataPayload::Signal(_) => None,
    }
}

fn channel_control_cursor(payload: &WebSocketChannelControlPayload) -> Option<String> {
    // Only the frontier / catch-up family carries a resume point; heartbeat,
    // dropped, resync_required and unauthorized never advance one.
    let (kind, cursor) = match payload {
        WebSocketChannelControlPayload::Account(frame) => {
            (frame.trace_kind(), frame.trace_cursor().map(str::to_owned))
        }
        WebSocketChannelControlPayload::Events(frame) => {
            (frame.trace_kind(), frame.trace_cursor().map(str::to_owned))
        }
        WebSocketChannelControlPayload::Signal(_) => return None,
    };
    matches!(
        kind,
        StreamTraceFrameKind::Frontier | StreamTraceFrameKind::CatchupComplete
    )
    .then_some(cursor)
    .flatten()
}

// ── Transport selection (§8.1) ──────────────────────────────────────────────

/// A handshake failure that is decided before any Arkret frame crosses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebSocketHandshakeFailure {
    /// The Upgrade response status was not `101`.
    UpgradeStatusNotSwitchingProtocols,
    /// The server did not select the `arkret.v1` subprotocol.
    SubprotocolNotSelected,
    /// An intermediary refused or stripped the upgrade.
    ProxyBlocked,
}

/// What the client does after a connection ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebSocketTransportDecision {
    /// Reconnect the WebSocket after honouring this delay.
    RetryWebSocket { after_ms: u32 },
    /// Terminate every channel and use canonical HTTP/JSON + bounded NDJSON
    /// until the descriptor changes or the user retries explicitly.
    FallbackHttp,
}

/// §8.1 retry budget. `1008` buys exactly one fresh-grant, fresh-socket retry;
/// `1001` / `1012` allow three attempts that never reach `welcome`; everything
/// else goes straight to HTTP.
#[derive(Clone, Copy, Debug, Default)]
pub struct WebSocketFallbackPolicy {
    policy_retries_used: u8,
    restart_attempts_without_welcome: u8,
}

/// §8.1 — attempts allowed before falling back.
pub const WEBSOCKET_POLICY_FAILURE_RETRIES: u8 = 1;
pub const WEBSOCKET_RESTART_ATTEMPTS: u8 = 3;

impl WebSocketFallbackPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// A connection reached `welcome`: both budgets reset.
    pub fn welcomed(&mut self) {
        self.policy_retries_used = 0;
        self.restart_attempts_without_welcome = 0;
    }

    /// An upgrade / proxy / subprotocol failure never gets a WebSocket retry.
    pub fn on_handshake_failure(
        &mut self,
        _failure: WebSocketHandshakeFailure,
    ) -> WebSocketTransportDecision {
        WebSocketTransportDecision::FallbackHttp
    }

    /// Decide the next transport from the close code.
    ///
    /// `drain_reconnect_after_ms` is the value of the last connection-scoped
    /// drain control, if one arrived; §8 requires it to be honoured before any
    /// reconnect to the same endpoint.
    pub fn on_close(
        &mut self,
        code: WebSocketCloseCode,
        drain_reconnect_after_ms: Option<u32>,
    ) -> WebSocketTransportDecision {
        match code {
            WebSocketCloseCode::Normal => WebSocketTransportDecision::RetryWebSocket {
                after_ms: drain_reconnect_after_ms.unwrap_or(0),
            },
            WebSocketCloseCode::GoingAway | WebSocketCloseCode::ServiceRestart => {
                self.restart_attempts_without_welcome =
                    self.restart_attempts_without_welcome.saturating_add(1);
                if self.restart_attempts_without_welcome >= WEBSOCKET_RESTART_ATTEMPTS {
                    return WebSocketTransportDecision::FallbackHttp;
                }
                WebSocketTransportDecision::RetryWebSocket {
                    after_ms: drain_reconnect_after_ms.unwrap_or(0),
                }
            }
            WebSocketCloseCode::PolicyViolation => {
                if self.policy_retries_used >= WEBSOCKET_POLICY_FAILURE_RETRIES {
                    return WebSocketTransportDecision::FallbackHttp;
                }
                self.policy_retries_used += 1;
                WebSocketTransportDecision::RetryWebSocket { after_ms: 0 }
            }
            WebSocketCloseCode::InternalError => WebSocketTransportDecision::FallbackHttp,
            WebSocketCloseCode::ProtocolError | WebSocketCloseCode::MessageTooBig => {
                WebSocketTransportDecision::FallbackHttp
            }
        }
    }
}

/// Which transport currently owns the account / events / Signal consumers.
///
/// §8 forbids holding both at once. The switch is an ordered handoff: the old
/// owner stops, durable cursors are persisted, only then the new owner starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WebSocketConsumerOwner {
    #[default]
    None,
    WebSocket,
    Http,
}

/// Single-owner guard for the transport handoff.
#[derive(Clone, Copy, Debug, Default)]
pub struct WebSocketConsumerHandoff {
    owner: WebSocketConsumerOwner,
    old_owner_stopped: bool,
    cursors_persisted: bool,
}

impl WebSocketConsumerHandoff {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn owner(&self) -> WebSocketConsumerOwner {
        self.owner
    }

    /// Start the first owner. Fails if one is already running.
    pub fn start(&mut self, owner: WebSocketConsumerOwner) -> Result<()> {
        if !matches!(self.owner, WebSocketConsumerOwner::None) {
            return Err(Error::Protocol(
                "a second stream consumer may not start while one is running".to_owned(),
            ));
        }
        self.owner = owner;
        self.old_owner_stopped = false;
        self.cursors_persisted = false;
        Ok(())
    }

    /// Terminate the current owner: every channel is closed and the physical
    /// connection, if any, is confirmed gone.
    pub fn stop(&mut self) {
        self.owner = WebSocketConsumerOwner::None;
        self.old_owner_stopped = true;
    }

    /// Record that every durable cursor the old owner produced is on disk.
    pub fn persist_cursors(&mut self) {
        self.cursors_persisted = true;
    }

    /// Hand ownership to the other transport.
    pub fn switch_to(&mut self, owner: WebSocketConsumerOwner) -> Result<()> {
        if !self.old_owner_stopped {
            return Err(Error::Protocol(
                "the previous stream owner must be terminated before the switch".to_owned(),
            ));
        }
        if !self.cursors_persisted {
            return Err(Error::Protocol(
                "durable cursors must be persisted before the switch".to_owned(),
            ));
        }
        self.owner = owner;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_frames::websocket_binding::{WebSocketClosedReason, WebSocketOpenParameters};

    fn limits() -> WebSocketConnectionLimits {
        WebSocketConnectionLimits {
            max_frame_bytes: 2048,
            max_channels: 16,
            max_connection_pending_bytes: 65_536,
            max_channel_pending_bytes: 16_384,
            max_connection_pending_frames: 128,
            max_channel_pending_frames: 32,
            heartbeat_interval_ms: 30_000,
        }
    }

    fn authenticated() -> WebSocketConnectionState {
        let mut state =
            WebSocketConnectionState::new("Y29ubmVjdGlvbi0wMTIzNDU2Nzg5YWJjZGVm", limits());
        state.authenticated();
        state
    }

    #[test]
    fn a_channel_id_is_never_reusable_after_it_closed() {
        let mut state = authenticated();
        let open = WebSocketClientFrame::open(
            "events-1",
            &WebSocketOpenParameters::Events(
                crate::sync_frames::websocket_binding::WebSocketEventsOpenParameters {
                    realms: Some(vec![
                        RealmId::new("ak:realm:0196419b-0000-8000-8000-000000000001").unwrap(),
                    ]),
                    ..Default::default()
                },
            ),
        )
        .unwrap();
        assert!(matches!(
            state.admit_open(&open).unwrap(),
            WebSocketOpenAdmission::Opened { .. }
        ));
        state
            .accept_server_frame(&WebSocketServerFrame::Closed {
                channel_id: "events-1".to_owned(),
                reason: WebSocketClosedReason::Error,
            })
            .unwrap();
        assert!(matches!(
            state.admit_open(&open).unwrap(),
            WebSocketOpenAdmission::Conflict(_)
        ));
    }

    #[test]
    fn one_channel_failure_leaves_its_siblings_open() {
        let mut state = authenticated();
        state
            .record_opened("account-1", WebSocketOperationId::AccountStreamSubscribe)
            .unwrap();
        state
            .record_opened("signal-1", WebSocketOperationId::SignalStreamSubscribe)
            .unwrap();
        state
            .record_opened("events-1", WebSocketOperationId::EventsStreamSubscribe)
            .unwrap();

        // An events control payload on the Signal channel kills only that
        // channel; the connection and the other two channels survive.
        let rejection = state
            .accept_server_frame(&WebSocketServerFrame::Control {
                frame_scope: WebSocketFrameScope::Channel,
                channel_id: Some("signal-1".to_owned()),
                payload: serde_json::json!({
                    "kind": "frontier",
                    "cursor": "ak:cursor:ZXZlbnRzLWN1cnNvci0wMDAx",
                }),
            })
            .expect_err("a foreign payload must not be admitted");
        assert!(!rejection.is_connection_scoped());
        state.close_channel("signal-1");
        assert_eq!(state.open_channel_ids(), ["account-1", "events-1"]);
    }

    #[test]
    fn a_frame_on_an_unopened_channel_is_a_connection_error() {
        let mut state = authenticated();
        let rejection = state
            .accept_server_frame(&WebSocketServerFrame::Data {
                channel_id: "never-opened".to_owned(),
                payload: serde_json::json!({
                    "kind": "delta",
                    "cursor": "ak:cursor:YWNjountY3Vyc29yLTAwMDE",
                }),
            })
            .expect_err("an unopened channel is a state violation");
        assert_eq!(
            rejection.close_code,
            Some(WebSocketCloseCode::ProtocolError)
        );
    }

    #[test]
    fn only_durable_channels_carry_a_cursor() {
        let mut state = authenticated();
        state
            .record_opened("account-1", WebSocketOperationId::AccountStreamSubscribe)
            .unwrap();
        state
            .record_opened("signal-1", WebSocketOperationId::SignalStreamSubscribe)
            .unwrap();
        state
            .accept_server_frame(&WebSocketServerFrame::Data {
                channel_id: "account-1".to_owned(),
                payload: serde_json::json!({
                    "kind": "delta",
                    "cursor": "ak:cursor:YWNjountY3Vyc29yLTAwMDE",
                }),
            })
            .unwrap();
        assert_eq!(
            state
                .channel_mut("account-1")
                .expect("account channel")
                .checkpoint(),
            Some("ak:cursor:YWNjountY3Vyc29yLTAwMDE")
        );
        state
            .accept_server_frame(&WebSocketServerFrame::Control {
                frame_scope: WebSocketFrameScope::Channel,
                channel_id: Some("signal-1".to_owned()),
                payload: serde_json::json!({"kind": "heartbeat"}),
            })
            .unwrap();
        let signal = state.channel("signal-1").expect("signal channel");
        assert_eq!(signal.durable_cursor, None);
        assert_eq!(signal.pending_cursor, None);
    }

    #[test]
    fn the_retry_budget_matches_the_close_code_table() {
        let mut policy = WebSocketFallbackPolicy::new();
        assert_eq!(
            policy.on_close(WebSocketCloseCode::ProtocolError, None),
            WebSocketTransportDecision::FallbackHttp
        );
        assert_eq!(
            policy.on_close(WebSocketCloseCode::MessageTooBig, None),
            WebSocketTransportDecision::FallbackHttp
        );

        let mut policy = WebSocketFallbackPolicy::new();
        assert_eq!(
            policy.on_close(WebSocketCloseCode::PolicyViolation, None),
            WebSocketTransportDecision::RetryWebSocket { after_ms: 0 }
        );
        assert_eq!(
            policy.on_close(WebSocketCloseCode::PolicyViolation, None),
            WebSocketTransportDecision::FallbackHttp
        );

        let mut policy = WebSocketFallbackPolicy::new();
        assert_eq!(
            policy.on_close(WebSocketCloseCode::GoingAway, Some(5_000)),
            WebSocketTransportDecision::RetryWebSocket { after_ms: 5_000 }
        );
        let mut policy = WebSocketFallbackPolicy::new();
        for _ in 0..2 {
            assert!(matches!(
                policy.on_close(WebSocketCloseCode::ServiceRestart, None),
                WebSocketTransportDecision::RetryWebSocket { .. }
            ));
        }
        assert_eq!(
            policy.on_close(WebSocketCloseCode::ServiceRestart, None),
            WebSocketTransportDecision::FallbackHttp
        );
    }

    #[test]
    fn the_transport_switch_never_runs_two_owners() {
        let mut handoff = WebSocketConsumerHandoff::new();
        handoff.start(WebSocketConsumerOwner::WebSocket).unwrap();
        handoff
            .start(WebSocketConsumerOwner::Http)
            .expect_err("a second owner must not start");
        handoff
            .switch_to(WebSocketConsumerOwner::Http)
            .expect_err("the old owner is still running");
        handoff.stop();
        handoff
            .switch_to(WebSocketConsumerOwner::Http)
            .expect_err("cursors are not persisted yet");
        handoff.persist_cursors();
        handoff.switch_to(WebSocketConsumerOwner::Http).unwrap();
        assert_eq!(handoff.owner(), WebSocketConsumerOwner::Http);
    }
}
