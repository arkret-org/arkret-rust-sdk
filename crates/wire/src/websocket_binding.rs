//! `ak.profile.binding.websocket.v1` connection-level primitives
//! (`zh/sync/websocket-binding.md`).
//!
//! This module owns everything the WebSocket binding needs that does **not**
//! reference an operation payload: the profile constants, the canonical `wss`
//! discovery URI form, the RFC 6454 origin canonicalisation, the closed
//! `challenge_dpop_session_v1` proof shapes, the server-side challenge record
//! and replay-ledger key, the closed transport error body and the RFC 6455
//! close-code table.
//!
//! The connection frames themselves live in
//! `arkret-models-collaboration` because their `data` / `control` payloads are
//! the canonical account, events and Signal frames. Proof signing and
//! verification live in `arkret-signatures`; this crate stays free of crypto
//! dependencies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{BindingKind, DomainSeparationId, ErrorCode, Result, WireError};

/// `supported_bindings[].kind` of this profile, as registered in
/// `binding-kind-registry.json`. A media / SFU WebSocket MUST NOT reuse it.
pub const WEBSOCKET_BINDING_KIND: BindingKind = BindingKind::Websocket;

/// WebSocket subprotocol the client MUST request and the server MUST select
/// (§2). A connection whose negotiated subprotocol is anything else is not an
/// Arkret sync binding and MUST be closed.
pub const WEBSOCKET_SUBPROTOCOL: &str = "arkret.v1";

/// `authentication` discriminator advertised by the discovery descriptor (§2)
/// and the only validator context that may accept
/// [`WEBSOCKET_AUTH_METHOD_TOKEN`] / a `wss` `htu` (§3.1).
pub const WEBSOCKET_AUTHENTICATION: &str = "challenge_dpop_session_v1";

/// `htm` of the `challenge_dpop_session_v1` proof (§3.1). It is an application
/// method token, not an HTTP method: a generic RFC 9449 HTTP DPoP verifier
/// MUST NOT accept it.
pub const WEBSOCKET_AUTH_METHOD_TOKEN: &str = "ARKRET-WEBSOCKET-AUTH";

/// Third component of the replay ledger key `(cnf.jkt, jti, context)` (§3.1).
///
/// Registered in `proof-context-registry.json` `domain_separations[]` as a
/// `replay_cache_namespace` primitive — it partitions the replay ledger and is
/// never a signing transcript, so it MUST NOT be spelled as a proof context.
pub const WEBSOCKET_AUTH_REPLAY_CONTEXT: &str = DomainSeparationId::WEBSOCKET_AUTH_V1;

/// Hard ceiling on one reassembled text message, independent of what discovery
/// or `welcome` advertise (§4). The effective limit is the minimum of the
/// three; exceeding it closes with [`WebSocketCloseCode::MessageTooBig`].
pub const WEBSOCKET_HARD_MAX_FRAME_BYTES: usize = 1_048_576;

/// Deadline between `challenge` and `authenticate` (§3). Also the maximum
/// `expires_at - issued_at` of a challenge record.
pub const WEBSOCKET_AUTHENTICATION_DEADLINE_MS: u64 = 5_000;

/// Minimum retention of the replay ledger entry and of the consumed challenge
/// record past its `expires_at` (§3.1), so replay and unknown stay
/// distinguishable.
pub const WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS: u64 = 300;

/// Maximum UTF-8 length of the discovery `base_url` / proof `htu` (§2).
pub const WEBSOCKET_MAX_BASE_URL_BYTES: usize = 2048;

/// Maximum UTF-8 length of an `authenticate.session_grant` (§3.1). The lower
/// bound is 1: the token is opaque visible ASCII so `ASCII(...)` is unique.
pub const WEBSOCKET_MAX_SESSION_GRANT_BYTES: usize = 16_384;

/// The three operations the first version of this profile covers (§1).
///
/// The set is closed and complete: a descriptor that lists a subset is not
/// this profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum WebSocketOperationId {
    AccountStreamSubscribe,
    EventsStreamSubscribe,
    SignalStreamSubscribe,
}

impl WebSocketOperationId {
    /// Every covered operation, in the order the profile registers them.
    pub const ALL: &'static [Self] = &[
        Self::AccountStreamSubscribe,
        Self::EventsStreamSubscribe,
        Self::SignalStreamSubscribe,
    ];

    /// The canonical operation id, taken from the generated registry so this
    /// profile never grows a second spelling of the same operation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountStreamSubscribe => {
                crate::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE
            }
            Self::EventsStreamSubscribe => crate::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
            Self::SignalStreamSubscribe => crate::ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|operation| operation.as_str() == value)
    }

    /// Signal is the only covered operation without a durable cursor (§6.2).
    pub const fn is_durable(self) -> bool {
        !matches!(self, Self::SignalStreamSubscribe)
    }
}

impl std::fmt::Display for WebSocketOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<WebSocketOperationId> for String {
    fn from(value: WebSocketOperationId) -> Self {
        value.as_str().to_owned()
    }
}

impl TryFrom<String> for WebSocketOperationId {
    type Error = WireError;

    fn try_from(value: String) -> Result<Self> {
        Self::from_wire(&value).ok_or_else(|| {
            WireError::Protocol(format!(
                "{value} is not covered by ak.profile.binding.websocket.v1"
            ))
        })
    }
}

/// RFC 6455 close codes this binding uses (§8.1). No private `4xxx` code is
/// registered, so this enum is the complete set an implementation may send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
pub enum WebSocketCloseCode {
    /// Both sides finished the physical connection normally.
    Normal,
    /// Drain was sent and its deadline arrived; the service is stopping.
    GoingAway,
    /// Binary frame, JSON/UTF-8/duplicate/unknown/direction/schema/state or
    /// subprotocol protocol error.
    ProtocolError,
    /// Origin, challenge, proof, grant, reauth or connection-level
    /// authorization failure.
    PolicyViolation,
    /// The reassembled text message exceeded the effective byte limit.
    MessageTooBig,
    /// Internal failure; connection state can no longer be guaranteed.
    InternalError,
    /// Service restart.
    ServiceRestart,
}

impl WebSocketCloseCode {
    pub const ALL: &'static [Self] = &[
        Self::Normal,
        Self::GoingAway,
        Self::ProtocolError,
        Self::PolicyViolation,
        Self::MessageTooBig,
        Self::InternalError,
        Self::ServiceRestart,
    ];

    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::GoingAway => 1001,
            Self::ProtocolError => 1002,
            Self::PolicyViolation => 1008,
            Self::MessageTooBig => 1009,
            Self::InternalError => 1011,
            Self::ServiceRestart => 1012,
        }
    }

    pub fn from_u16(code: u16) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|known| known.as_u16() == code)
    }

    /// §8.1 — `1002` / `1009` mean the binding itself is incompatible: the
    /// client terminates every channel and switches to HTTP until the
    /// descriptor changes or the user retries explicitly.
    pub const fn forces_http_fallback(self) -> bool {
        matches!(self, Self::ProtocolError | Self::MessageTooBig)
    }
}

impl From<WebSocketCloseCode> for u16 {
    fn from(value: WebSocketCloseCode) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for WebSocketCloseCode {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self> {
        Self::from_u16(value).ok_or_else(|| {
            WireError::Protocol(format!(
                "WebSocket close code {value} is not registered by ak.profile.binding.websocket.v1"
            ))
        })
    }
}

/// Closed transport error body carried by an `error` frame (§8).
///
/// This is deliberately **not** the HTTP `ErrorEnvelope`: it has three members
/// and its `code` must resolve to a registered [`ErrorCode`], so an unknown
/// code fails closed at parse time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketTransportError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
}

/// Maximum `message` length of [`WebSocketTransportError`] (schema
/// `maxLength`, counted in code points).
pub const WEBSOCKET_MAX_ERROR_MESSAGE_CHARS: usize = 1024;

/// Maximum `retry_after_ms` / `reconnect_after_ms` any binding frame may carry.
pub const WEBSOCKET_MAX_RETRY_AFTER_MS: u32 = 300_000;

impl WebSocketTransportError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    pub fn with_retry_after_ms(mut self, retry_after_ms: u32) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.message.is_empty()
            || self.message.chars().count() > WEBSOCKET_MAX_ERROR_MESSAGE_CHARS
        {
            return Err(WireError::Protocol(format!(
                "WebSocket error message must be 1..={WEBSOCKET_MAX_ERROR_MESSAGE_CHARS} characters"
            )));
        }
        if self
            .retry_after_ms
            .is_some_and(|value| value > WEBSOCKET_MAX_RETRY_AFTER_MS)
        {
            return Err(WireError::Protocol(format!(
                "WebSocket error retry_after_ms exceeds {WEBSOCKET_MAX_RETRY_AFTER_MS}"
            )));
        }
        Ok(())
    }
}

// ── Canonical identifiers ───────────────────────────────────────────────────

/// `connection_id` and `nonce` share one shape: 22..128 base64url characters,
/// i.e. at least 128 bits of entropy when generated (§3.1).
pub const WEBSOCKET_OPAQUE_ID_MIN_CHARS: usize = 22;
pub const WEBSOCKET_OPAQUE_ID_MAX_CHARS: usize = 128;
/// `ping_id` uses a shorter floor (schema `ping`/`pong`).
pub const WEBSOCKET_PING_ID_MIN_CHARS: usize = 16;
/// `channel_id` is a client-generated 1..64 character opaque token (§4).
pub const WEBSOCKET_CHANNEL_ID_MAX_CHARS: usize = 64;

fn is_base64url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

fn validate_base64url_token(value: &str, min: usize, max: usize, field: &str) -> Result<()> {
    let length = value.chars().count();
    if length < min || length > max || !value.chars().all(is_base64url_char) {
        return Err(WireError::Protocol(format!(
            "WebSocket {field} must be {min}..={max} base64url characters"
        )));
    }
    Ok(())
}

/// Validate a `connection_id` or a challenge `nonce`.
pub fn validate_websocket_opaque_id(value: &str, field: &str) -> Result<()> {
    validate_base64url_token(
        value,
        WEBSOCKET_OPAQUE_ID_MIN_CHARS,
        WEBSOCKET_OPAQUE_ID_MAX_CHARS,
        field,
    )
}

/// Validate a `ping_id`.
pub fn validate_websocket_ping_id(value: &str) -> Result<()> {
    validate_base64url_token(
        value,
        WEBSOCKET_PING_ID_MIN_CHARS,
        WEBSOCKET_OPAQUE_ID_MAX_CHARS,
        "ping_id",
    )
}

/// Validate a `channel_id`. The alphabet is the URI unreserved set, so a
/// channel id can never be confused with a cursor or a typed id.
pub fn validate_websocket_channel_id(value: &str) -> Result<()> {
    let length = value.chars().count();
    let allowed = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '~' | '-'));
    if length == 0 || length > WEBSOCKET_CHANNEL_ID_MAX_CHARS || !allowed {
        return Err(WireError::Protocol(format!(
            "WebSocket channel_id must be 1..={WEBSOCKET_CHANNEL_ID_MAX_CHARS} unreserved characters"
        )));
    }
    Ok(())
}

/// Validate an `authenticate.session_grant` (§3.1): 1..16384 visible ASCII
/// bytes. The server MUST NOT normalise, trim or re-encode it before hashing.
pub fn validate_websocket_session_grant(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > WEBSOCKET_MAX_SESSION_GRANT_BYTES
        || !value.bytes().all(|byte| (0x21..=0x7E).contains(&byte))
    {
        return Err(WireError::Protocol(format!(
            "WebSocket session_grant must be 1..={WEBSOCKET_MAX_SESSION_GRANT_BYTES} visible ASCII bytes"
        )));
    }
    Ok(())
}

// ── Canonical discovery URI ─────────────────────────────────────────────────

/// Validate the canonical `wss` form required of the discovery `base_url` and
/// of the proof `htu` (§2).
///
/// The check is deliberately performed on the **verbatim** string rather than
/// on a re-serialised `Url`: the profile requires the advertised bytes to
/// already be canonical, so normalising first would accept exactly the inputs
/// it exists to reject (`:443`, uppercase host, dot segments, query).
pub fn validate_websocket_base_url(input: &str) -> Result<()> {
    let reject = |reason: &str| -> WireError {
        WireError::Protocol(format!(
            "WebSocket base_url is not the canonical wss form: {reason}"
        ))
    };
    if input.len() > WEBSOCKET_MAX_BASE_URL_BYTES {
        return Err(reject("longer than 2048 bytes"));
    }
    let Some(rest) = input.strip_prefix("wss://") else {
        return Err(reject("scheme must be the lowercase literal wss"));
    };
    if rest.contains('?') || rest.contains('#') {
        return Err(reject("query and fragment are forbidden"));
    }
    let Some(path_start) = rest.find('/') else {
        return Err(reject("path must be a non-empty absolute path"));
    };
    let (authority, path) = rest.split_at(path_start);
    if authority.contains('@') {
        return Err(reject("userinfo is forbidden"));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() || host.ends_with('.') {
        return Err(reject(
            "host must be a non-empty A-label without a trailing dot",
        ));
    }
    if !host
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-')
    {
        return Err(reject("host must be a lowercase A-label"));
    }
    if host.split('.').any(str::is_empty) {
        return Err(reject("host must not contain an empty label"));
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(reject("port must be decimal digits"));
        }
        if port.starts_with('0') {
            return Err(reject("port must not have a leading zero"));
        }
        let value: u32 = port.parse().map_err(|_| reject("port is out of range"))?;
        if value == 443 {
            return Err(reject("the default port 443 must be omitted"));
        }
        if value == 0 || value > 65_535 {
            return Err(reject("port is out of range"));
        }
    }
    validate_websocket_base_url_path(path).map_err(|reason| reject(&reason))
}

fn validate_websocket_base_url_path(path: &str) -> std::result::Result<(), String> {
    if path.len() < 2 {
        return Err("path must be a non-empty absolute path".to_owned());
    }
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let high = chars.next().ok_or("truncated percent-encoding")?;
            let low = chars.next().ok_or("truncated percent-encoding")?;
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return Err("percent-encoding must be two hex digits".to_owned());
            }
            if high.is_ascii_lowercase() || low.is_ascii_lowercase() {
                return Err("percent-encoding must use uppercase hex".to_owned());
            }
            let byte = u8::from_str_radix(&format!("{high}{low}"), 16)
                .map_err(|_| "percent-encoding must be two hex digits".to_owned())?;
            if is_uri_unreserved(byte) {
                return Err("unreserved characters must not be percent-encoded".to_owned());
            }
            continue;
        }
        let allowed = ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '-' | '.'
                    | '_'
                    | '~'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | ':'
                    | '@'
                    | '/'
            );
        if !allowed {
            return Err(format!("path character {ch:?} is not allowed"));
        }
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("dot segments must be removed".to_owned());
    }
    Ok(())
}

const fn is_uri_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// RFC 6454 serialization of an HTTP `Origin` header value (§3).
///
/// Returns the canonical `scheme://host[:port]` form with a lowercase scheme
/// and host and the default port removed. `null`, an opaque origin, an origin
/// carrying a path and a syntactically invalid value are all rejected: the
/// profile defines no origin-less native bypass.
pub fn canonical_http_origin(input: &str) -> Result<String> {
    let reject = |reason: &str| -> WireError {
        WireError::Protocol(format!("WebSocket Origin is not acceptable: {reason}"))
    };
    if input == "null" {
        return Err(reject("the null origin is rejected"));
    }
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| reject("origin must be scheme://host[:port]"))?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443_u32,
        "http" => 80,
        _ => return Err(reject("origin scheme must be http or https")),
    };
    if rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
        return Err(reject(
            "origin must not carry userinfo, path, query or fragment",
        ));
    }
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    if host.is_empty() || host.ends_with('.') {
        return Err(reject("origin host must be a non-empty A-label"));
    }
    let host = host.to_ascii_lowercase();
    if !host
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-')
    {
        return Err(reject("origin host must be an A-label"));
    }
    let port = match port {
        None => None,
        Some(port) => {
            let value: u32 = port
                .parse()
                .map_err(|_| reject("origin port must be decimal digits"))?;
            if value == 0 || value > 65_535 {
                return Err(reject("origin port is out of range"));
            }
            (value != default_port).then_some(value)
        }
    };
    Ok(match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

// ── challenge_dpop_session_v1 proof shapes ──────────────────────────────────

/// `kty` of the holder key. The profile registers exactly one value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketDpopKeyType {
    #[default]
    #[serde(rename = "OKP")]
    Okp,
}

/// `crv` of the holder key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketDpopCurve {
    #[default]
    Ed25519,
}

/// `alg` of the proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketDpopAlgorithm {
    #[default]
    Ed25519,
}

/// `typ` of the proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketDpopType {
    #[default]
    #[serde(rename = "dpop+jwt")]
    DpopJwt,
}

/// Public holder JWK embedded in the protected header
/// (`ak.schema.websocket_dpop_protected_header.v1`).
///
/// The shape is closed: no `kid`, no `x5*`, no private member. `x` is the
/// 43-character base64url Ed25519 public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketDpopPublicJwk {
    pub kty: WebSocketDpopKeyType,
    pub crv: WebSocketDpopCurve,
    pub x: String,
}

/// Length of a base64url-encoded 32-byte Ed25519 public key / SHA-256 digest.
pub const WEBSOCKET_BASE64URL_32_BYTE_CHARS: usize = 43;

impl WebSocketDpopPublicJwk {
    pub fn new(x: impl Into<String>) -> Self {
        Self {
            kty: WebSocketDpopKeyType::Okp,
            crv: WebSocketDpopCurve::Ed25519,
            x: x.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_base64url_token(
            &self.x,
            WEBSOCKET_BASE64URL_32_BYTE_CHARS,
            WEBSOCKET_BASE64URL_32_BYTE_CHARS,
            "dpop_proof jwk x",
        )
    }
}

/// Decoded protected header of the `challenge_dpop_session_v1` proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketDpopProtectedHeader {
    pub typ: WebSocketDpopType,
    pub alg: WebSocketDpopAlgorithm,
    pub jwk: WebSocketDpopPublicJwk,
}

impl WebSocketDpopProtectedHeader {
    pub fn new(jwk: WebSocketDpopPublicJwk) -> Self {
        Self {
            typ: WebSocketDpopType::DpopJwt,
            alg: WebSocketDpopAlgorithm::Ed25519,
            jwk,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.jwk.validate()
    }
}

/// Decoded claims of the `challenge_dpop_session_v1` proof.
///
/// `htm` and `htu` are typed as plain strings so a wrong value is a validation
/// failure rather than a parse failure, which is what the negative fixture
/// cases distinguish; [`WebSocketDpopClaims::validate`] closes both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketDpopClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub ath: String,
    pub nonce: String,
}

impl WebSocketDpopClaims {
    pub fn validate(&self) -> Result<()> {
        validate_base64url_token(
            &self.jti,
            WEBSOCKET_PING_ID_MIN_CHARS,
            WEBSOCKET_OPAQUE_ID_MAX_CHARS,
            "dpop_proof jti",
        )?;
        if self.htm != WEBSOCKET_AUTH_METHOD_TOKEN {
            return Err(WireError::Protocol(format!(
                "WebSocket auth proof htm must be {WEBSOCKET_AUTH_METHOD_TOKEN}"
            )));
        }
        validate_websocket_base_url(&self.htu)?;
        if self.iat < 0 {
            return Err(WireError::Protocol(
                "WebSocket auth proof iat must be a non-negative NumericDate".to_owned(),
            ));
        }
        validate_base64url_token(
            &self.ath,
            WEBSOCKET_BASE64URL_32_BYTE_CHARS,
            WEBSOCKET_BASE64URL_32_BYTE_CHARS,
            "dpop_proof ath",
        )?;
        validate_websocket_opaque_id(&self.nonce, "dpop_proof nonce")
    }
}

/// Decoded `challenge_dpop_session_v1` proof
/// (`ak.schema.websocket_dpop_proof.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketDpopProof {
    pub protected: WebSocketDpopProtectedHeader,
    pub claims: WebSocketDpopClaims,
}

impl WebSocketDpopProof {
    pub fn validate(&self) -> Result<()> {
        self.protected.validate()?;
        self.claims.validate()
    }
}

// ── Server-side challenge state ─────────────────────────────────────────────

/// The single-use challenge record the service atomically writes **before**
/// sending a `challenge` (§3.1).
///
/// `connection_id` and the socket `Origin` are bound here, not inside the
/// proof: the profile explicitly forbids carrying them as private JWT claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketChallengeRecord {
    pub connection_id: String,
    pub nonce: String,
    pub canonical_origin: String,
    pub canonical_base_url: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
}

impl WebSocketChallengeRecord {
    /// The store key: one challenge is addressed by `(connection_id, nonce)`.
    pub fn key(&self) -> (&str, &str) {
        (self.connection_id.as_str(), self.nonce.as_str())
    }

    pub fn validate(&self) -> Result<()> {
        validate_websocket_opaque_id(&self.connection_id, "connection_id")?;
        validate_websocket_opaque_id(&self.nonce, "nonce")?;
        canonical_http_origin(&self.canonical_origin)?;
        validate_websocket_base_url(&self.canonical_base_url)?;
        let window = self.expires_at - self.issued_at;
        if window <= chrono::Duration::zero()
            || window > chrono::Duration::milliseconds(WEBSOCKET_AUTHENTICATION_DEADLINE_MS as i64)
        {
            return Err(WireError::Protocol(format!(
                "WebSocket challenge window must be 0..={WEBSOCKET_AUTHENTICATION_DEADLINE_MS}ms"
            )));
        }
        Ok(())
    }

    /// A challenge is usable while it is unconsumed and `now <= expires_at`.
    pub fn is_open_at(&self, now: DateTime<Utc>) -> bool {
        !self.consumed && now >= self.issued_at && now <= self.expires_at
    }
}

/// Replay ledger key written in the same atomic step that marks a challenge
/// consumed (§3.1). Reusing the same key, the same nonce or the same
/// `(connection_id, nonce)` pair MUST fail.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WebSocketReplayLedgerKey {
    pub cnf_jkt: String,
    pub jti: String,
    pub context: String,
}

impl WebSocketReplayLedgerKey {
    pub fn new(cnf_jkt: impl Into<String>, jti: impl Into<String>) -> Self {
        Self {
            cnf_jkt: cnf_jkt.into(),
            jti: jti.into(),
            context: WEBSOCKET_AUTH_REPLAY_CONTEXT.to_owned(),
        }
    }

    /// The ordered triple the fixture pins.
    pub fn as_triple(&self) -> [&str; 3] {
        [
            self.cnf_jkt.as_str(),
            self.jti.as_str(),
            self.context.as_str(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_base_url_accepts_the_fixture_form() {
        validate_websocket_base_url("wss://server.example/_arkret/ws").unwrap();
        validate_websocket_base_url("wss://server.example:8443/_arkret/ws").unwrap();
    }

    #[test]
    fn canonical_base_url_rejects_every_fixture_negative() {
        for input in [
            "ws://server.example/_arkret/ws",
            "wss://server.example:443/_arkret/ws",
            "wss://SERVER.example/_arkret/ws",
            "wss://server.example/_arkret/../ws",
            "wss://server.example/_arkret/ws?grant=secret",
            "wss://server.example./_arkret/ws",
            "wss://user@server.example/_arkret/ws",
            "wss://server.example",
            "wss://server.example/_arkret/%2fws",
            "wss://server.example/_arkret/%41ws",
        ] {
            validate_websocket_base_url(input)
                .expect_err(&format!("{input} must not be canonical"));
        }
    }

    #[test]
    fn origin_canonicalization_removes_the_default_port_only() {
        assert_eq!(
            canonical_http_origin("https://App.Example:443").unwrap(),
            "https://app.example"
        );
        assert_eq!(
            canonical_http_origin("https://app.example:8443").unwrap(),
            "https://app.example:8443"
        );
        canonical_http_origin("null").unwrap_err();
        canonical_http_origin("https://app.example/path").unwrap_err();
        canonical_http_origin("wss://app.example").unwrap_err();
    }

    #[test]
    fn close_codes_round_trip_and_gate_fallback() {
        for code in WebSocketCloseCode::ALL {
            assert_eq!(WebSocketCloseCode::from_u16(code.as_u16()), Some(*code));
        }
        assert!(WebSocketCloseCode::ProtocolError.forces_http_fallback());
        assert!(WebSocketCloseCode::MessageTooBig.forces_http_fallback());
        assert!(!WebSocketCloseCode::PolicyViolation.forces_http_fallback());
        assert_eq!(WebSocketCloseCode::from_u16(4000), None);
    }

    #[test]
    fn session_grant_stays_visible_ascii() {
        validate_websocket_session_grant("ak.session.grant.fixture.websocket.v1").unwrap();
        validate_websocket_session_grant("令牌").unwrap_err();
        validate_websocket_session_grant("").unwrap_err();
        validate_websocket_session_grant("has space").unwrap_err();
    }
}
