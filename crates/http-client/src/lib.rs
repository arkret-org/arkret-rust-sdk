//! HTTP transport bindings for Arkret v1 service endpoints.
//!
//! # TLS backend and PQ-hybrid requirement
//!
//! This crate is TLS-neutral by default: no TLS backend is compiled in, and
//! the deploying service picks its own (`reqwest/rustls-tls` or the
//! `tls-rustls` passthrough feature here / on the umbrella `arkret` crate).
//!
//! **PQ-hybrid TLS is a protocol MUST**: `arkret-spec`
//! `transport-bindings` §5 (2026-06-13 ruling) requires post-quantum hybrid
//! key exchange (X25519MLKEM768) for **all** profiles, fail-closed — a
//! deployment MUST NOT fall back to classical-only key exchange. When using
//! rustls, configure a crypto provider whose `kx_groups` includes
//! `X25519MLKEM768` and excludes classical-only groups, e.g. via
//! `rustls::crypto::aws_lc_rs` (which ships X25519MLKEM768) and a
//! `ClientConfig` built with `with_kx_groups(&[&X25519MLKEM768])`. reqwest's
//! `use_preconfigured_tls` accepts such a `ClientConfig`. A connection-time
//! negotiated-group assertion is not provided by this crate (reqwest does
//! not expose the negotiated kx group); enforce the MUST at configuration
//! time as described.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use reqwest::Method;
#[cfg(any(not(target_arch = "wasm32"), test))]
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use url::Url;

pub mod account_subscribe;
mod builder;
mod client_internals;
mod endpoints;
mod error;
mod request;
mod subscribe_body;
// Production reqwest + Tokio DID resolver. Leans on a live Tokio runtime,
// blocking off-thread scheduling, and reqwest's native transport, none of
// which exist on the wasm32 fetch backend — native-only.
#[cfg(not(target_arch = "wasm32"))]
pub mod http_did_resolver;
pub mod key_backup_client;
#[cfg(not(target_arch = "wasm32"))]
pub mod service_resolution_fetcher;

pub use account_subscribe::AccountSubscribeFolder;
pub use builder::ClientBuilder;
#[cfg(not(target_arch = "wasm32"))]
pub use builder::RedirectPolicy;
// Re-exported at crate root so the in-crate test module (which references
// these via bare names through `use super::*`) and sibling endpoint modules
// can reach the internal helpers. `pub(crate)` keeps them out of the public
// API.
pub(crate) use client_internals::reject_path_segment;
#[cfg(test)]
pub(crate) use client_internals::validate_request_builder;
pub use endpoints::{
    AccountSubscribeFrameStream, BlobDownloadOptions, BlobResumableUploadOptions,
    EventsSubscribeFrameStream, EventsSubscribeOptions,
    RESUMABLE_UPLOAD_FEATURE, RESUMABLE_UPLOAD_THRESHOLD_BYTES, SignalSubscribeFrameStream,
    blob_resumable_upload_base_url,
};
pub use error::{Error, Result};
#[cfg(not(target_arch = "wasm32"))]
pub use service_resolution_fetcher::{
    MaterializedServiceResolution, SERVICE_DESCRIBE_FETCH_MAX_BYTES,
    SERVICE_RESOLUTION_FETCH_MAX_BYTES, SERVICE_RESOLUTION_FETCH_TIMEOUT, ServiceResolutionFetcher,
};

pub const HEADER_REQUEST_ID: &str = "X-Arkret-Request-Id";
pub const HEADER_WAIT_FOR: &str = "X-Arkret-Wait-For";
pub const HEADER_IDEMPOTENCY_KEY: &str = "Idempotency-Key";
pub const HEADER_OPERATION: &str = "Arkret-Operation";

/// Default total request timeout applied per request when
/// [`ClientBuilder::timeout`] is not called. reqwest itself defaults to
/// *no* timeout, which would let a hung server (SYN black hole,
/// never-ending body) suspend the caller forever; this crate is the
/// shared transport for all Arkret services, so the default must be
/// bounded. The long-lived NDJSON subscribe streams
/// (`account_subscribe_frames`, `events_subscribe_frames`) are exempt — they
/// stay open by design. Override with [`ClientBuilder::timeout`] (an
/// explicit value applies client-wide, including streams).
/// Native-only — the browser owns timeouts on wasm32.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default connection-establishment (TCP + TLS) timeout applied when
/// [`ClientBuilder::connect_timeout`] is not called. Bounds the connect
/// phase for every request including subscribe streams. See
/// [`DEFAULT_REQUEST_TIMEOUT`] for rationale.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum bytes a single NDJSON subscribe frame (one line) may occupy
/// before [`Client::account_subscribe_batch`] aborts. Bounds memory while
/// waiting for the first newline on a hostile / misbehaving stream.
pub(crate) const MAX_SUBSCRIBE_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub enum Auth {
    Bearer(String),
    DeviceProof(String),
    ServiceSignature(String),
    Dpop(DpopAuth),
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.debug_tuple("Bearer").field(&"<redacted>").finish(),
            Self::DeviceProof(_) => f.debug_tuple("DeviceProof").field(&"<redacted>").finish(),
            Self::ServiceSignature(_) => f
                .debug_tuple("ServiceSignature")
                .field(&"<redacted>")
                .finish(),
            Self::Dpop(auth) => f.debug_tuple("Dpop").field(auth).finish(),
        }
    }
}

pub use arkret_signatures::DpopProofRequest;

type DpopProofCallback = dyn Fn(DpopProofRequest) -> Result<String> + Send + Sync + 'static;

#[derive(Clone)]
pub struct DpopAuth {
    access_token: Option<String>,
    proof: Arc<DpopProofCallback>,
}

impl std::fmt::Debug for DpopAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopAuth")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl DpopAuth {
    pub fn proof_only(
        proof: impl Fn(DpopProofRequest) -> Result<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            access_token: None,
            proof: Arc::new(proof),
        }
    }

    /// Present a DPoP-bound credential using the RFC 9449
    /// `Authorization: DPoP <token>` scheme.
    pub fn with_dpop_token(
        dpop_token: impl Into<String>,
        proof: impl Fn(DpopProofRequest) -> Result<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            access_token: Some(dpop_token.into()),
            proof: Arc::new(proof),
        }
    }

    #[must_use]
    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    pub(crate) fn proof_for(&self, method: &Method, url: &Url) -> Result<String> {
        let mut request =
            DpopProofRequest::new(method.as_str().to_ascii_uppercase(), dpop_htu(url));
        if let Some(access_token) = &self.access_token {
            request = request.access_token(access_token.clone());
        }
        (self.proof)(request)
    }
}

/// Optional RFC 9421 HTTP message signer for account-client requests.
///
/// The signer is applied immediately before a request is executed so retry
/// attempts get fresh `created` / `expires` values. It is intentionally
/// separate from [`Auth`]: Arkret account-client calls commonly present both a
/// DPoP session grant and an HTTP message signature bound to the grant's
/// signing key.
#[derive(Clone)]
pub struct HttpMessageSigner {
    key_id: String,
    signing_key: Arc<SigningKey>,
    validity: Duration,
}

impl std::fmt::Debug for HttpMessageSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpMessageSigner")
            .field("key_id", &self.key_id)
            .field("validity", &self.validity)
            .finish_non_exhaustive()
    }
}

impl HttpMessageSigner {
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key: Arc::new(signing_key),
            validity: Duration::from_secs(120),
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub(crate) fn validity_seconds(&self) -> i64 {
        i64::try_from(self.validity.as_secs()).unwrap_or(i64::MAX)
    }
}

fn dpop_htu(url: &Url) -> String {
    let mut htu = url.clone();
    htu.set_query(None);
    htu.set_fragment(None);
    htu.to_string()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientRequestOptions {
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub wait_for: Option<String>,
}

impl ClientRequestOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn wait_for(mut self, wait_for: impl Into<String>) -> Self {
        self.wait_for = Some(wait_for.into());
        self
    }
}

/// Status / transport retry policy applied by [`Client`]'s native `execute`
/// path.
///
/// # wasm32 behavior
///
/// Retry is **not implemented on wasm32**: the browser fetch backend has no
/// in-crate sleep primitive and no connect-error discrimination, so
/// `execute()` collapses to a single send there and this configuration is
/// ignored. Callers that need retry on wasm must layer it above the client
/// (e.g. via `wasm-bindgen-futures`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryConfig {
    pub max_retries: usize,
    pub retry_statuses: Vec<u16>,
    pub retry_network_errors: bool,
    pub base_delay: Duration,
    pub max_delay: Duration,
    /// Apply 0–20% additive random jitter to computed backoff delays
    /// (api-conventions.md §9 default backoff) before taking the maximum with
    /// a server-directed retry hint.
    pub jitter: bool,
}

/// Spec ceiling for the default backoff policy: at most 5 retries per
/// `(endpoint, scope)` within a 5-minute window (api-conventions.md §9).
/// With the 1 s base / factor-2 / 60 s cap defaults, 5 retries complete in
/// well under 5 minutes, so a per-request cap satisfies the window bound.
const SPEC_MAX_DEFAULT_RETRIES: usize = 5;

impl RetryConfig {
    pub fn disabled() -> Self {
        Self {
            max_retries: 0,
            retry_statuses: standard_retry_statuses(),
            retry_network_errors: true,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            jitter: false,
        }
    }

    /// Spec-default backoff (api-conventions.md §9): first retry ≥ 1000 ms,
    /// factor 2, capped at 60 000 ms, 0–20% jitter, and at most
    /// `SPEC_MAX_DEFAULT_RETRIES` retries (`max_retries` is clamped).
    pub fn standard(max_retries: usize) -> Self {
        Self {
            max_retries: max_retries.min(SPEC_MAX_DEFAULT_RETRIES),
            retry_statuses: standard_retry_statuses(),
            retry_network_errors: true,
            base_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(60),
            jitter: true,
        }
    }

    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    #[cfg(any(not(target_arch = "wasm32"), test))]
    pub(crate) fn should_retry_status(&self, status: StatusCode) -> bool {
        self.retry_statuses.contains(&status.as_u16())
    }

    #[cfg(any(not(target_arch = "wasm32"), test))]
    pub(crate) fn retry_delay(&self, attempt: usize) -> Duration {
        if self.base_delay.is_zero() {
            return Duration::ZERO;
        }
        let shift = attempt.saturating_sub(1).min(31) as u32;
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        let delay = self.base_delay.saturating_mul(factor);
        let delay = if self.max_delay.is_zero() {
            delay
        } else {
            std::cmp::min(delay, self.max_delay)
        };
        if self.jitter {
            apply_jitter(delay)
        } else {
            delay
        }
    }

    /// Next retry delay, honoring a server `Retry-After`.
    ///
    /// The local exponential delay (including its additive jitter) and the
    /// server hint are independent lower bounds. The effective delay is their
    /// maximum, so a short or elapsed hint never accelerates the local ladder
    /// and a long hint is never truncated by `max_delay`.
    #[cfg(any(not(target_arch = "wasm32"), test))]
    pub(crate) fn retry_delay_from_headers(&self, headers: &HeaderMap, attempt: usize) -> Duration {
        let local_backoff = self.retry_delay(attempt);
        retry_after_ms(headers)
            .map(Duration::from_millis)
            .map_or(local_backoff, |server_hint| local_backoff.max(server_hint))
    }
}

/// Add 0–20% random jitter to `delay` (api-conventions.md §9). Falls back to
/// the unjittered delay if the OS randomness source fails.
#[cfg(any(not(target_arch = "wasm32"), test))]
fn apply_jitter(delay: Duration) -> Duration {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return delay;
    }
    let fraction = f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX);
    delay.mul_f64(1.0 + fraction * 0.2)
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    pub(crate) base_url: Url,
    pub(crate) http: reqwest::Client,
    pub(crate) auth: Option<Auth>,
    pub(crate) http_message_signer: Option<HttpMessageSigner>,
    pub(crate) allow_insecure_localhost: bool,
    pub(crate) retry: RetryConfig,
    pub(crate) user_agent: Option<String>,
    /// Per-request total timeout applied by [`Client::request`] when the
    /// builder did not set an explicit client-wide timeout and did not
    /// inject a pre-built `reqwest::Client`. `None` means the transport
    /// configuration is caller-owned. Subscribe streams skip this.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) default_timeout: Option<Duration>,
}

/// Parse the `Retry-After` header into milliseconds. Both RFC 9110 forms
/// are supported: delta-seconds and HTTP-date (IMF-fixdate). The HTTP-date
/// form is converted to a relative delay against the current wall clock as
/// a pure timestamp difference (no local-timezone lookup, wasm-safe); a
/// date in the past yields `Some(0)`. Used by
/// [`RetryConfig::retry_delay_from_headers`] and the error-envelope
/// hydration in `client_internals`.
pub(crate) fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return seconds.checked_mul(1000);
    }
    let target = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let delta_ms = target
        .signed_duration_since(chrono::Utc::now())
        .num_milliseconds();
    Some(u64::try_from(delta_ms).unwrap_or(0))
}

fn standard_retry_statuses() -> Vec<u16> {
    vec![408, 429, 500, 502, 503, 504]
}

#[cfg(test)]
mod tests;
