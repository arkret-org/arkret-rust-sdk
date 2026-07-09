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

use arkret_core::Result;
use arkret_signatures::http_signature::Ed25519SigningKey;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use url::Url;

mod builder;
mod client_internals;
mod endpoints_account;
mod endpoints_agent;
mod endpoints_data;
mod endpoints_events;
mod endpoints_identity;
mod endpoints_misc;

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
pub use endpoints_data::{
    BlobDownloadOptions, BlobResumableUploadOptions, RESUMABLE_UPLOAD_FEATURE,
    RESUMABLE_UPLOAD_THRESHOLD_BYTES, blob_resumable_upload_base_url,
};
pub use endpoints_events::{EventsSubscribeFrameStream, EventsSubscribeOptions};
pub use endpoints_misc::SignedAppletTransactionOptions;

pub const HEADER_REQUEST_ID: &str = "X-Arkret-Request-Id";
pub const HEADER_WAIT_FOR: &str = "X-Arkret-Wait-For";
pub const HEADER_IDEMPOTENCY_KEY: &str = "Idempotency-Key";

/// Default total request timeout applied per request when
/// [`ClientBuilder::timeout`] is not called. reqwest itself defaults to
/// *no* timeout, which would let a hung server (SYN black hole,
/// never-ending body) suspend the caller forever; this crate is the
/// shared transport for all Arkret services, so the default must be
/// bounded. The long-lived NDJSON subscribe streams
/// (`account_subscribe`, `events_subscribe_stream`) are exempt — they
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
/// before [`Client::account_subscribe_once`] aborts. Bounds memory while
/// waiting for the first newline on a hostile / misbehaving stream.
pub(crate) const MAX_SUBSCRIBE_FRAME_BYTES: usize = 8 * 1024 * 1024;

pub(crate) const QUERY_AUTH_KEYS: &[&str] = &[
    "access_token",
    "auth",
    "authorization",
    "bearer",
    "id_token",
    "refresh_token",
    "session",
    "session_token",
    "token",
];

#[derive(Clone, Debug)]
pub enum Auth {
    Bearer(String),
    DeviceProof(String),
    ServiceSignature(String),
    Dpop(DpopAuth),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpopProofRequest {
    pub method: String,
    pub htu: String,
    pub access_token: Option<String>,
}

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

    pub fn with_access_token(
        access_token: impl Into<String>,
        proof: impl Fn(DpopProofRequest) -> Result<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            access_token: Some(access_token.into()),
            proof: Arc::new(proof),
        }
    }

    #[must_use]
    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    pub(crate) fn proof_for(&self, method: &Method, url: &Url) -> Result<String> {
        (self.proof)(DpopProofRequest {
            method: method.as_str().to_ascii_uppercase(),
            htu: dpop_htu(url),
            access_token: self.access_token.clone(),
        })
    }
}

/// Optional RFC 9421 HTTP message signer for account-client requests.
///
/// The signer is applied immediately before a request is executed so retry
/// attempts get fresh `created` / `expires` values. It is intentionally
/// separate from [`Auth`]: Arkret account-client calls commonly present both a
/// Bearer/DPoP session grant and an HTTP message signature bound to the grant's
/// signing key.
#[derive(Clone)]
pub struct HttpMessageSigner {
    key_id: String,
    signing_key: Arc<Ed25519SigningKey>,
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
    pub fn new(key_id: impl Into<String>, signing_key: Ed25519SigningKey) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key: Arc::new(signing_key),
            validity: Duration::from_secs(120),
        }
    }

    #[must_use]
    pub fn with_validity(mut self, validity: Duration) -> Self {
        self.validity = validity;
        self
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn signing_key(&self) -> &Ed25519SigningKey {
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
/// ignored (a `tracing::warn` is emitted once per call when the `tracing`
/// feature is enabled). Callers that need retry on wasm must layer it above
/// the client (e.g. via `wasm-bindgen-futures`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryConfig {
    pub max_retries: usize,
    pub retry_statuses: Vec<u16>,
    pub retry_network_errors: bool,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub respect_retry_after: bool,
    /// Apply 0–20% additive random jitter to computed backoff delays
    /// (api-conventions.md §9 default backoff). Does not apply to
    /// server-directed `Retry-After` values.
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
            respect_retry_after: true,
            jitter: false,
        }
    }

    /// Spec-default backoff (api-conventions.md §9): first retry ≥ 1000 ms,
    /// factor 2, capped at 60 000 ms, 0–20% jitter, and at most
    /// [`SPEC_MAX_DEFAULT_RETRIES`] retries (`max_retries` is clamped).
    pub fn standard(max_retries: usize) -> Self {
        Self {
            max_retries: max_retries.min(SPEC_MAX_DEFAULT_RETRIES),
            retry_statuses: standard_retry_statuses(),
            retry_network_errors: true,
            base_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(60),
            respect_retry_after: true,
            jitter: true,
        }
    }

    pub fn with_base_delay(mut self, base_delay: Duration) -> Self {
        self.base_delay = base_delay;
        self
    }

    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    pub fn respect_retry_after(mut self, respect_retry_after: bool) -> Self {
        self.respect_retry_after = respect_retry_after;
        self
    }

    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn should_retry_status(&self, status: StatusCode) -> bool {
        self.retry_statuses.contains(&status.as_u16())
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
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
    /// A server-directed `Retry-After` is authoritative: it is **not**
    /// truncated by `max_delay` and gets no jitter (api-conventions.md §9:
    /// clients MUST prefer the server instruction).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn retry_delay_from_headers(&self, headers: &HeaderMap, attempt: usize) -> Duration {
        if self.respect_retry_after
            && let Some(retry_after_ms) = retry_after_ms(headers)
        {
            return Duration::from_millis(retry_after_ms);
        }
        self.retry_delay(attempt)
    }
}

/// Add 0–20% random jitter to `delay` (api-conventions.md §9). Falls back to
/// the unjittered delay if the OS randomness source fails.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
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
mod tests {
    use arkret_core::Error;
    use reqwest::Method;
    use reqwest::header::{HeaderValue, USER_AGENT};

    use super::*;

    #[test]
    fn builds_relative_api_url() {
        let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
        let request = client
            .request(Method::GET, "/_arkret/describe")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://alice.example/arkret/_arkret/describe"
        );
    }

    #[test]
    fn rejects_remote_http_by_default() {
        let error = Client::new(Url::parse("http://alice.example/arkret/").unwrap()).unwrap_err();
        assert!(matches!(error, Error::InsecureUrl(_)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn allows_insecure_localhost_when_explicit() {
        let client = Client::builder(Url::parse("http://127.0.0.1:8080/").unwrap())
            .allow_insecure_localhost()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert_eq!(client.base_url().scheme(), "http");
    }

    #[test]
    fn rejects_absolute_request_paths() {
        let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
        let error = client
            .request(Method::GET, "https://evil.example/api")
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn rejects_header_unsafe_auth_material() {
        let error = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .auth(Auth::Bearer("token\r\nX-Evil: true".to_owned()))
            .build()
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn dpop_auth_adds_bearer_and_per_request_proof() {
        let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .auth(Auth::Dpop(DpopAuth::with_access_token(
                "grant.jwt",
                |req| {
                    assert_eq!(req.method, "POST");
                    assert_eq!(req.htu, "https://alice.example/arkret/_arkret/self/events");
                    assert_eq!(req.access_token.as_deref(), Some("grant.jwt"));
                    Ok("proof.jwt".to_owned())
                },
            )))
            .build()
            .unwrap();
        let request = client
            .request(Method::POST, "/_arkret/self/events?cursor=ignored")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.headers()["authorization"], "Bearer grant.jwt");
        assert_eq!(request.headers()["dpop"], "proof.jwt");
    }

    #[test]
    fn dpop_auth_supports_proof_only_kickoff() {
        let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .auth(Auth::Dpop(DpopAuth::proof_only(|req| {
                assert_eq!(req.method, "POST");
                assert_eq!(req.access_token, None);
                Ok("kickoff.proof.jwt".to_owned())
            })))
            .build()
            .unwrap();
        let request = client
            .request(Method::POST, "/_arkret/gate/account/session-grants")
            .unwrap()
            .build()
            .unwrap();

        assert!(!request.headers().contains_key("authorization"));
        assert_eq!(request.headers()["dpop"], "kickoff.proof.jwt");
    }

    #[test]
    fn rejects_encoded_path_separator_segments() {
        let error = reject_path_segment("txn_%2Fescape").unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn request_options_add_standard_headers() {
        let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .user_agent("arkret-sdk-test/1")
            .build()
            .unwrap();
        let options = ClientRequestOptions::new()
            .request_id("req-1")
            .idempotency_key("idem-1")
            .wait_for("ak:cursor:01");
        let request = client
            .apply_request_options(
                client.request(Method::PUT, "/_arkret/self/events").unwrap(),
                &options,
            )
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.headers()[USER_AGENT], "arkret-sdk-test/1");
        assert_eq!(request.headers()[HEADER_REQUEST_ID], "req-1");
        assert_eq!(request.headers()[HEADER_IDEMPOTENCY_KEY], "idem-1");
        assert_eq!(request.headers()[HEADER_WAIT_FOR], "ak:cursor:01");
    }

    #[test]
    fn request_options_reject_header_injection() {
        let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
        let options = ClientRequestOptions::new().request_id("req\r\nX-Evil: true");

        let error = client
            .apply_request_options(
                client.request(Method::GET, "/_arkret/describe").unwrap(),
                &options,
            )
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn rejects_query_auth_on_base_path_and_built_request() {
        assert!(
            Client::new(Url::parse("https://alice.example/arkret/?access_token=secret").unwrap())
                .is_err()
        );

        let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
        let builder = client
            .request(Method::GET, "/_arkret/self/events")
            .unwrap()
            .query(&[("access_token", "secret")]);

        let error = validate_request_builder(&builder).unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn retry_after_seconds_are_reported_as_millis() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));

        assert_eq!(retry_after_ms(&headers), Some(3000));
    }

    #[test]
    fn standard_retry_config_covers_transient_statuses() {
        let retry = RetryConfig::standard(2);

        assert!(retry.should_retry_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(retry.should_retry_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!retry.should_retry_status(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn retry_config_uses_bounded_exponential_backoff() {
        let retry = RetryConfig::standard(4)
            .with_jitter(false)
            .with_base_delay(Duration::from_millis(25))
            .with_max_delay(Duration::from_millis(80));

        assert_eq!(retry.retry_delay(1), Duration::from_millis(25));
        assert_eq!(retry.retry_delay(2), Duration::from_millis(50));
        assert_eq!(retry.retry_delay(3), Duration::from_millis(80));
        assert_eq!(retry.retry_delay(4), Duration::from_millis(80));
    }

    #[test]
    fn retry_config_defaults_match_spec_backoff_policy() {
        // api-conventions.md §9: base ≥ 1000 ms, factor 2, cap ≥ 60 000 ms,
        // jitter on, at most 5 retries.
        let retry = RetryConfig::standard(10);

        assert_eq!(retry.max_retries, 5);
        assert_eq!(retry.base_delay, Duration::from_millis(1000));
        assert_eq!(retry.max_delay, Duration::from_secs(60));
        assert!(retry.jitter);
        assert!(retry.respect_retry_after);
    }

    #[test]
    fn retry_delay_jitter_stays_within_twenty_percent() {
        let retry = RetryConfig::standard(3);
        for attempt in 1..=3 {
            let base = Duration::from_millis(1000 * (1 << (attempt - 1)));
            let delay = retry.retry_delay(attempt);
            assert!(delay >= base, "attempt {attempt}: {delay:?} < {base:?}");
            assert!(
                delay <= base.mul_f64(1.2),
                "attempt {attempt}: {delay:?} > {:?}",
                base.mul_f64(1.2)
            );
        }
    }

    #[test]
    fn retry_after_overrides_max_delay_cap() {
        // api-conventions.md §9: a server Retry-After is authoritative and
        // MUST NOT be truncated by the client's own max_delay.
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
        let retry = RetryConfig::standard(2)
            .with_jitter(false)
            .with_max_delay(Duration::from_secs(2));

        assert_eq!(
            retry.retry_delay_from_headers(&headers, 1),
            Duration::from_secs(3)
        );
        assert_eq!(
            retry
                .respect_retry_after(false)
                .retry_delay_from_headers(&headers, 1),
            Duration::from_millis(1000)
        );
    }

    #[test]
    fn retry_after_http_date_form_is_parsed_as_relative_delay() {
        // Future IMF-fixdate → positive delay near the actual delta.
        let target = chrono::Utc::now() + chrono::Duration::seconds(30);
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&target.to_rfc2822().replace("+0000", "GMT")).unwrap(),
        );
        let ms = retry_after_ms(&headers).expect("HTTP-date Retry-After must parse");
        assert!((20_000..=31_000).contains(&ms), "unexpected delay: {ms}");

        // Past HTTP-date → clamped to zero, not an error / fallback.
        let past = chrono::Utc::now() - chrono::Duration::seconds(30);
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&past.to_rfc2822().replace("+0000", "GMT")).unwrap(),
        );
        assert_eq!(retry_after_ms(&headers), Some(0));

        // Garbage still falls back to None (exponential backoff path).
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-date"));
        assert_eq!(retry_after_ms(&headers), None);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn transport_options_apply_without_panic() {
        let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(45))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .gzip(false)
            .redirect(RedirectPolicy::None)
            .no_proxy()
            .build()
            .unwrap();

        assert_eq!(client.base_url().as_str(), "https://alice.example/arkret/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn proxy_can_be_added_via_builder() {
        let proxy = reqwest::Proxy::http("http://proxy.example:3128").unwrap();
        let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .proxy(proxy)
            .build()
            .unwrap();
        assert_eq!(client.base_url().as_str(), "https://alice.example/arkret/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn transport_options_conflict_with_pre_built_http_client() {
        let http = reqwest::Client::new();
        let error = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .http_client(http)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(message) if message.contains("transport options")));
    }

    #[test]
    fn pre_built_http_client_alone_is_accepted() {
        let http = reqwest::Client::new();
        let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .http_client(http)
            .build()
            .unwrap();
        assert_eq!(client.base_url().as_str(), "https://alice.example/arkret/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod events_submit_tests {
        use std::collections::BTreeMap;

        use arkret_core::{
            BlobRef, BlobUploadMetadata, Did, DirectConversationResolveRequestBody,
            DirectoryPrivateContactDiscoveryRequestBody, Event, EventId, EventRequirements, Hash,
            Hlc, MimiReportAbuseRequestBody, RealmId, StrandId, SyncRequestBody,
        };
        use serde_json::{Value, json};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use super::*;

        /// Build an `Event` suitable for wire-shape tests. The fixture is not
        /// signed and would fail `validate_for_submit`, but the SDK methods
        /// under test do not invoke that validation — they just serialise the
        /// envelope into the request body. The fixture is deliberately
        /// stripped down so the serialised body is easy to assert against.
        fn fixture_event(content_body: &str) -> Event {
            Event {
                event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
                kind: "ak.message.create".into(),
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
                actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                actor_seq: 1,
                created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
                hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
                prev_refs: Vec::new(),
                effective_scope: None,
                refs: Vec::new(),
                preconditions: Vec::new(),
                effects: Vec::new(),
                seal_ref: None,
                auth_context: None,
                seal_basis: None,
                requirements: EventRequirements::default(),
                redacts: None,
                payload: json!({ "body": content_body }),
                executed_by: None,
                authorization_ref: None,
                applet_id: None,
                external_ref: None,
                actor_kind: None,
                unsigned: BTreeMap::new(),
                proofs: Vec::new(),
            }
        }

        /// Spin up a single-shot HTTP listener on `127.0.0.1` and return both
        /// a [`Client`] pointing at it and a oneshot receiver that yields the
        /// raw request bytes once the listener has served `body_response`.
        ///
        /// The listener accepts exactly one connection, reads until the body
        /// is consumed (assuming a `Content-Length` header is present, which
        /// `reqwest::RequestBuilder::json` guarantees), and replies with the
        /// supplied `body_response` JSON under HTTP/1.1 200 OK. The chosen
        /// port is allocated by the OS so tests can run in parallel.
        async fn spawn_capture_server(
            body_response: &'static str,
        ) -> (Client, tokio::sync::oneshot::Receiver<Vec<u8>>) {
            spawn_capture_server_with(body_response, |builder| builder).await
        }

        async fn spawn_capture_server_with<F>(
            body_response: &'static str,
            configure: F,
        ) -> (Client, tokio::sync::oneshot::Receiver<Vec<u8>>)
        where
            F: FnOnce(ClientBuilder) -> ClientBuilder,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();

            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let mut headers_end = None;
                let mut content_length: Option<usize> = None;
                loop {
                    let n = socket.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if headers_end.is_none()
                        && let Some(idx) = buf.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        headers_end = Some(idx + 4);
                        let header_str = std::str::from_utf8(&buf[..idx]).unwrap_or("");
                        for line in header_str.split("\r\n") {
                            if let Some(value) = line
                                .strip_prefix("Content-Length: ")
                                .or_else(|| line.strip_prefix("content-length: "))
                            {
                                content_length = value.trim().parse().ok();
                            }
                        }
                    }
                    if let (Some(hdr_end), Some(len)) = (headers_end, content_length)
                        && buf.len() >= hdr_end + len
                    {
                        break;
                    }
                    if headers_end.is_some() && content_length.is_none() {
                        break;
                    }
                }

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_response.len(),
                    body_response
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.ok();
                let _ = tx.send(buf);
            });

            let base = Url::parse(&format!("http://{addr}/")).unwrap();
            let client = configure(Client::builder(base).allow_insecure_localhost())
                .build()
                .unwrap();
            (client, rx)
        }

        /// Split a raw HTTP/1.1 request capture into (request-line, headers, body).
        fn split_request(raw: &[u8]) -> (String, String, Vec<u8>) {
            let idx = raw
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap();
            let head = std::str::from_utf8(&raw[..idx]).unwrap();
            let body = raw[idx + 4..].to_vec();
            let mut lines = head.splitn(2, "\r\n");
            let request_line = lines.next().unwrap_or("").to_owned();
            let headers = lines.next().unwrap_or("").to_owned();
            (request_line, headers, body)
        }

        #[tokio::test]
        async fn events_submit_single_event_posts_envelope() {
            let canned = r#"{"status":"accepted","accepted":["ak:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let event = fixture_event("hello");
            let response = client.events_submit(&event).await.unwrap();

            assert!(matches!(
                response.status,
                arkret_core::EventsSubmitStatus::Accepted
            ));
            assert_eq!(response.accepted.len(), 1);

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_arkret/self/events "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            // The wire body is the bare envelope, not wrapped in `{"event":..}`
            // or `{"events":[..]}`.
            assert!(
                parsed.get("events").is_none(),
                "single-event POST must not wrap in events[]: {parsed}"
            );
            assert_eq!(parsed["kind"], "ak.message.create");
            assert_eq!(parsed["payload"]["body"], "hello");
            assert_eq!(parsed["actor_id"], "did:webvh:z6mkfixture:alice.example");
        }

        #[tokio::test]
        async fn blob_upload_bytes_posts_multipart_form() {
            let canned = r#"{"blob_ref":"ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":5,"media_type":"text/plain","content_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","upload_receipt":null}"#;
            let (client, capture) = spawn_capture_server(canned).await;
            let metadata = BlobUploadMetadata {
                realm_id: None,
                content_digest: Some(
                    Hash::new(
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    .unwrap(),
                ),
                size_bytes: 5,
                media_type: Some("text/plain".to_owned()),
                filename: Some("note.txt".to_owned()),
                purpose: Some("message_attachment".to_owned()),
            };

            let response = client
                .blob_upload_bytes(&metadata, b"hello".to_vec())
                .await
                .unwrap();

            assert_eq!(response.size_bytes, 5);
            let raw = capture.await.unwrap();
            let (request_line, headers, body) = split_request(&raw);
            assert!(request_line.starts_with("POST /_arkret/self/blob/upload "));
            assert!(headers.lines().any(|line| {
                line.to_ascii_lowercase()
                    .starts_with("content-type: multipart/form-data; boundary=")
            }));
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("name=\"content\""));
            assert!(body.contains("hello"));
            assert!(body.contains("name=\"size_bytes\""));
            assert!(body.contains("5"));
            assert!(body.contains("name=\"media_type\""));
            assert!(body.contains("text/plain"));
            assert!(body.contains("name=\"filename\""));
            assert!(body.contains("note.txt"));
            assert!(body.contains("name=\"purpose\""));
            assert!(body.contains("message_attachment"));
        }

        #[tokio::test]
        async fn blob_download_bytes_gets_purpose_range_and_wait_for() {
            let (client, capture) = spawn_capture_server("hello").await;
            let blob_ref = BlobRef::new(
                "ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            )
            .unwrap();
            let options = BlobDownloadOptions::new()
                .purpose("message_attachment")
                .range("bytes=1-3")
                .max_bytes(16);
            let request_options = ClientRequestOptions::new().wait_for("ak:cursor:test");

            let bytes = client
                .blob_download_bytes_with_options(&blob_ref, &options, &request_options)
                .await
                .unwrap();

            assert_eq!(bytes, b"hello");
            let raw = capture.await.unwrap();
            let (request_line, headers, _body) = split_request(&raw);
            assert!(request_line.starts_with("GET /_arkret/self/blob/get?"));
            assert!(
                request_line.contains(
                    "blob_ref=ck%3Ablob%3Asha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                "unexpected request line: {request_line}",
            );
            assert!(request_line.contains("purpose=message_attachment"));
            assert!(
                headers
                    .lines()
                    .any(|line| { line.to_ascii_lowercase().starts_with("range: bytes=1-3") })
            );
            assert!(headers.lines().any(|line| {
                line.to_ascii_lowercase()
                    .starts_with("x-arkret-wait-for: ak:cursor:test")
            }));
        }

        #[tokio::test]
        async fn blob_download_bytes_enforces_configured_cap() {
            let (client, _capture) = spawn_capture_server("hello").await;
            let blob_ref = BlobRef::new(
                "ak:blob:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
            )
            .unwrap();
            let options = BlobDownloadOptions::new().max_bytes(4);

            let error = client
                .blob_download_bytes(&blob_ref, &options)
                .await
                .unwrap_err();

            assert!(matches!(error, Error::Protocol(message) if message.contains("4-byte limit")));
        }

        #[tokio::test]
        async fn http_message_signer_signs_self_requests_before_send() {
            let canned = r#"{"status":"accepted","accepted":["ak:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let signer =
                HttpMessageSigner::new("grant-key", Ed25519SigningKey::from_bytes(&[7u8; 32]));
            let (client, capture) =
                spawn_capture_server_with(canned, |builder| builder.http_message_signer(signer))
                    .await;

            let event = fixture_event("signed");
            client.events_submit(&event).await.unwrap();

            let raw = capture.await.unwrap();
            let (_request_line, headers, _body) = split_request(&raw);
            assert!(
                headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("signature-input:"))
            );
            assert!(
                headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("signature:"))
            );
            assert!(
                headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("content-digest:"))
            );
        }

        #[tokio::test]
        async fn http_message_signer_does_not_sign_public_describe() {
            let canned = r#"{"name":"test","version":"v1"}"#;
            let signer =
                HttpMessageSigner::new("grant-key", Ed25519SigningKey::from_bytes(&[8u8; 32]));
            let (client, capture) =
                spawn_capture_server_with(canned, |builder| builder.http_message_signer(signer))
                    .await;

            let _: Value = client.get("/_arkret/describe").await.unwrap();

            let raw = capture.await.unwrap();
            let (_request_line, headers, _body) = split_request(&raw);
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("signature-input:"))
            );
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("signature:"))
            );
        }

        #[tokio::test]
        async fn events_submit_batch_posts_events_array() {
            let canned = r#"{"status":"accepted","accepted":["ak:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let events = vec![fixture_event("first"), fixture_event("second")];
            let response = client.events_submit_batch(&events).await.unwrap();
            assert!(matches!(
                response.status,
                arkret_core::EventsSubmitStatus::Accepted
            ));

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(request_line.starts_with("POST /_arkret/self/events "));
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            let events_value = parsed
                .get("events")
                .expect("batch body must carry events[]");
            let arr = events_value.as_array().expect("events must be an array");
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0]["payload"]["body"], "first");
            assert_eq!(arr[1]["payload"]["body"], "second");
        }

        #[tokio::test]
        async fn events_query_gets_canonical_events_collection() {
            let canned = r#"{"events":[],"prev_cursor":null,"next_cursor":null,"limited":false}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let response = client
                .events_query(
                    "ak:realm:test",
                    Some("ak:cursor:older"),
                    Some("ak:cursor:newer"),
                    Some("descending"),
                    Some(20),
                )
                .await
                .unwrap();
            assert!(response.events.is_empty());

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line.starts_with("GET /_arkret/self/events?"),
                "unexpected request line: {request_line}",
            );
            assert!(!request_line.contains("/_arkret/self/events/query?"));
            assert!(request_line.contains("realms=ck%3Arealm%3Atest"));
            assert!(request_line.contains("before=ck%3Acursor%3Aolder"));
            assert!(request_line.contains("after=ck%3Acursor%3Anewer"));
            assert!(request_line.contains("order=descending"));
            assert!(request_line.contains("limit=20"));
        }

        #[tokio::test]
        async fn events_query_outcome_uses_standard_shape_and_completeness_query() {
            let canned = r#"{"events":[],"prev_cursor":null,"next_cursor":null,"has_more":false,"range_completeness":{"attestation_refs":[]}}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let response = client
                .events_query_outcome(
                    "ak:realm:test",
                    None,
                    Some("ak:cursor:newer"),
                    Some("ascending"),
                    Some(50),
                    Some(true),
                )
                .await
                .unwrap();
            assert!(response.events.is_empty());
            assert!(!response.has_more);
            assert_eq!(
                response.range_completeness["attestation_refs"]
                    .as_array()
                    .map(Vec::len),
                Some(0)
            );

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line.starts_with("GET /_arkret/self/events?"),
                "unexpected request line: {request_line}",
            );
            assert!(request_line.contains("realms=ck%3Arealm%3Atest"));
            assert!(request_line.contains("after=ck%3Acursor%3Anewer"));
            assert!(request_line.contains("order=ascending"));
            assert!(request_line.contains("limit=50"));
            assert!(request_line.contains("include_completeness=true"));
        }

        #[tokio::test]
        async fn list_key_backups_includes_series_id_query() {
            let (client, capture) =
                spawn_capture_server(r#"{"backups":[],"has_more":false}"#).await;
            let query = arkret_core::KeyBackupsListQuery {
                series_id: Some(
                    arkret_core::BackupSeriesId::new(
                        "ak:backup_series:01964137-0000-7000-8000-000000000777",
                    )
                    .unwrap(),
                ),
                backup_class: Some(arkret_core::BackupClass::DidRecovery),
                cursor: None,
                limit: Some(25),
            };

            let response = client.list_key_backups(&query).await.unwrap();
            assert!(response.backups.is_empty());
            assert!(!response.has_more);

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line.starts_with("GET /_arkret/self/keys/backups?"),
                "unexpected request line: {request_line}",
            );
            assert!(
                request_line.contains(
                    "series_id=ck%3Abackup_series%3A01964137-0000-7000-8000-000000000777"
                )
            );
            assert!(request_line.contains("backup_class=did_recovery"));
            assert!(request_line.contains("limit=25"));
        }

        #[tokio::test]
        async fn directory_private_contact_discovery_posts_canonical_path() {
            let (client, capture) = spawn_capture_server(r#"{"matches":[],"proofs":[]}"#).await;
            let request = DirectoryPrivateContactDiscoveryRequestBody {
                requester: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                contacts: vec![json!({"contact_digest": "sha256:contact"})],
                proofs: Vec::new(),
                privacy_profile: Some("psi-v1".to_owned()),
                padding: Value::Null,
            };

            let response = client
                .directory_private_contact_discovery(&request)
                .await
                .unwrap();
            assert!(response.matches.is_empty());

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_arkret/find/directory/private-contact-discovery "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["requester"], "did:webvh:z6mkfixture:alice.example");
            assert_eq!(parsed["privacy_profile"], "psi-v1");
        }

        #[tokio::test]
        async fn contacts_list_gets_spec_path() {
            let (client, capture) =
                spawn_capture_server(r#"{"contacts":[],"has_more":false}"#).await;

            let response = client.contacts_list().await.unwrap();
            assert!(response.contacts.is_empty());
            assert!(!response.has_more);

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line.starts_with("GET /_arkret/self/contacts "),
                "unexpected request line: {request_line}",
            );
        }

        #[tokio::test]
        async fn direct_conversation_resolve_posts_spec_path_and_current_shape() {
            let canned = r#"{
                "state":"found",
                "realm_id":"ak:realm:01904100-0000-7000-8000-d10000000001",
                "main_strand_id":"ak:strand:01904100-0000-7000-8000-d10000000002",
                "binding_event_ref":"ak:event:01904100-0000-7000-8000-d10000000003",
                "created":false
            }"#;
            let (client, capture) = spawn_capture_server(canned).await;
            let request = DirectConversationResolveRequestBody {
                peer: Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
                create: true,
                idempotency_key: Some("dm-alice-bob".to_owned()),
            };

            let response = client.direct_conversation_resolve(&request).await.unwrap();
            assert_eq!(
                response.state,
                arkret_core::DirectConversationResolveState::Found
            );
            assert_eq!(
                response.binding_event_ref.as_ref().map(|id| id.as_str()),
                Some("ak:event:01904100-0000-7000-8000-d10000000003")
            );
            assert_eq!(response.created, Some(false));

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_arkret/self/direct-conversations/resolve "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["peer"], "did:webvh:z6mkfixture:bob.example");
            assert_eq!(parsed["create"], true);
            assert_eq!(parsed["idempotency_key"], "dm-alice-bob");
        }

        #[tokio::test]
        async fn mimi_provider_directory_gets_canonical_path_with_filters() {
            let (client, capture) = spawn_capture_server(r#"{"providers":[]}"#).await;
            let features = vec!["blind_wakeup".to_owned(), "mimi_v1".to_owned()];

            let response = client
                .mimi_provider_directory(Some("provider-a"), &features)
                .await
                .unwrap();
            assert!(response.providers.is_empty());

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line.starts_with("GET /_arkret/open/mimi/provider-directory?"),
                "unexpected request line: {request_line}",
            );
            assert!(request_line.contains("provider_id=provider-a"));
            assert!(request_line.contains("features=blind_wakeup"));
            assert!(request_line.contains("features=mimi_v1"));
        }

        #[tokio::test]
        async fn mimi_report_abuse_posts_canonical_path() {
            let (client, capture) = spawn_capture_server(
                r#"{"report_id":"ak:report:01904100-0000-7000-8000-a0086f45c575","status":"queued","routed_to":[]}"#,
            )
            .await;
            let request = MimiReportAbuseRequestBody {
                strand_id: StrandId::new("ak:strand:01904100-0000-7000-8000-f571eead1fc4").unwrap(),
                mimi_room_uri: Some("mimi://provider/rooms/room-1".to_owned()),
                realm_id: None,
                target_ref: "mimi://provider/rooms/room-1/messages/msg-1".to_owned(),
                reporter: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                abuse_reason_code: "spam".to_owned(),
                evidence_package: Value::Null,
                franking_proof: Value::Null,
                description: Some("unsolicited message".to_owned()),
            };

            let response = client.mimi_report_abuse(&request).await.unwrap();
            assert_eq!(response.status, "queued");

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_arkret/open/mimi/report-abuse "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["abuse_reason_code"], "spam");
            assert_eq!(parsed["reporter"], "did:webvh:z6mkfixture:alice.example");
        }

        #[tokio::test]
        async fn events_submit_returns_partial_status() {
            let canned = r#"{
                "status": "partial",
                "accepted": ["ak:event:01904100-0000-7000-8000-a0086f45c575"],
                "rejected": [
                    {"id": "ak:event:01904100-0000-7000-8000-deadbeefdead", "reason_code": "schema_violation"}
                ]
            }"#;
            let (client, _capture) = spawn_capture_server(canned).await;

            let response = client
                .events_submit_batch(&[fixture_event("a"), fixture_event("b")])
                .await
                .unwrap();

            assert!(
                matches!(response.status, arkret_core::EventsSubmitStatus::Partial),
                "expected Partial status, got {:?}",
                response.status
            );
            assert_eq!(response.accepted.len(), 1);
            assert_eq!(response.rejected.len(), 1);
            assert_eq!(response.rejected[0].reason_code, "schema_violation");
        }

        /// S-6 (savfox SDK gap): the streaming API yields one
        /// [`AccountSubscribeFrame`] per NDJSON line, including across
        /// chunk boundaries. Backed by a minimal stub server that
        /// dribbles the body out in slices.
        async fn spawn_chunked_ndjson_server(body_parts: Vec<&'static str>) -> Client {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                // Read & discard request headers.
                let mut buf = [0u8; 4096];
                let mut acc = Vec::new();
                loop {
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    acc.extend_from_slice(&buf[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }

                let body: String = body_parts.iter().copied().collect();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                for part in body_parts {
                    socket.write_all(part.as_bytes()).await.unwrap();
                    // Yield so the client side observes >1 chunk.
                    tokio::task::yield_now().await;
                }
                socket.shutdown().await.ok();
            });

            let base = Url::parse(&format!("http://{addr}/")).unwrap();
            Client::builder(base)
                .allow_insecure_localhost()
                .build()
                .unwrap()
        }

        #[tokio::test]
        async fn account_subscribe_frames_yields_one_frame_per_line() {
            use arkret_core::AccountSubscribeFrame;
            use futures_util::StreamExt;

            // Three frames split across 4 chunks; the second frame
            // straddles a chunk boundary mid-line so the codec must
            // buffer to assemble it.
            let parts = vec![
                r#"{"kind":"heartbeat"}"#,
                "\n{\"cursor\":\"sx:adv:1\"",
                ",\"kind\":\"frontier\"}\n",
                "{\"cursor\":\"sx:live:0\",\"kind\":\"catchup_complete\"}\n",
            ];
            let client = spawn_chunked_ndjson_server(parts).await;
            let mut stream = client
                .account_subscribe_frames(&SyncRequestBody {
                    after: None,
                    catchup: None,
                    filter: None,
                    subscriptions: None,
                    wait_for: None,
                })
                .await
                .expect("stream init");

            let mut got = Vec::new();
            while let Some(item) = stream.next().await {
                got.push(item.expect("frame decode"));
            }
            assert_eq!(got.len(), 3, "expected 3 frames, got {got:?}");
            assert_eq!(
                got[0].kind,
                AccountSubscribeFrame::from_ndjson_line(r#"{"kind":"heartbeat"}"#)
                    .unwrap()
                    .unwrap()
                    .kind
            );
            assert!(got[1].cursor.is_some());
            assert!(got[2].is_catchup_complete());
        }

        #[tokio::test]
        async fn account_subscribe_once_surfaces_dropped_interrupt() {
            use arkret_core::AccountStreamInterrupt;

            // Benign keepalive first, then a `dropped` control frame: the
            // dropped frame must surface as a structured interrupt instead
            // of being skipped while waiting for a delta.
            let parts = vec![
                "{\"kind\":\"heartbeat\"}\n",
                "{\"kind\":\"dropped\",\"cursor\":\"sx:drop:9\",\"reconnect_after_ms\":10000}\n",
            ];
            let client = spawn_chunked_ndjson_server(parts).await;
            let error = client
                .account_subscribe_once(&SyncRequestBody {
                    after: None,
                    catchup: Some(true),
                    filter: None,
                    subscriptions: None,
                    wait_for: None,
                })
                .await
                .unwrap_err();

            match error {
                Error::AccountStreamInterrupt(AccountStreamInterrupt::Dropped {
                    cursor,
                    reconnect_after_ms,
                }) => {
                    assert_eq!(cursor.as_deref(), Some("sx:drop:9"));
                    assert_eq!(reconnect_after_ms, Some(10_000));
                }
                other => panic!("expected dropped interrupt, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn account_subscribe_once_surfaces_unauthorized_interrupt() {
            use arkret_core::AccountStreamInterrupt;

            let parts = vec!["{\"kind\":\"unauthorized\",\"reason\":\"revoked\"}\n"];
            let client = spawn_chunked_ndjson_server(parts).await;
            let error = client
                .account_subscribe_once(&SyncRequestBody {
                    after: None,
                    catchup: Some(true),
                    filter: None,
                    subscriptions: None,
                    wait_for: None,
                })
                .await
                .unwrap_err();

            assert!(matches!(
                error,
                Error::AccountStreamInterrupt(AccountStreamInterrupt::Unauthorized { reason })
                    if reason.as_deref() == Some("revoked")
            ));
        }

        #[tokio::test]
        async fn events_submit_with_options_sends_idempotency_key() {
            let canned = r#"{"status":"accepted","accepted":["ak:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let options = ClientRequestOptions::new().idempotency_key("evt-idem-1");
            client
                .events_submit_with_options(&fixture_event("hello"), &options)
                .await
                .unwrap();

            let raw = capture.await.unwrap();
            let (request_line, headers, _body) = split_request(&raw);
            assert!(request_line.starts_with("POST /_arkret/self/events "));
            assert!(
                headers
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("idempotency-key: evt-idem-1")),
                "missing Idempotency-Key header: {headers}"
            );
        }
    }
}
