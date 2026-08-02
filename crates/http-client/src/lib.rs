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

use arkret_signatures::http_signature::Ed25519SigningKey;
use reqwest::Method;
#[cfg(any(not(target_arch = "wasm32"), test))]
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use url::Url;

pub mod account_subscribe;
mod builder;
mod client_internals;
mod endpoints_account;
mod endpoints_agent;
mod endpoints_data;
mod endpoints_events;
mod endpoints_identity;
mod endpoints_join_policy;
mod endpoints_misc;
mod endpoints_security;
mod endpoints_signal;
mod error;
mod subscribe_body;
// Production reqwest + Tokio DID resolver. Leans on a live Tokio runtime,
// blocking off-thread scheduling, and reqwest's native transport, none of
// which exist on the wasm32 fetch backend — native-only.
#[cfg(not(target_arch = "wasm32"))]
pub mod http_did_resolver;
pub mod key_backup_client;

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
pub use endpoints_account::{AccountSubscribeFrameStream, login_did_proof};
pub use endpoints_agent::AgentRuntimeApprovalStatusResponse;
pub use endpoints_data::{
    BlobDownloadOptions, BlobResumableUploadOptions, RESUMABLE_UPLOAD_FEATURE,
    RESUMABLE_UPLOAD_THRESHOLD_BYTES, blob_resumable_upload_base_url,
};
pub use endpoints_events::{EventsSubscribeFrameStream, EventsSubscribeOptions};
pub use endpoints_join_policy::JoinApplicationListOptions;
pub use endpoints_misc::SignedAppletTransactionOptions;
pub use endpoints_signal::SignalSubscribeFrameStream;
pub use error::{Error, Result};

pub const HEADER_REQUEST_ID: &str = "X-Arkret-Request-Id";
pub const HEADER_WAIT_FOR: &str = "X-Arkret-Wait-For";
pub const HEADER_IDEMPOTENCY_KEY: &str = "Idempotency-Key";

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
    authorization_scheme: DpopAuthorizationScheme,
    proof: Arc<DpopProofCallback>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DpopAuthorizationScheme {
    Bearer,
    Dpop,
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
            authorization_scheme: DpopAuthorizationScheme::Bearer,
            proof: Arc::new(proof),
        }
    }

    pub fn with_access_token(
        access_token: impl Into<String>,
        proof: impl Fn(DpopProofRequest) -> Result<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            access_token: Some(access_token.into()),
            authorization_scheme: DpopAuthorizationScheme::Bearer,
            proof: Arc::new(proof),
        }
    }

    /// Build authentication for credentials whose wire authorization scheme
    /// is `DPoP`, such as `account_handoff_grant`. This is distinct from an
    /// Arkret session grant, which uses `Bearer <ak.session.grant>` plus a
    /// DPoP proof header.
    pub fn with_dpop_token(
        token: impl Into<String>,
        proof: impl Fn(DpopProofRequest) -> Result<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            access_token: Some(token.into()),
            authorization_scheme: DpopAuthorizationScheme::Dpop,
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
    /// `SPEC_MAX_DEFAULT_RETRIES` retries (`max_retries` is clamped).
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
    /// A server-directed `Retry-After` is authoritative: it is **not**
    /// truncated by `max_delay` and gets no jitter (api-conventions.md §9:
    /// clients MUST prefer the server instruction).
    #[cfg(any(not(target_arch = "wasm32"), test))]
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
mod tests {
    use arkret_wire::{ProfileId, SchemaId};
    use reqwest::Method;
    use reqwest::header::{HeaderValue, USER_AGENT};

    use super::*;
    use crate::Error;

    #[test]
    fn auth_debug_redacts_all_credentials() {
        for (auth, secret) in [
            (Auth::Bearer("bearer-secret".to_owned()), "bearer-secret"),
            (
                Auth::DeviceProof("device-secret".to_owned()),
                "device-secret",
            ),
            (
                Auth::ServiceSignature("service-secret".to_owned()),
                "service-secret",
            ),
        ] {
            let debug = format!("{auth:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains(secret));
        }
    }

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
    fn account_handoff_auth_uses_dpop_authorization_scheme() {
        let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
            .auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "handoff-secret",
                |req| {
                    assert_eq!(req.method, "POST");
                    assert_eq!(
                        req.htu,
                        "https://alice.example/arkret/_arkret/gate/account/register"
                    );
                    assert_eq!(req.access_token.as_deref(), Some("handoff-secret"));
                    Ok("handoff-proof.jwt".to_owned())
                },
            )))
            .build()
            .unwrap();
        let request = client
            .request(Method::POST, "/_arkret/gate/account/register")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.headers()["authorization"], "DPoP handoff-secret");
        assert_eq!(request.headers()["dpop"], "handoff-proof.jwt");
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

        use arkret_models_collaboration::http_bodies::{
            DirectConversationResolveRequestBody, MimiReportAbuseRequestBody,
        };
        use arkret_models_collaboration::objects::blob::BlobUploadMetadata;
        use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
        use arkret_models_crypto::MlsGovernanceProofRequestBodyBody;
        use arkret_models_discovery::{
            DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
        };
        use arkret_wire::{
            AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
            AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
            AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, BlobRef, DeviceId,
            Did, DidUrl, Event, EventId, EventInitialSubmission, EventRequirements, Hash, Hlc,
            LeaseBasisRef, MimiRoomUri, NonEmptyString, PayloadProof, RealmId, RiskTier, ScopeRef,
            SealId, ServiceKind, StrandId, proof_kind,
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
            let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap();
            Event {
                event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
                kind: "ak.message.create".into(),
                realm_id: realm_id.clone(),
                scope_ref: ScopeRef::Realm { realm_id },
                actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                actor_seq: 1,
                created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
                hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
                prev_refs: Vec::new(),
                refs: Vec::new(),
                preconditions: Vec::new(),
                seal_ref: None,
                auth_context: None,
                seal_basis: None,
                requirements: EventRequirements::default(),
                redacts: None,
                payload: BTreeMap::from([("body".to_owned(), json!(content_body))]),
                executed_by: None,
                authorization_ref: None,
                applet_id: None,
                external_ref: None,
                actor_kind: None,
                unsigned: BTreeMap::new(),
                causal_refs: Vec::new(),
                proofs: Vec::new(),
            }
        }

        /// Wrap a fixture Event in the publication evidence the v1 submit rail
        /// requires. An Event never travels alone here: the lease is what
        /// bounds the revocation window, and only the caller can mint it.
        ///
        /// The lease must bind to the Event it authorizes — same `actor_id`,
        /// same signed `scope_ref` — and its `expires_at - issued_at` must
        /// stay inside the [`RiskTier::Low`] ceiling of 24h. Each proof covers
        /// the lease digest (computed with `proofs` removed, so a proof commits
        /// to every other member) and carries `created_at == issued_at`. The
        /// JWS is a placeholder: these tests assert wire shape, and the SDK
        /// methods under test do not verify signatures.
        fn fixture_submission(content_body: &str) -> EventInitialSubmission {
            let event = fixture_event(content_body);
            let issued_at: chrono::DateTime<chrono::Utc> =
                "2026-04-26T00:00:00.000Z".parse().unwrap();
            let authority_set_policy = AuthoritySetPolicy {
                schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
                authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
                policy_kind: AuthoritySetPolicyKind::RealmAdmission,
                scope_ref: event.scope_ref.clone(),
                source: AuthoritySetPolicySource {
                    source_kind: AuthoritySetSourceKind::RealmControl,
                    source_ref: event.event_id.as_str().to_owned(),
                    source_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
                    generation_ref: "1".to_owned(),
                },
                authorization_rules: vec![AuthoritySetAuthorizationRule {
                    rule_id: "realm_admission".to_owned(),
                    issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                    allowed_actions: vec![event.kind.as_str().to_owned()],
                    issuers: vec![AuthoritySetIssuer {
                        verification_method: DidUrl::new(
                            "did:webvh:z6mkfixture:authority.example#key-1",
                        )
                        .unwrap(),
                    }],
                    threshold: 1,
                }],
            };
            let mut authorization_lease = AuthorizationLease {
                authorization_lease_id: AuthorizationLeaseId::new(
                    "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
                )
                .unwrap(),
                basis_ref: LeaseBasisRef::Seal(
                    SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
                ),
                actor_id: event.actor_id.clone(),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
                scope_ref: event.scope_ref.clone(),
                action: event.kind.as_str().to_owned(),
                authorization_rule_id: "realm_admission".to_owned(),
                risk_tier: RiskTier::Low,
                issued_at,
                expires_at: issued_at + chrono::Duration::hours(1),
                authority_set_ref: AuthoritySetRef {
                    authority_set_id: authority_set_policy.authority_set_id.clone(),
                    authority_set_digest: authority_set_policy.digest().unwrap(),
                },
                authority_set_policy,
                proofs: Vec::new(),
            };
            let lease_digest = authorization_lease.lease_digest().unwrap();
            authorization_lease.proofs = vec![PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                    .unwrap(),
                payload_digest: lease_digest,
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }];

            EventInitialSubmission {
                event,
                authorization_lease: Some(authorization_lease),
                // Optional receiver-relative dependency evidence; the fixture
                // Event cites no seal_ref / seal_basis, so it needs none.
                cba_proof_bundles: Vec::new(),
                control_proposal_receipt: None,
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
        async fn events_submit_single_posts_initial_submission() {
            let canned = r#"{"status":"accepted","accepted":["ak:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let submission = fixture_submission("hello");
            let response = client.events_submit(&submission).await.unwrap();

            assert!(matches!(
                response.status,
                arkret_models_collaboration::http_bodies::EventsSubmitStatus::Accepted
            ));
            assert_eq!(response.accepted.len(), 1);

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_arkret/self/events "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            // The wire body is the single `EventInitialSubmission` arm: the
            // Event under `event`, its lease beside it, and no `events[]`
            // batch wrapper.
            assert!(
                parsed.get("events").is_none(),
                "single submission POST must not wrap in events[]: {parsed}"
            );
            assert_eq!(parsed["event"]["kind"], "ak.message.create");
            assert_eq!(parsed["event"]["payload"]["body"], "hello");
            assert_eq!(
                parsed["event"]["actor_id"],
                "did:webvh:z6mkfixture:alice.example"
            );
            // The lease is publication evidence, not an Event field: it sits
            // next to the envelope and never inside it.
            assert!(parsed["event"].get("authorization_lease").is_none());
            assert_eq!(
                parsed["authorization_lease"]["actor_id"],
                "did:webvh:z6mkfixture:alice.example"
            );
            assert_eq!(
                parsed["authorization_lease"]["scope_ref"],
                parsed["event"]["scope_ref"]
            );
        }

        #[tokio::test]
        async fn mls_governance_proof_posts_typed_request() {
            let (client, capture) = spawn_capture_server("{}").await;
            let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap();
            let request = MlsGovernanceProofRequestBodyBody {
                realm_id: realm_id.clone(),
                effective_scope: ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                mls_group_id: "Z3JvdXA".to_owned(),
                previous_epoch: 0,
                next_epoch: 0,
                binding_profile: ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1.to_owned(),
                reducer_profile: "ak.reducer.v1".to_owned(),
                trusted_anchor_seal_id: SealId::new(
                    "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                chunk_index: 0,
                expected_bundle_digest: None,
            };

            client.mls_governance_proof(&request).await.unwrap_err();

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_arkret/self/events/mls-governance-proof "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["realm_id"], realm_id.as_str());
            assert_eq!(parsed["effective_scope"]["kind"], "realm");
            assert_eq!(parsed["mls_group_id"], "Z3JvdXA");
            assert_eq!(parsed["previous_epoch"], 0);
            assert_eq!(parsed["next_epoch"], 0);
            assert_eq!(
                parsed["binding_profile"],
                ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1
            );
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
                    "blob_ref=ak%3Ablob%3Asha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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

            let submission = fixture_submission("signed");
            client.events_submit(&submission).await.unwrap();

            let raw = capture.await.unwrap();
            let (_request_line, headers, body) = split_request(&raw);
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
            arkret_canonical::canonical::validate_canonical_bytes(&body)
                .expect("signed HTTP body must be canonical JSON");
            let content_digest = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-digest")
                        .then_some(value.trim())
                })
                .expect("content-digest header");
            let content_digest =
                arkret_signatures::http_signature::ContentDigest::parse(content_digest).unwrap();
            arkret_signatures::http_signature::verify_content_digest(&content_digest, &body)
                .expect("content digest must cover exact canonical body bytes");
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
        async fn dpop_auth_does_not_authenticate_public_describe() {
            let canned = r#"{
                "protocol_version":"1.0",
                "service_kind":"principal_server",
                "service_id":"did:web:server.local",
                "trust_domain":"ak:trust_domain:server.local",
                "supported_profiles":[],
                "supported_operations":[],
                "supported_bindings":[],
                "supported_features":[],
                "auth_metadata":{"mode":"development","methods":[]},
                "limits":{},
                "plaintext_visibility":{"data_classes":[],"max_visibility":"none"},
                "implemented_features":[],
                "claimed_profiles":[],
                "verified_profiles":[],
                "experimental_features":[],
                "compat_surfaces":[],
                "development_mode":false,
                "rate_limit_policy":{}
            }"#;
            let (client, capture) = spawn_capture_server_with(canned, |builder| {
                builder.auth(Auth::Dpop(DpopAuth::with_access_token(
                    "session-grant",
                    |_| Ok("proof.jwt".to_owned()),
                )))
            })
            .await;

            client.describe().await.unwrap();

            let raw = capture.await.unwrap();
            let (_request_line, headers, _body) = split_request(&raw);
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            );
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("dpop:"))
            );
        }

        #[tokio::test]
        async fn role_scoped_describe_sends_selector_and_rejects_mismatched_response() {
            let canned = r#"{
                "protocol_version":"1.0",
                "service_kind":"principal_server",
                "service_id":"did:web:server.local",
                "trust_domain":"ak:trust_domain:server.local",
                "supported_profiles":[],
                "supported_operations":[],
                "supported_bindings":[],
                "supported_features":[],
                "auth_metadata":{"mode":"development","methods":[]},
                "limits":{},
                "plaintext_visibility":{"data_classes":[],"max_visibility":"none"},
                "implemented_features":[],
                "claimed_profiles":[],
                "verified_profiles":[],
                "experimental_features":[],
                "compat_surfaces":[],
                "development_mode":false,
                "rate_limit_policy":{}
            }"#;
            let (client, capture) = spawn_capture_server(canned).await;
            let description = client
                .describe_for_role(ServiceKind::PrincipalServer)
                .await
                .unwrap();
            assert_eq!(description.service_kind, ServiceKind::PrincipalServer);

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line
                    .starts_with("GET /_arkret/describe?service_kind=principal_server HTTP/1.1"),
                "unexpected request line: {request_line}",
            );

            let mismatched = Box::leak(
                canned
                    .replace(
                        "\"service_kind\":\"principal_server\"",
                        "\"service_kind\":\"auth_server\"",
                    )
                    .into_boxed_str(),
            );
            let (client, _capture) = spawn_capture_server(mismatched).await;
            assert!(
                client
                    .describe_for_role(ServiceKind::PrincipalServer)
                    .await
                    .is_err()
            );
        }

        #[tokio::test]
        async fn events_submit_batch_posts_events_array() {
            let canned = r#"{"status":"accepted","accepted":["ak:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let submissions = vec![fixture_submission("first"), fixture_submission("second")];
            let response = client.events_submit_batch(&submissions).await.unwrap();
            assert!(matches!(
                response.status,
                arkret_models_collaboration::http_bodies::EventsSubmitStatus::Accepted
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
            assert_eq!(arr[0]["event"]["payload"]["body"], "first");
            assert_eq!(arr[1]["event"]["payload"]["body"], "second");
            // Every element is a full submission: each Event carries its own
            // lease rather than sharing one for the batch.
            assert!(arr[0].get("authorization_lease").is_some());
            assert!(arr[1].get("authorization_lease").is_some());
            // Idempotency is a header concern; the batch body has no such field.
            assert!(
                parsed.get("idempotency_key").is_none(),
                "batch body must not carry idempotency_key: {parsed}"
            );
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
            assert!(request_line.contains("realms=ak%3Arealm%3Atest"));
            assert!(request_line.contains("before=ak%3Acursor%3Aolder"));
            assert!(request_line.contains("after=ak%3Acursor%3Anewer"));
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
                response
                    .range_completeness
                    .as_ref()
                    .map(|completeness| completeness.attestation_refs.len()),
                Some(0)
            );

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line.starts_with("GET /_arkret/self/events?"),
                "unexpected request line: {request_line}",
            );
            assert!(request_line.contains("realms=ak%3Arealm%3Atest"));
            assert!(request_line.contains("after=ak%3Acursor%3Anewer"));
            assert!(request_line.contains("order=ascending"));
            assert!(request_line.contains("limit=50"));
            assert!(request_line.contains("include_completeness=true"));
        }

        #[tokio::test]
        async fn list_key_backups_includes_series_id_query() {
            let (client, capture) =
                spawn_capture_server(r#"{"backups":[],"has_more":false}"#).await;
            let query = arkret_models_crypto::KeyBackupsListQuery {
                series_id: Some(
                    arkret_wire::BackupSeriesId::new(
                        "ak:backup_series:01964137-0000-7000-8000-000000000777",
                    )
                    .unwrap(),
                ),
                backup_kind: Some(arkret_models_crypto::BackupKind::DidRecovery),
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
                    "series_id=ak%3Abackup_series%3A01964137-0000-7000-8000-000000000777"
                )
            );
            assert!(request_line.contains("backup_kind=did_recovery"));
            assert!(request_line.contains("limit=25"));
        }

        #[tokio::test]
        async fn directory_private_contact_discovery_posts_canonical_path() {
            let (client, capture) = spawn_capture_server(
                r#"{"phase":"match","profile":"ak.private_contact_discovery.v1","batch_id":"ak:batch:01964137-0000-7000-8000-000000000777","key_epoch":14,"hit_bitmap":[false],"padding_count":0}"#,
            )
            .await;
            let request = DirectoryPrivateContactDiscoveryRequestBody::Blind {
                profile: "ak.private_contact_discovery.v1".to_owned(),
                batch_id: arkret_wire::BatchId::new(
                    "ak:batch:01964137-0000-7000-8000-000000000777",
                )
                .unwrap(),
                ciphersuite: "OPRF-ristretto255-SHA512".to_owned(),
                key_epoch: 14,
                blinded_elements: vec!["dGVzdA".to_owned()],
            };

            let response = client
                .directory_private_contact_discovery(&request)
                .await
                .unwrap();
            assert!(matches!(
                response,
                DirectoryPrivateContactDiscoveryOutcome::Match { .. }
            ));

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_arkret/find/directory/private-contact-discovery "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["phase"], "blind");
            assert_eq!(parsed["profile"], "ak.private_contact_discovery.v1");
            assert_eq!(parsed["ciphersuite"], "OPRF-ristretto255-SHA512");
            assert!(parsed.get("requester").is_none());
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
                peer_claim_request: None,
            };

            let response = client.direct_conversation_resolve(&request).await.unwrap();
            assert_eq!(
                response.state,
                arkret_models_collaboration::http_bodies::DirectConversationResolveState::Found
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
            let (client, capture) = spawn_capture_server(
                r#"{
                    "schema":"ak.schema.mimi_interop.v1",
                    "service_id":"did:web:mimi.example.test",
                    "service_kind":"mimi_provider",
                    "supported_profiles":["ak.profile.mimi_interop.v1"],
                    "mimi":{
                        "protocol_draft":"draft-ietf-mimi-protocol-04",
                        "content_draft":"draft-ietf-mimi-content-04",
                        "room_policy_draft":"draft-ietf-mimi-room-policy-03",
                        "identifier_draft":"draft-kohbrok-mimi-identifiers-01",
                        "base_url":"https://mimi.example.test",
                        "provider_id":"provider-a",
                        "endpoints":[{"endpoint_id":"mimi_v1","relative_path":"/messages"}],
                        "features":["mimi_v1"],
                        "mls_cipher_suites":["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                        "content_profiles":["application/mimi-content"],
                        "room_policy_components":["membership"]
                    },
                    "proof":{
                        "kind":"detached_jws",
                        "verification_method":"did:web:mimi.example.test#notary-key",
                        "alg":"EdDSA",
                        "payload_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
                        "created_at":"2026-08-01T00:00:00.000Z",
                        "jws":"eyJhbGciOiJFZERTQSJ9..c2ln"
                    }
                }"#,
            )
            .await;
            let features = vec!["blind_wakeup".to_owned(), "mimi_v1".to_owned()];

            let response = client
                .mimi_provider_directory(Some("provider-a"), &features)
                .await
                .unwrap();
            assert_eq!(response.service_kind, "mimi_provider");
            assert_eq!(response.mimi.provider_id, "provider-a");
            assert_eq!(response.mimi.features, ["mimi_v1"]);

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
                mimi_room_uri: Some(MimiRoomUri::new("mimi://provider/rooms/room-1").unwrap()),
                realm_id: None,
                target_ref: NonEmptyString::new("mimi://provider/rooms/room-1/messages/msg-1")
                    .unwrap(),
                reporter: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                abuse_reason_code: NonEmptyString::new("spam").unwrap(),
                evidence_package: None,
                franking_proof: None,
                description: Some(NonEmptyString::new("unsolicited message").unwrap()),
            };

            let response = client.mimi_report_abuse(&request).await.unwrap();
            assert_eq!(response.status.as_str(), "queued");

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
                .events_submit_batch(&[fixture_submission("a"), fixture_submission("b")])
                .await
                .unwrap();

            assert!(
                matches!(
                    response.status,
                    arkret_models_collaboration::http_bodies::EventsSubmitStatus::Partial
                ),
                "expected Partial status, got {:?}",
                response.status
            );
            assert_eq!(response.accepted.len(), 1);
            assert_eq!(response.rejected.len(), 1);
            assert_eq!(
                response.rejected[0].reason_code.as_str(),
                "schema_violation"
            );
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
            use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;

            // Four frames split across chunks; the frontier frame
            // straddles a chunk boundary mid-line so the codec must
            // buffer to assemble it.
            let parts = vec![
                r#"{"kind":"heartbeat"}"#,
                "\n{\"cursor\":\"ak:cursor:adv-1\"",
                ",\"kind\":\"frontier\"}\n",
                "{\"cursor\":\"ak:cursor:delta-1\",\"kind\":\"delta\",\"partial\":false}\n",
                "{\"cursor\":\"ak:cursor:live-0\",\"kind\":\"catchup_complete\"}\n",
            ];
            let client = spawn_chunked_ndjson_server(parts).await;
            let mut stream = client
                .account_subscribe_frames(&SyncRequestBody {
                    after: None,
                    catchup: Some(true),
                    filter: None,
                    subscriptions: None,
                })
                .await
                .expect("stream init");

            let mut got = Vec::new();
            while let Some(frame) = stream.next_frame().await.expect("frame decode") {
                got.push(frame);
            }
            assert_eq!(got.len(), 4, "expected 4 frames, got {got:?}");
            assert_eq!(
                got[0].kind,
                AccountSubscribeFrame::from_ndjson_line(r#"{"kind":"heartbeat"}"#)
                    .unwrap()
                    .unwrap()
                    .kind
            );
            assert!(got[1].cursor.is_some());
            assert_eq!(got[2].kind, arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta);
            assert!(got[3].is_catchup_complete());
            assert_eq!(stream.reconnect_cursor(), Some("ak:cursor:live-0"));
        }

        #[tokio::test]
        async fn account_subscribe_batch_waits_for_valid_catchup_completion() {
            let parts = vec![
                "{\"cursor\":\"ak:cursor:delta-1\",\"kind\":\"delta\",\"partial\":true}\n",
                "{\"cursor\":\"ak:cursor:delta-2\",\"kind\":\"delta\",\"partial\":false}\n",
                "{\"cursor\":\"ak:cursor:complete-2\",\"kind\":\"catchup_complete\"}\n",
            ];
            let client = spawn_chunked_ndjson_server(parts).await;
            let outcome = client
                .account_subscribe_batch(&SyncRequestBody {
                    after: None,
                    catchup: Some(true),
                    filter: None,
                    subscriptions: None,
                })
                .await
                .unwrap();

            assert_eq!(outcome.cursor, "ak:cursor:complete-2");
            assert_eq!(outcome.frames.len(), 2);
            assert_eq!(outcome.frames[1].partial, Some(false));
        }

        #[tokio::test]
        async fn account_subscribe_batch_returns_while_live_body_stays_open() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let count = socket.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..count]);
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\
                          Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
                    )
                    .await
                    .unwrap();
                for frame in [
                    "{\"cursor\":\"ak:cursor:delta-live\",\"kind\":\"delta\",\"partial\":false}\n",
                    "{\"cursor\":\"ak:cursor:catchup-live\",\"kind\":\"catchup_complete\"}\n",
                ] {
                    socket
                        .write_all(format!("{:X}\r\n{}\r\n", frame.len(), frame).as_bytes())
                        .await
                        .unwrap();
                }
                let _ = release_rx.await;
                let _ = socket.write_all(b"0\r\n\r\n").await;
            });

            let client = Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
                .allow_insecure_localhost()
                .build()
                .unwrap();
            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                client.account_subscribe_batch(&SyncRequestBody {
                    after: None,
                    catchup: Some(true),
                    filter: None,
                    subscriptions: None,
                }),
            )
            .await
            .expect("account batch must not wait for the live response body to close")
            .unwrap();
            release_tx.send(()).ok();

            assert_eq!(outcome.cursor, "ak:cursor:catchup-live");
            assert_eq!(outcome.frames.len(), 1);
        }

        #[tokio::test]
        async fn account_subscribe_batch_surfaces_dropped_interrupt() {
            use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;

            // Benign keepalive first, then a `dropped` control frame: the
            // dropped frame must surface as a structured interrupt instead
            // of being skipped while waiting for a delta.
            let parts = vec![
                "{\"kind\":\"heartbeat\"}\n",
                "{\"kind\":\"dropped\",\"cursor\":\"ak:cursor:drop-9\",\"reconnect_after_ms\":10000}\n",
            ];
            let client = spawn_chunked_ndjson_server(parts).await;
            let error = client
                .account_subscribe_batch(&SyncRequestBody {
                    after: None,
                    catchup: Some(true),
                    filter: None,
                    subscriptions: None,
                })
                .await
                .unwrap_err();

            match error {
                Error::AccountStreamInterrupt(AccountStreamInterrupt::Dropped {
                    cursor,
                    reconnect_after_ms,
                }) => {
                    assert_eq!(cursor, "ak:cursor:drop-9");
                    assert_eq!(reconnect_after_ms, Some(10_000));
                }
                other => panic!("expected dropped interrupt, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn account_subscribe_batch_surfaces_unauthorized_interrupt() {
            use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;

            let parts = vec!["{\"kind\":\"unauthorized\"}\n"];
            let client = spawn_chunked_ndjson_server(parts).await;
            let error = client
                .account_subscribe_batch(&SyncRequestBody {
                    after: None,
                    catchup: Some(true),
                    filter: None,
                    subscriptions: None,
                })
                .await
                .unwrap_err();

            assert!(matches!(
                error,
                Error::AccountStreamInterrupt(AccountStreamInterrupt::Unauthorized)
            ));
        }

        #[tokio::test]
        async fn events_submit_with_options_sends_idempotency_key() {
            let canned = r#"{"status":"accepted","accepted":["ak:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let options = ClientRequestOptions::new().idempotency_key("evt-idem-1");
            client
                .events_submit_with_options(&fixture_submission("hello"), &options)
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
