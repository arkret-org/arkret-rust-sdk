use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use url::Url;

mod builder;
mod client_internals;
mod endpoints_account;
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
pub(crate) use client_internals::{reject_path_segment, validate_request_builder};

pub const HEADER_REQUEST_ID: &str = "X-Cokret-Request-Id";
pub const HEADER_WAIT_FOR: &str = "X-Cokret-Wait-For";
pub const HEADER_IDEMPOTENCY_KEY: &str = "Idempotency-Key";

/// Default total request timeout applied per request when
/// [`ClientBuilder::timeout`] is not called. reqwest itself defaults to
/// *no* timeout, which would let a hung server (SYN black hole,
/// never-ending body) suspend the caller forever; this crate is the
/// shared transport for all Cokret services, so the default must be
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryConfig {
    pub max_retries: usize,
    pub retry_statuses: Vec<u16>,
    pub retry_network_errors: bool,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub respect_retry_after: bool,
}

impl RetryConfig {
    pub fn disabled() -> Self {
        Self {
            max_retries: 0,
            retry_statuses: standard_retry_statuses(),
            retry_network_errors: true,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            respect_retry_after: true,
        }
    }

    pub fn standard(max_retries: usize) -> Self {
        Self {
            max_retries,
            retry_statuses: standard_retry_statuses(),
            retry_network_errors: true,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            respect_retry_after: true,
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
        if self.max_delay.is_zero() {
            delay
        } else {
            std::cmp::min(delay, self.max_delay)
        }
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn retry_delay_from_headers(&self, headers: &HeaderMap, attempt: usize) -> Duration {
        if self.respect_retry_after
            && let Some(retry_after_ms) = retry_after_ms(headers)
        {
            let retry_after = Duration::from_millis(retry_after_ms);
            return if self.max_delay.is_zero() {
                retry_after
            } else {
                std::cmp::min(retry_after, self.max_delay)
            };
        }
        self.retry_delay(attempt)
    }
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
    pub(crate) retry: RetryConfig,
    pub(crate) user_agent: Option<String>,
    /// Per-request total timeout applied by [`Client::request`] when the
    /// builder did not set an explicit client-wide timeout and did not
    /// inject a pre-built `reqwest::Client`. `None` means the transport
    /// configuration is caller-owned. Subscribe streams skip this.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) default_timeout: Option<Duration>,
}

/// Parse the `Retry-After` header (delta-seconds form) into milliseconds.
/// Used by [`RetryConfig::retry_delay_from_headers`] and the error-envelope
/// hydration in `client_internals`.
pub(crate) fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
}

fn standard_retry_statuses() -> Vec<u16> {
    vec![408, 429, 500, 502, 503, 504]
}

#[cfg(test)]
mod tests {
    use cokret_core::Error;
    use reqwest::Method;
    use reqwest::header::{HeaderValue, USER_AGENT};

    use super::*;

    #[test]
    fn builds_relative_api_url() {
        let client = Client::new(Url::parse("https://alice.example/cokret/").unwrap()).unwrap();
        let request = client
            .request(Method::GET, "/_cokret/describe")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://alice.example/cokret/_cokret/describe"
        );
    }

    #[test]
    fn rejects_remote_http_by_default() {
        let error = Client::new(Url::parse("http://alice.example/cokret/").unwrap()).unwrap_err();
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
        let client = Client::new(Url::parse("https://alice.example/cokret/").unwrap()).unwrap();
        let error = client
            .request(Method::GET, "https://evil.example/api")
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn rejects_header_unsafe_auth_material() {
        let error = Client::builder(Url::parse("https://alice.example/cokret/").unwrap())
            .auth(Auth::Bearer("token\r\nX-Evil: true".to_owned()))
            .build()
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn rejects_encoded_path_separator_segments() {
        let error = reject_path_segment("txn_%2Fescape").unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn request_options_add_standard_headers() {
        let client = Client::builder(Url::parse("https://alice.example/cokret/").unwrap())
            .user_agent("cokret-sdk-test/1")
            .build()
            .unwrap();
        let options = ClientRequestOptions::new()
            .request_id("req-1")
            .idempotency_key("idem-1")
            .wait_for("ck:cursor:01");
        let request = client
            .apply_request_options(
                client.request(Method::PUT, "/_cokret/self/events").unwrap(),
                &options,
            )
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.headers()[USER_AGENT], "cokret-sdk-test/1");
        assert_eq!(request.headers()[HEADER_REQUEST_ID], "req-1");
        assert_eq!(request.headers()[HEADER_IDEMPOTENCY_KEY], "idem-1");
        assert_eq!(request.headers()[HEADER_WAIT_FOR], "ck:cursor:01");
    }

    #[test]
    fn request_options_reject_header_injection() {
        let client = Client::new(Url::parse("https://alice.example/cokret/").unwrap()).unwrap();
        let options = ClientRequestOptions::new().request_id("req\r\nX-Evil: true");

        let error = client
            .apply_request_options(
                client.request(Method::GET, "/_cokret/describe").unwrap(),
                &options,
            )
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn rejects_query_auth_on_base_path_and_built_request() {
        assert!(
            Client::new(Url::parse("https://alice.example/cokret/?access_token=secret").unwrap())
                .is_err()
        );

        let client = Client::new(Url::parse("https://alice.example/cokret/").unwrap()).unwrap();
        let builder = client
            .request(Method::GET, "/_cokret/self/events")
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
            .with_base_delay(Duration::from_millis(25))
            .with_max_delay(Duration::from_millis(80));

        assert_eq!(retry.retry_delay(1), Duration::from_millis(25));
        assert_eq!(retry.retry_delay(2), Duration::from_millis(50));
        assert_eq!(retry.retry_delay(3), Duration::from_millis(80));
        assert_eq!(retry.retry_delay(4), Duration::from_millis(80));
    }

    #[test]
    fn retry_config_respects_retry_after_with_max_delay_cap() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
        let retry = RetryConfig::standard(2).with_max_delay(Duration::from_secs(2));

        assert_eq!(
            retry.retry_delay_from_headers(&headers, 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            retry
                .respect_retry_after(false)
                .retry_delay_from_headers(&headers, 1),
            Duration::from_millis(100)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn transport_options_apply_without_panic() {
        let client = Client::builder(Url::parse("https://alice.example/cokret/").unwrap())
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

        assert_eq!(client.base_url().as_str(), "https://alice.example/cokret/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn proxy_can_be_added_via_builder() {
        let proxy = reqwest::Proxy::http("http://proxy.example:3128").unwrap();
        let client = Client::builder(Url::parse("https://alice.example/cokret/").unwrap())
            .proxy(proxy)
            .build()
            .unwrap();
        assert_eq!(client.base_url().as_str(), "https://alice.example/cokret/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn transport_options_conflict_with_pre_built_http_client() {
        let http = reqwest::Client::new();
        let error = Client::builder(Url::parse("https://alice.example/cokret/").unwrap())
            .http_client(http)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(message) if message.contains("transport options")));
    }

    #[test]
    fn pre_built_http_client_alone_is_accepted() {
        let http = reqwest::Client::new();
        let client = Client::builder(Url::parse("https://alice.example/cokret/").unwrap())
            .http_client(http)
            .build()
            .unwrap();
        assert_eq!(client.base_url().as_str(), "https://alice.example/cokret/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod events_submit_tests {
        use std::collections::BTreeMap;

        use cokret_core::{
            Did, DirectConversationResolveRequestBody, DirectoryPrivateContactDiscoveryRequestBody,
            Event, EventId, EventRequirements, Hlc, MimiReportAbuseRequestBody, RealmId, StrandId,
            SyncRequestBody,
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
                event_id: EventId::new("ck:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
                kind: "ck.message.create".into(),
                realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
                actor_id: Did::new("did:web:alice.example").unwrap(),
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
                content: json!({ "body": content_body }),
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
            let client = Client::builder(base)
                .allow_insecure_localhost()
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
            let canned = r#"{"status":"accepted","accepted":["ck:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let event = fixture_event("hello");
            let response = client.events_submit(&event).await.unwrap();

            assert!(matches!(
                response.status,
                cokret_core::EventsSubmitStatus::Accepted
            ));
            assert_eq!(response.accepted.len(), 1);

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_cokret/self/events "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            // The wire body is the bare envelope, not wrapped in `{"event":..}`
            // or `{"events":[..]}`.
            assert!(
                parsed.get("events").is_none(),
                "single-event POST must not wrap in events[]: {parsed}"
            );
            assert_eq!(parsed["kind"], "ck.message.create");
            assert_eq!(parsed["payload"]["body"], "hello");
            assert_eq!(parsed["actor_id"], "did:web:alice.example");
        }

        #[tokio::test]
        async fn events_submit_batch_posts_events_array() {
            let canned = r#"{"status":"accepted","accepted":["ck:event:01904100-0000-7000-8000-a0086f45c575"]}"#;
            let (client, capture) = spawn_capture_server(canned).await;

            let events = vec![fixture_event("first"), fixture_event("second")];
            let response = client.events_submit_batch(&events).await.unwrap();
            assert!(matches!(
                response.status,
                cokret_core::EventsSubmitStatus::Accepted
            ));

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(request_line.starts_with("POST /_cokret/self/events "));
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
                    "ck:realm:test",
                    Some("ck:cursor:older"),
                    Some("ck:cursor:newer"),
                    Some("descending"),
                    Some(20),
                )
                .await
                .unwrap();
            assert!(response.events.is_empty());

            let raw = capture.await.unwrap();
            let (request_line, _headers, _body) = split_request(&raw);
            assert!(
                request_line.starts_with("GET /_cokret/self/events?"),
                "unexpected request line: {request_line}",
            );
            assert!(!request_line.contains("/_cokret/self/events/query?"));
            assert!(request_line.contains("realms=ck%3Arealm%3Atest"));
            assert!(request_line.contains("before=ck%3Acursor%3Aolder"));
            assert!(request_line.contains("after=ck%3Acursor%3Anewer"));
            assert!(request_line.contains("order=descending"));
            assert!(request_line.contains("limit=20"));
        }

        #[tokio::test]
        async fn directory_private_contact_discovery_posts_canonical_path() {
            let (client, capture) = spawn_capture_server(r#"{"matches":[],"proofs":[]}"#).await;
            let request = DirectoryPrivateContactDiscoveryRequestBody {
                requester: Did::new("did:web:alice.example").unwrap(),
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
                request_line.starts_with("POST /_cokret/find/directory/private-contact-discovery "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["requester"], "did:web:alice.example");
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
                request_line.starts_with("GET /_cokret/self/contacts "),
                "unexpected request line: {request_line}",
            );
        }

        #[tokio::test]
        async fn direct_conversation_resolve_posts_spec_path_and_current_shape() {
            let canned = r#"{
                "state":"found",
                "realm_id":"ck:realm:01904100-0000-7000-8000-d10000000001",
                "main_strand_id":"ck:strand:01904100-0000-7000-8000-d10000000002",
                "binding_event_ref":"ck:event:01904100-0000-7000-8000-d10000000003",
                "created":false
            }"#;
            let (client, capture) = spawn_capture_server(canned).await;
            let request = DirectConversationResolveRequestBody {
                peer: Did::new("did:web:bob.example").unwrap(),
                create: true,
                idempotency_key: Some("dm-alice-bob".to_owned()),
            };

            let response = client.direct_conversation_resolve(&request).await.unwrap();
            assert_eq!(
                response.state,
                cokret_core::DirectConversationResolveState::Found
            );
            assert_eq!(
                response.binding_event_ref.as_ref().map(|id| id.as_str()),
                Some("ck:event:01904100-0000-7000-8000-d10000000003")
            );
            assert_eq!(response.created, Some(false));

            let raw = capture.await.unwrap();
            let (request_line, _headers, body) = split_request(&raw);
            assert!(
                request_line.starts_with("POST /_cokret/self/direct-conversations/resolve "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["peer"], "did:web:bob.example");
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
                request_line.starts_with("GET /_cokret/open/mimi/provider-directory?"),
                "unexpected request line: {request_line}",
            );
            assert!(request_line.contains("provider_id=provider-a"));
            assert!(request_line.contains("features=blind_wakeup"));
            assert!(request_line.contains("features=mimi_v1"));
        }

        #[tokio::test]
        async fn mimi_report_abuse_posts_canonical_path() {
            let (client, capture) = spawn_capture_server(
                r#"{"report_id":"ck:report:01904100-0000-7000-8000-a0086f45c575","status":"queued","routed_to":[]}"#,
            )
            .await;
            let request = MimiReportAbuseRequestBody {
                strand_id: StrandId::new("ck:strand:01904100-0000-7000-8000-f571eead1fc4").unwrap(),
                mimi_room_uri: Some("mimi://provider/rooms/room-1".to_owned()),
                realm_id: None,
                target_ref: "mimi://provider/rooms/room-1/messages/msg-1".to_owned(),
                reporter: Did::new("did:web:alice.example").unwrap(),
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
                request_line.starts_with("POST /_cokret/open/mimi/report-abuse "),
                "unexpected request line: {request_line}",
            );
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["abuse_reason_code"], "spam");
            assert_eq!(parsed["reporter"], "did:web:alice.example");
        }

        #[tokio::test]
        async fn events_submit_returns_partial_status() {
            let canned = r#"{
                "status": "partial",
                "accepted": ["ck:event:01904100-0000-7000-8000-a0086f45c575"],
                "rejected": [
                    {"event_id": "ck:event:01904100-0000-7000-8000-deadbeefdead", "reason": "schema_violation"}
                ]
            }"#;
            let (client, _capture) = spawn_capture_server(canned).await;

            let response = client
                .events_submit_batch(&[fixture_event("a"), fixture_event("b")])
                .await
                .unwrap();

            assert!(
                matches!(response.status, cokret_core::EventsSubmitStatus::Partial),
                "expected Partial status, got {:?}",
                response.status
            );
            assert_eq!(response.accepted.len(), 1);
            assert_eq!(response.rejected.len(), 1);
            assert_eq!(response.rejected[0]["reason"], "schema_violation");
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
            use cokret_core::AccountSubscribeFrame;
            use futures_util::StreamExt;

            // Three frames split across 4 chunks; the second frame
            // straddles a chunk boundary mid-line so the codec must
            // buffer to assemble it.
            let parts = vec![
                r#"{"kind":"heartbeat"}"#,
                "\n{\"kind\":\"frontier\"",
                ",\"cursor\":\"sx:adv:1\"}\n",
                "{\"kind\":\"catchup_complete\",\"cursor\":\"sx:live:0\"}\n",
            ];
            let client = spawn_chunked_ndjson_server(parts).await;
            let mut stream = client
                .account_subscribe_frames(&SyncRequestBody {
                    after: None,
                    catchup: None,
                    set_presence: None,
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
    }
}
