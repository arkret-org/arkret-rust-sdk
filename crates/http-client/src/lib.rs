use std::time::Duration;

use cokret_core::{
    AccountCursorRevokeOutcome, AccountCursorRevokeRequestBody, AccountSubscribeFrame,
    AppletActorView, AppletDescription, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletTransactionRequestBody, AuthzCheckOutcome,
    AuthzCheckRequestBody, AuthzInviteList, BackupId, BlobMetadata, BlobRef, BlobUploadMetadata,
    BlobUploadOutcome, ContactList, ContactRequestOutcome, ContactRequestRequestBody,
    ContactRespondOutcome, ContactRespondRequestBody, ContactTombstone,
    ContactTombstoneRequestBody, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesPutOutcome, DeviceMessagesPutRequestBody,
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, DirectConversationResolveOutcome,
    DirectConversationResolveRequestBody, DirectoryActorSearchOutcome,
    DirectoryAgentSelectorResolutionOutcome, DirectoryDescription,
    DirectoryHandleResolutionOutcome, DirectoryListHandlesForSubjectRequestBody,
    DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
    DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveAgentSelectorRequestBody, DirectoryResolveHandleRequestBody,
    DirectoryResolveOrganizationRequestBody, DirectoryResolveRealmRequestBody,
    DirectoryResolveTargetRequestBody, DirectorySearchActorsRequestBody,
    DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
    DirectorySearchUsersRequestBody, DirectorySubjectHandleList, DirectoryTargetResolutionOutcome,
    DirectoryUserSearchOutcome, Error, ErrorEnvelope, Event, EventsSubmitOutcome, GrantList,
    IdentityDescription, IdentityDocumentView, IdentityLogOutcome, IdentityReceiptsOutcome,
    IdentityResolveOutcome, IdentityResolveRequestBody, KeyBackup, KeyBackupSummary,
    KeyBackupsListQuery, KeysBackupsDeleteOutcome, KeysBackupsDeleteRequestBody, KeysBackupsList,
    KeysBackupsPutOutcome, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody, MediaIceConfigOutcome,
    MediaIceConfigRequestBody, MimiProviderDirectory, MimiReportAbuseOutcome,
    MimiReportAbuseRequestBody, ModerationReportOutcome, ModerationReportRequestBody, OkOutcome,
    PATH_SELF_CONTACTS, PATH_SELF_CONTACTS_REQUEST, PATH_SELF_CONTACTS_RESPOND,
    PATH_SELF_CONTACTS_TOMBSTONE, PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE, PolicyCheckOutcome,
    PolicyCheckRequestBody, PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceOutcome,
    PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody, Result, ServerDescription,
    ServiceRequirements, SessionGrantOutcome, SessionGrantRequestBody, SnapshotHeadState,
    SyncBackfillOutcome, SyncDescription, SyncOutcome, SyncRequestBody,
};
use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::sleep;
use url::Url;

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
const MAX_SUBSCRIBE_FRAME_BYTES: usize = 8 * 1024 * 1024;

const QUERY_AUTH_KEYS: &[&str] = &[
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

/// Wrap a reqwest transport error into the transport-agnostic
/// `cokret_core::Error::Http` variant at the crate boundary. cokret-core
/// deliberately carries no reqwest dependency (ARCHITECTURE.md: core is the
/// wire-model layer; the HTTP stack lives in this crate), so the conversion
/// is explicit here instead of a `#[from]` impl on the core error type.
fn transport_error(error: reqwest::Error) -> Error {
    Error::Http(error.to_string())
}

#[cfg(feature = "tracing")]
#[derive(Clone, Debug)]
struct RequestTraceFields {
    method: String,
    path: String,
}

#[cfg(feature = "tracing")]
fn request_trace_fields(builder: &RequestBuilder) -> Option<RequestTraceFields> {
    let request = builder.try_clone()?.build().ok()?;
    Some(RequestTraceFields {
        method: request.method().as_str().to_owned(),
        path: request.url().path().to_owned(),
    })
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

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
    fn should_retry_status(&self, status: StatusCode) -> bool {
        self.retry_statuses.contains(&status.as_u16())
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn retry_delay(&self, attempt: usize) -> Duration {
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
    fn retry_delay_from_headers(&self, headers: &HeaderMap, attempt: usize) -> Duration {
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
    base_url: Url,
    http: reqwest::Client,
    auth: Option<Auth>,
    retry: RetryConfig,
    user_agent: Option<String>,
    /// Per-request total timeout applied by [`Client::request`] when the
    /// builder did not set an explicit client-wide timeout and did not
    /// inject a pre-built `reqwest::Client`. `None` means the transport
    /// configuration is caller-owned. Subscribe streams skip this.
    #[cfg(not(target_arch = "wasm32"))]
    default_timeout: Option<Duration>,
}

/// Named redirect policies. `reqwest::redirect::Policy` is not `Clone`, so
/// we model the supported choices as a small enum and materialise a Policy
/// at `build()` time.
///
/// Native-only: `reqwest`'s `redirect` module is not compiled into the
/// wasm32 fetch backend (the browser handles redirects transparently), so
/// this enum and the corresponding [`ClientBuilder::redirect`] method are
/// gated out on wasm32.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub enum RedirectPolicy {
    /// Refuse to follow any redirects (typical service-to-service).
    None,
    /// Follow up to `limit` redirects, then return the last response.
    Limited(usize),
}

#[cfg(not(target_arch = "wasm32"))]
impl RedirectPolicy {
    fn into_reqwest(self) -> reqwest::redirect::Policy {
        match self {
            RedirectPolicy::None => reqwest::redirect::Policy::none(),
            RedirectPolicy::Limited(limit) => reqwest::redirect::Policy::limited(limit),
        }
    }
}

/// Native transport configuration applied to the underlying `reqwest::Client`.
///
/// Every field is optional. `None` means "let `reqwest` keep its default."
/// These options are silently ignored when [`ClientBuilder::http_client`] is
/// used to inject a fully-built `reqwest::Client` — in that mode the caller
/// owns the transport configuration end to end. [`ClientBuilder::build`]
/// returns [`Error::Protocol`] if both a pre-built client and any transport
/// option are set, to avoid silent surprises.
///
/// The wasm32 fetch backend exposes none of these knobs (the browser owns
/// the connection pool, proxy, redirect and timeout policies), so on wasm32
/// `TransportConfig` is a zero-sized stub that is always "default" and
/// applies as a no-op.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, Default)]
struct TransportConfig {
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: Option<usize>,
    tcp_nodelay: Option<bool>,
    tcp_keepalive: Option<Duration>,
    http2_keep_alive_interval: Option<Duration>,
    http2_keep_alive_timeout: Option<Duration>,
    http2_keep_alive_while_idle: Option<bool>,
    proxies: Vec<reqwest::Proxy>,
    no_proxy: bool,
    redirect: Option<RedirectPolicy>,
    gzip: Option<bool>,
}

#[cfg(not(target_arch = "wasm32"))]
impl TransportConfig {
    fn is_default(&self) -> bool {
        self.timeout.is_none()
            && self.connect_timeout.is_none()
            && self.pool_idle_timeout.is_none()
            && self.pool_max_idle_per_host.is_none()
            && self.tcp_nodelay.is_none()
            && self.tcp_keepalive.is_none()
            && self.http2_keep_alive_interval.is_none()
            && self.http2_keep_alive_timeout.is_none()
            && self.http2_keep_alive_while_idle.is_none()
            && self.proxies.is_empty()
            && !self.no_proxy
            && self.redirect.is_none()
            && self.gzip.is_none()
    }

    fn apply(self, mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        // An explicit total timeout applies client-wide (including the
        // subscribe streams — the caller asked for it). When unset, the
        // bounded [`DEFAULT_REQUEST_TIMEOUT`] is applied *per request*
        // in `Client::request` instead, so long-lived streams stay open.
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        // reqwest's own default is *no* connect timeout at all; always
        // bound the connection-establishment phase so a SYN black hole
        // can never suspend a caller forever.
        builder = builder.connect_timeout(self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT));
        if let Some(pool_idle_timeout) = self.pool_idle_timeout {
            builder = builder.pool_idle_timeout(pool_idle_timeout);
        }
        if let Some(pool_max_idle_per_host) = self.pool_max_idle_per_host {
            builder = builder.pool_max_idle_per_host(pool_max_idle_per_host);
        }
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            builder = builder.tcp_nodelay(tcp_nodelay);
        }
        if let Some(tcp_keepalive) = self.tcp_keepalive {
            builder = builder.tcp_keepalive(tcp_keepalive);
        }
        if let Some(http2_keep_alive_interval) = self.http2_keep_alive_interval {
            builder = builder.http2_keep_alive_interval(http2_keep_alive_interval);
        }
        if let Some(http2_keep_alive_timeout) = self.http2_keep_alive_timeout {
            builder = builder.http2_keep_alive_timeout(http2_keep_alive_timeout);
        }
        if let Some(http2_keep_alive_while_idle) = self.http2_keep_alive_while_idle {
            builder = builder.http2_keep_alive_while_idle(http2_keep_alive_while_idle);
        }
        for proxy in self.proxies {
            builder = builder.proxy(proxy);
        }
        if self.no_proxy {
            builder = builder.no_proxy();
        }
        if let Some(redirect) = self.redirect {
            builder = builder.redirect(redirect.into_reqwest());
        }
        if let Some(gzip) = self.gzip {
            builder = builder.gzip(gzip);
        }
        builder
    }
}

/// Wasm32 stub for `TransportConfig`. The fetch backend doesn't expose any
/// of the native transport knobs, so this is a zero-sized type that always
/// reports "default" and applies as a no-op.
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Default)]
struct TransportConfig;

#[cfg(target_arch = "wasm32")]
impl TransportConfig {
    fn is_default(&self) -> bool {
        true
    }

    fn apply(self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder
    }
}

#[derive(Clone, Debug)]
pub struct ClientBuilder {
    base_url: Url,
    http: Option<reqwest::Client>,
    auth: Option<Auth>,
    allow_insecure_localhost: bool,
    transport: TransportConfig,
    retry: RetryConfig,
    user_agent: Option<String>,
}

impl ClientBuilder {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            http: None,
            auth: None,
            allow_insecure_localhost: false,
            transport: TransportConfig::default(),
            retry: RetryConfig::default(),
            user_agent: None,
        }
    }

    /// Inject a fully-built `reqwest::Client`. The caller owns transport
    /// configuration in this mode; mixing `http_client(...)` with any
    /// transport-shaping builder method (`timeout`, `proxy`, …) is a
    /// programming error and is rejected by [`Self::build`].
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn allow_insecure_localhost(mut self) -> Self {
        self.allow_insecure_localhost = true;
        self
    }

    /// Total timeout for a single request including the connect handshake,
    /// TLS, headers and body. Use [`Self::connect_timeout`] when you want a
    /// separate, shorter cap on the connection establishment phase.
    ///
    /// Native-only: the wasm32 fetch backend has no per-request timeout
    /// hook (the browser owns the timeline).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.transport.timeout = Some(timeout);
        self
    }

    /// Cap the connection-establishment phase (TCP + TLS handshake) only.
    /// Independent of the total request timeout set via [`Self::timeout`].
    ///
    /// Native-only: there is no concept of a separate connect phase in the
    /// wasm32 fetch backend.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.transport.connect_timeout = Some(connect_timeout);
        self
    }

    /// Maximum idle time before a pooled connection is reaped. `None` means
    /// `reqwest`'s default. Set a value if your service is behind a proxy or
    /// load balancer with an aggressive idle-connection kill window.
    ///
    /// Native-only: the wasm32 fetch backend has no user-visible connection
    /// pool.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn pool_idle_timeout(mut self, pool_idle_timeout: Duration) -> Self {
        self.transport.pool_idle_timeout = Some(pool_idle_timeout);
        self
    }

    /// Cap the number of idle connections kept open per remote host.
    ///
    /// Native-only: see [`Self::pool_idle_timeout`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn pool_max_idle_per_host(mut self, pool_max_idle_per_host: usize) -> Self {
        self.transport.pool_max_idle_per_host = Some(pool_max_idle_per_host);
        self
    }

    /// Enable / disable TCP_NODELAY on connections. Defaults to reqwest's
    /// choice (currently enabled).
    ///
    /// Native-only: the wasm32 fetch backend doesn't expose TCP-level knobs.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn tcp_nodelay(mut self, tcp_nodelay: bool) -> Self {
        self.transport.tcp_nodelay = Some(tcp_nodelay);
        self
    }

    /// Enable TCP keepalive with the given interval. Useful when the path
    /// includes long-lived NAT mappings or stateful firewalls that drop
    /// silent connections.
    ///
    /// Native-only: see [`Self::tcp_nodelay`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn tcp_keepalive(mut self, interval: Duration) -> Self {
        self.transport.tcp_keepalive = Some(interval);
        self
    }

    /// Send an HTTP/2 PING frame at this interval.
    ///
    /// Native-only: HTTP/2 framing is invisible behind the browser fetch
    /// pipeline on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn http2_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.transport.http2_keep_alive_interval = Some(interval);
        self
    }

    /// Drop the HTTP/2 connection if a PING is unanswered within this window.
    ///
    /// Native-only: see [`Self::http2_keep_alive_interval`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn http2_keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.transport.http2_keep_alive_timeout = Some(timeout);
        self
    }

    /// Whether to keep sending HTTP/2 PINGs while idle.
    ///
    /// Native-only: see [`Self::http2_keep_alive_interval`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn http2_keep_alive_while_idle(mut self, enabled: bool) -> Self {
        self.transport.http2_keep_alive_while_idle = Some(enabled);
        self
    }

    /// Route requests through an HTTP / HTTPS proxy. Multiple calls compose:
    /// `reqwest` evaluates proxies in order and falls through to no-proxy if
    /// none match. Pair with [`Self::no_proxy`] to disable system proxy
    /// detection from environment variables.
    ///
    /// Native-only: the browser owns proxy selection on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn proxy(mut self, proxy: reqwest::Proxy) -> Self {
        self.transport.proxies.push(proxy);
        self
    }

    /// Disable proxy auto-detection from environment variables
    /// (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`). Combine with
    /// [`Self::proxy`] for fully explicit routing in production.
    ///
    /// Native-only: see [`Self::proxy`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn no_proxy(mut self) -> Self {
        self.transport.no_proxy = true;
        self
    }

    /// Override the default redirect policy. The default is to follow up
    /// to 10 redirects; pass [`RedirectPolicy::None`] for service-to-service
    /// paths where redirect-following is a bug.
    ///
    /// Native-only: the browser handles redirects transparently on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn redirect(mut self, policy: RedirectPolicy) -> Self {
        self.transport.redirect = Some(policy);
        self
    }

    /// Toggle gzip response decoding (the `gzip` feature is on by default
    /// in `cokret-http-client`'s `reqwest` profile, so this method exists to
    /// let callers turn it *off* when stricter content negotiation matters).
    ///
    /// Native-only: gzip negotiation is owned by the browser on wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn gzip(mut self, enabled: bool) -> Self {
        self.transport.gzip = Some(enabled);
        self
    }

    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    // `mut self` is only used by the native redirect-hardening block below;
    // on wasm32 the browser owns redirect/header-stripping so the binding is
    // intentionally unused there.
    #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
    pub fn build(mut self) -> Result<Client> {
        validate_base_url(&self.base_url, self.allow_insecure_localhost)?;
        if let Some(auth) = &self.auth {
            validate_auth(auth)?;
        }
        if let Some(user_agent) = &self.user_agent {
            validate_header_value("user agent", user_agent)?;
        }
        // DeviceProof / ServiceSignature credentials ride in custom headers
        // (`X-Cokret-Device-Proof`, `Signature` / `X-Cokret-Service-Signature`)
        // that reqwest does NOT strip across a cross-host redirect (its
        // sensitive-header allowlist only covers `Authorization` / `Cookie` /
        // `Proxy-Authorization`). Following a 3xx to an attacker-controlled
        // host would replay these device / service credentials to a third
        // party. Default such clients to never follow redirects unless the
        // caller explicitly chose a policy (Bearer is safe — reqwest strips
        // `Authorization` itself — so it keeps reqwest's default).
        #[cfg(not(target_arch = "wasm32"))]
        if self.http.is_none()
            && self.transport.redirect.is_none()
            && matches!(
                self.auth,
                Some(Auth::DeviceProof(_)) | Some(Auth::ServiceSignature(_))
            )
        {
            self.transport.redirect = Some(RedirectPolicy::None);
        }
        // Pre-built clients own their transport configuration end to end;
        // the per-request default timeout only kicks in when this builder
        // owns the transport and no explicit timeout was configured.
        #[cfg(not(target_arch = "wasm32"))]
        let default_timeout = if self.http.is_none() && self.transport.timeout.is_none() {
            Some(DEFAULT_REQUEST_TIMEOUT)
        } else {
            None
        };
        let http = match self.http {
            Some(http) => {
                if !self.transport.is_default() {
                    return Err(Error::Protocol(
                        "transport options conflict with a pre-built http_client; configure one or the other"
                            .to_owned(),
                    ));
                }
                http
            }
            None => self
                .transport
                .apply(reqwest::Client::builder())
                .build()
                .map_err(transport_error)?,
        };
        Ok(Client {
            base_url: self.base_url,
            http,
            auth: self.auth,
            retry: self.retry,
            user_agent: self.user_agent,
            #[cfg(not(target_arch = "wasm32"))]
            default_timeout,
        })
    }
}

impl Client {
    pub fn builder(base_url: Url) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    pub fn new(base_url: Url) -> Result<Self> {
        Self::builder(base_url).build()
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry
    }

    pub async fn describe(&self) -> Result<ServerDescription> {
        self.get("/_cokret/describe").await
    }

    pub async fn describe_and_verify(
        &self,
        requirements: &ServiceRequirements,
    ) -> Result<ServerDescription> {
        let description = self.describe().await?;
        requirements.verify(&description)?;
        Ok(description)
    }

    pub async fn identity_describe(&self) -> Result<IdentityDescription> {
        self.get("/_cokret/root/identity/describe").await
    }

    pub async fn identity_resolve(
        &self,
        request: &IdentityResolveRequestBody,
    ) -> Result<IdentityResolveOutcome> {
        self.post("/_cokret/root/identity/resolve", request).await
    }

    pub async fn identity_document(
        &self,
        did: &str,
        version: Option<&str>,
    ) -> Result<IdentityDocumentView> {
        let mut builder = self
            .request(Method::GET, "/_cokret/root/identity/document")?
            .query(&[("did", did)]);
        if let Some(version) = version {
            builder = builder.query(&[("version", version)]);
        }
        self.send_json(builder).await
    }

    pub async fn identity_log(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<IdentityLogOutcome> {
        let mut builder = self
            .request(Method::GET, "/_cokret/root/identity/log")?
            .query(&[("did", did)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn identity_submit_did_operation(
        &self,
        request: &DidOperationSubmitRequestBody,
    ) -> Result<DidOperationSubmitOutcome> {
        self.post("/_cokret/root/identity/submit-did-operation", request)
            .await
    }

    pub async fn identity_receipts(
        &self,
        did: &str,
        head: &str,
    ) -> Result<IdentityReceiptsOutcome> {
        let builder = self
            .request(Method::GET, "/_cokret/root/identity/receipts")?
            .query(&[("did", did), ("head", head)]);
        self.send_json(builder).await
    }

    /// `POST /_cokret/gate/account/session-grants`
    /// (`ck.gate.account.command.issue_session_grant`): exchange a body-borne
    /// passkey / OIDC / device / DID proof for a session grant. This is
    /// the only session-grant issuance path registered in the spec HTTP
    /// binding (`x-cokret-auth.proof_in_body: true`); challenge
    /// acquisition is deployment-local per `identity-did.md` §5.1.
    pub async fn auth_issue_session_grant(
        &self,
        req: &SessionGrantRequestBody,
    ) -> Result<SessionGrantOutcome> {
        self.post("/_cokret/gate/account/session-grants", req).await
    }

    pub async fn account_subscribe(&self, request: &SyncRequestBody) -> Result<Response> {
        // Long-lived NDJSON stream — exempt from the per-request default
        // total timeout (see `DEFAULT_REQUEST_TIMEOUT`).
        let mut builder = self
            .request_unbounded(Method::GET, "/_cokret/self/account/subscribe")?
            .header("accept", "application/x-ndjson");
        if let Some(after) = request.after.as_deref() {
            builder = builder.query(&[("after", after)]);
        }
        if let Some(catchup) = request.catchup {
            builder = builder.query(&[("catchup", catchup)]);
        }
        if let Some(presence) = request.set_presence.as_ref() {
            builder = builder.query(&[("set_presence", presence)]);
        }
        self.send_response(builder).await
    }

    /// Subscribe and return the first delta frame, then drop the
    /// connection.
    ///
    /// `/_cokret/self/account/subscribe` is a long-lived NDJSON stream:
    /// the server keeps pushing frames and does not close the response
    /// on its own, so reading the whole body up front would never
    /// return (and would buffer the stream without bound). The body is
    /// therefore read incrementally, one chunk at a time, and the
    /// connection is dropped as soon as the first delta frame decodes.
    pub async fn account_subscribe_once(&self, request: &SyncRequestBody) -> Result<SyncOutcome> {
        use futures_util::StreamExt;

        fn first_delta_in(buffer: &mut Vec<u8>) -> Result<Option<SyncOutcome>> {
            while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = buffer.drain(..=newline).collect();
                if let Some(sync) = decode_subscribe_line(&line)? {
                    return Ok(Some(sync));
                }
            }
            Ok(None)
        }

        fn decode_subscribe_line(line: &[u8]) -> Result<Option<SyncOutcome>> {
            let trimmed = trim_ascii(line);
            if trimmed.is_empty() {
                return Ok(None);
            }
            let frame: AccountSubscribeFrame = serde_json::from_slice(trimmed)
                .map_err(|error| Error::Protocol(error.to_string()))?;
            Ok(SyncOutcome::from_account_subscribe_frame(frame))
        }

        let response = self.account_subscribe(request).await?;
        let mut stream = response.bytes_stream();
        let mut buffer: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(transport_error)?;
            buffer.extend_from_slice(&chunk);
            if let Some(sync) = first_delta_in(&mut buffer)? {
                return Ok(sync);
            }
            if buffer.len() > MAX_SUBSCRIBE_FRAME_BYTES {
                return Err(Error::Protocol(
                    "account subscribe frame exceeds maximum line size".to_owned(),
                ));
            }
        }
        // Stream ended; the trailing bytes may hold one last unterminated
        // frame.
        if let Some(sync) = decode_subscribe_line(&buffer)? {
            return Ok(sync);
        }
        Err(Error::Protocol(
            "account subscribe stream ended before a delta frame".to_owned(),
        ))
    }

    /// S-6 (savfox SDK gap): NDJSON-streamed account subscribe. Yields
    /// one [`AccountSubscribeFrame`] per line; transient per-line
    /// decode errors surface as `Err` items but the stream continues
    /// until the underlying HTTP body ends.
    ///
    /// Native-only — the wasm32 fetch backend's response streaming
    /// shape is incompatible with the `bytes_stream` codec pipeline
    /// used here.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn account_subscribe_frames(
        &self,
        request: &SyncRequestBody,
    ) -> Result<
        std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<AccountSubscribeFrame>> + Send>>,
    > {
        use futures_util::StreamExt;
        use tokio_util::codec::{FramedRead, LinesCodec};
        use tokio_util::io::StreamReader;

        let response = self.account_subscribe(request).await?;
        let byte_stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other));
        let reader = StreamReader::new(byte_stream);
        // Bound the per-line buffer so a hostile / misbehaving server that
        // never emits a newline can't drive unbounded memory growth (DoS).
        // Matches `account_subscribe_once`'s 8 MiB cap; over-limit lines
        // surface as `LinesCodecError::MaxLineLengthExceeded`, mapped to
        // `Error::Protocol` in the `Err` arm below.
        let lines = FramedRead::new(
            reader,
            LinesCodec::new_with_max_length(MAX_SUBSCRIBE_FRAME_BYTES),
        );
        let stream = lines.filter_map(|line_res| async move {
            match line_res {
                Ok(line) => match AccountSubscribeFrame::from_ndjson_line(&line) {
                    Ok(Some(frame)) => Some(Ok(frame)),
                    Ok(None) => None,
                    Err(err) => Some(Err(err)),
                },
                Err(err) => Some(Err(Error::Protocol(format!(
                    "account subscribe line read failed: {err}"
                )))),
            }
        });
        Ok(Box::pin(stream))
    }

    pub async fn account_describe(&self) -> Result<SyncDescription> {
        self.get("/_cokret/self/account/describe").await
    }

    pub async fn account_cursor_revoke(
        &self,
        request: &AccountCursorRevokeRequestBody,
    ) -> Result<AccountCursorRevokeOutcome> {
        self.post("/_cokret/self/account/cursor/revoke", request)
            .await
    }

    pub async fn contacts_request(
        &self,
        request: &ContactRequestRequestBody,
    ) -> Result<ContactRequestOutcome> {
        self.post(PATH_SELF_CONTACTS_REQUEST, request).await
    }

    pub async fn contacts_respond(
        &self,
        request: &ContactRespondRequestBody,
    ) -> Result<ContactRespondOutcome> {
        self.post(PATH_SELF_CONTACTS_RESPOND, request).await
    }

    pub async fn contacts_list(&self) -> Result<ContactList> {
        self.get(PATH_SELF_CONTACTS).await
    }

    pub async fn contacts_tombstone(
        &self,
        request: &ContactTombstoneRequestBody,
    ) -> Result<ContactTombstone> {
        self.post(PATH_SELF_CONTACTS_TOMBSTONE, request).await
    }

    pub async fn direct_conversation_resolve(
        &self,
        request: &DirectConversationResolveRequestBody,
    ) -> Result<DirectConversationResolveOutcome> {
        self.post(PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE, request)
            .await
    }

    /// Subscribe to the Event stream for one or more Realms / actors via
    /// `ck.self.events.stream.subscribe` (`GET /_cokret/self/events/subscribe`). The selector is
    /// `realms[]` ∪ `actors[]` repeated query args, and frames use top-level
    /// `kind` with explicit control variants.
    ///
    /// Round C47 (spec e10b6ad): the response Content-Type is now
    /// `application/x-ndjson` (was `text/event-stream`). The client sends an
    /// `Accept: application/x-ndjson` header so old SSE-only servers reject
    /// up front instead of streaming a shape we cannot parse.
    pub async fn events_subscribe_stream(
        &self,
        realm_id: &str,
        after: Option<&str>,
    ) -> Result<Response> {
        // Long-lived NDJSON stream — exempt from the per-request default
        // total timeout (see `DEFAULT_REQUEST_TIMEOUT`).
        let mut builder = self
            .request_unbounded(Method::GET, "/_cokret/self/events/subscribe")?
            .header("accept", "application/x-ndjson")
            .query(&[("realms", realm_id)]);
        if let Some(after) = after {
            builder = builder.query(&[("after", after)]);
        }
        self.send_response(builder).await
    }

    /// Range-read Events via `ck.self.events.query.scan` (`GET /_cokret/self/events`). Pass
    /// `before` to walk older history, `after` to catch up toward newer events,
    /// and `order` to override the default proximity-to-seal ordering.
    pub async fn events_query(
        &self,
        realm_id: &str,
        before: Option<&str>,
        after: Option<&str>,
        order: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SyncBackfillOutcome> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/events")?
            .query(&[("realms", realm_id)]);
        if let Some(before) = before {
            builder = builder.query(&[("before", before)]);
        }
        if let Some(after) = after {
            builder = builder.query(&[("after", after)]);
        }
        if let Some(order) = order {
            builder = builder.query(&[("order", order)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    /// Submit a single signed Event Envelope via `ck.self.events.command.submit`
    /// (`POST /_cokret/self/events`). Wire body is the bare envelope per the OpenAPI
    /// `oneOf` first arm (`event-envelope.schema.json`).
    pub async fn events_submit(&self, event: &Event) -> Result<EventsSubmitOutcome> {
        self.post("/_cokret/self/events", event).await
    }

    /// Submit a batch of signed Event Envelopes via `ck.self.events.command.submit`
    /// (`POST /_cokret/self/events`) using the `EventsSubmitBatchRequestBody` body shape.
    pub async fn events_submit_batch(&self, events: &[Event]) -> Result<EventsSubmitOutcome> {
        #[derive(serde::Serialize)]
        struct Batch<'a> {
            events: &'a [Event],
        }
        self.post("/_cokret/self/events", &Batch { events }).await
    }

    pub async fn snapshot_head(&self, realm_id: &str) -> Result<SnapshotHeadState> {
        let builder = self
            .request(Method::GET, "/_cokret/self/snapshot/head")?
            .query(&[("realm_id", realm_id)]);
        self.send_json(builder).await
    }

    pub async fn authz_check(&self, request: &AuthzCheckRequestBody) -> Result<AuthzCheckOutcome> {
        self.post("/_cokret/self/authz/check", request).await
    }

    pub async fn authz_effective_grants(
        &self,
        realm_id: &str,
        subject: &str,
        at: Option<&str>,
    ) -> Result<GrantList> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/authz/effective-grants")?
            .query(&[("realm_id", realm_id), ("subject", subject)]);
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn authz_invites(
        &self,
        subject: &str,
        realm_id: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<AuthzInviteList> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/authz/invites")?
            .query(&[("subject", subject)]);
        if let Some(realm_id) = realm_id {
            builder = builder.query(&[("realm_id", realm_id)]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        self.send_json(builder).await
    }

    pub async fn blob_metadata(&self, blob_ref: &BlobRef) -> Result<BlobMetadata> {
        let builder = self
            .request(Method::GET, "/_cokret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_json(builder).await
    }

    pub async fn blob_head(&self, blob_ref: &BlobRef) -> Result<HeaderMap> {
        let builder = self
            .request(Method::HEAD, "/_cokret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_empty(builder).await
    }

    pub async fn blob_upload(&self, body: &BlobUploadMetadata) -> Result<BlobUploadOutcome> {
        self.post("/_cokret/self/blob/upload", body).await
    }

    pub async fn blob_upload_bytes(
        &self,
        metadata: &BlobUploadMetadata,
        bytes: Vec<u8>,
    ) -> Result<BlobUploadOutcome> {
        let mut builder = self
            .request(Method::POST, "/_cokret/self/blob/upload")?
            .header("X-Cokret-Blob-Metadata", serde_json::to_string(metadata)?);
        if let Some(media_type) = &metadata.media_type {
            builder = builder.header("Content-Type", media_type);
        }
        if let Some(filename) = &metadata.filename {
            builder = builder.header(
                "Content-Disposition",
                format!("attachment; filename=\"{filename}\""),
            );
        }
        if let Some(content_digest) = &metadata.content_digest {
            builder = builder.header("Digest", content_digest.as_str());
        }
        self.send_json(builder.body(bytes)).await
    }

    pub async fn blob_download(&self, blob_ref: &BlobRef, range: Option<&str>) -> Result<Vec<u8>> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        if let Some(range) = range {
            builder = builder.header("Range", range);
        }
        let response = self.send_response(builder).await?;
        Ok(response.bytes().await.map_err(transport_error)?.to_vec())
    }

    pub async fn keys_upload(&self, request: &KeysUploadRequestBody) -> Result<KeysUploadOutcome> {
        self.post("/_cokret/self/keys/upload", request).await
    }

    pub async fn keys_query(&self, request: &KeysQueryRequestBody) -> Result<KeysQueryOutcome> {
        self.post("/_cokret/self/keys/query", request).await
    }

    pub async fn keys_claim(&self, request: &KeysClaimRequestBody) -> Result<KeysClaimOutcome> {
        self.post("/_cokret/self/keys/claim", request).await
    }

    /// Upload (create or update) an encrypted [`KeyBackup`] envelope.
    /// Spec: `crypto-media/key-management.md` §7.2 +
    /// `sync/service-http-binding.md` §3 (PUT
    /// `/_cokret/self/keys/backups/{backup_id}`). The envelope's
    /// `ciphertext_digest` is the server-side idempotency / dedup key.
    pub async fn put_key_backup(
        &self,
        backup_id: &BackupId,
        body: &KeyBackup,
    ) -> Result<KeysBackupsPutOutcome> {
        let path = format!("/_cokret/self/keys/backups/{}", backup_id.as_str());
        self.put(&path, body).await
    }

    /// List existing key backups for the authorized actor. Honors the
    /// `backup_class` / `cursor` / `limit` filters from
    /// [`KeyBackupsListQuery`] (key-management.md §7.5).
    pub async fn list_key_backups(&self, query: &KeyBackupsListQuery) -> Result<KeysBackupsList> {
        let mut builder = self.request(Method::GET, "/_cokret/self/keys/backups")?;
        if let Some(class) = query.backup_class {
            let class_str = match class {
                cokret_core::BackupClass::DidRecovery => "did_recovery",
                cokret_core::BackupClass::SecretStorage => "secret_storage",
                cokret_core::BackupClass::MlsHistory => "mls_history",
            };
            builder = builder.query(&[("backup_class", class_str)]);
        }
        if let Some(ref cursor) = query.cursor {
            builder = builder.query(&[("cursor", cursor.as_str())]);
        }
        if let Some(limit) = query.limit {
            builder = builder.query(&[("limit", limit.to_string())]);
        }
        self.send_json(builder).await
    }

    /// Convenience variant that returns just the summary list. Equivalent to
    /// [`list_key_backups`](Self::list_key_backups) with default query.
    pub async fn list_all_key_backups(&self) -> Result<Vec<KeyBackupSummary>> {
        let response: KeysBackupsList = self
            .list_key_backups(&KeyBackupsListQuery {
                backup_class: None,
                cursor: None,
                limit: None,
            })
            .await?;
        Ok(response.backups)
    }

    /// Fetch a single encrypted [`KeyBackup`] envelope for local
    /// decryption. The server never returns plaintext; decryption
    /// requires the passphrase + the envelope's KDF/AEAD parameters and
    /// is performed via [`crate`]-adjacent helpers
    /// (`cokret_crypto::backup::decrypt_vault`).
    pub async fn get_key_backup(&self, backup_id: &BackupId) -> Result<KeyBackup> {
        let path = format!("/_cokret/self/keys/backups/{}", backup_id.as_str());
        self.get(&path).await
    }

    /// Delete an existing key backup envelope. Spec §7.4 marks this as a
    /// high-risk operation; the caller must supply the typed
    /// [`KeysBackupsDeleteRequestBody`] with a valid proof and (optionally) a
    /// human-readable reason.
    pub async fn delete_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsDeleteRequestBody,
    ) -> Result<KeysBackupsDeleteOutcome> {
        let path = format!("/_cokret/self/keys/backups/{}", backup_id.as_str());
        let builder = self.request(Method::DELETE, &path)?.json(request);
        self.send_json(builder).await
    }

    pub async fn send_device_messages(
        &self,
        idempotency_key: &str,
        request: &DeviceMessagesPutRequestBody,
    ) -> Result<DeviceMessagesPutOutcome> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_cokret/self/device_messages", request, &options)
            .await
    }

    pub async fn receive_device_messages(
        &self,
        from: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DeviceMessagesGetOutcome> {
        let mut builder = self.request(Method::GET, "/_cokret/self/device_messages")?;
        if let Some(from) = from {
            builder = builder.query(&[("from", from)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn ack_device_messages(
        &self,
        request: &DeviceMessagesAckRequestBody,
    ) -> Result<DeviceMessagesAckOutcome> {
        self.post("/_cokret/self/device_messages/ack", request)
            .await
    }

    pub async fn directory_describe(&self) -> Result<DirectoryDescription> {
        self.get("/_cokret/find/directory/describe").await
    }

    pub async fn directory_search_realms(
        &self,
        request: &DirectorySearchRealmsRequestBody,
    ) -> Result<DirectoryRealmSearchOutcome> {
        self.post("/_cokret/find/directory/search-realms", request)
            .await
    }

    pub async fn directory_resolve_realm(
        &self,
        request: &DirectoryResolveRealmRequestBody,
    ) -> Result<DirectoryRealmResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-realm", request)
            .await
    }

    /// R3.3 (CKP-0011, cokret-spec @ cced4b8) — `ck.find.directory.query.resolve_target`.
    /// Resolve a client-agnostic shareable object address (Realm / Strand /
    /// Message) to a preview. The `address` and any `token` should be derived
    /// from [`cokret_core::models::parse_address`]; invite and preview tokens
    /// MUST be bound to the resolved object server-side via
    /// [`cokret_core::models::verify_token_target`].
    pub async fn directory_resolve_target(
        &self,
        request: &DirectoryResolveTargetRequestBody,
    ) -> Result<DirectoryTargetResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-target", request)
            .await
    }

    pub async fn directory_search_organizations(
        &self,
        request: &DirectorySearchOrganizationsRequestBody,
    ) -> Result<DirectoryOrganizationSearchOutcome> {
        self.post("/_cokret/find/directory/search-organizations", request)
            .await
    }

    pub async fn directory_resolve_organization(
        &self,
        request: &DirectoryResolveOrganizationRequestBody,
    ) -> Result<DirectoryOrganizationResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-organization", request)
            .await
    }

    pub async fn directory_search_actors(
        &self,
        request: &DirectorySearchActorsRequestBody,
    ) -> Result<DirectoryActorSearchOutcome> {
        self.post("/_cokret/find/directory/search-actors", request)
            .await
    }

    pub async fn directory_search_users(
        &self,
        q: &str,
        realm_id: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DirectoryUserSearchOutcome> {
        let request = DirectorySearchUsersRequestBody {
            query: q.to_owned(),
            realm_id: realm_id.map(str::parse).transpose()?,
            cursor: None,
            limit,
            intent: None,
        };
        self.post("/_cokret/find/directory/search-users", &request)
            .await
    }

    pub async fn directory_resolve_handle(
        &self,
        request: &DirectoryResolveHandleRequestBody,
    ) -> Result<DirectoryHandleResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-handle", request)
            .await
    }

    /// Resolve a controller-scoped native personal agent selector exactly.
    pub async fn directory_resolve_agent_selector(
        &self,
        request: &DirectoryResolveAgentSelectorRequestBody,
    ) -> Result<DirectoryAgentSelectorResolutionOutcome> {
        let body: DirectoryAgentSelectorResolutionOutcome = self
            .post("/_cokret/find/directory/resolve-agent-selector", request)
            .await?;
        body.validate()?;
        Ok(body)
    }

    /// R3.2 (cokret-spec @ b56cab1) — `ck.find.directory.query.list_handles_for_subject`.
    /// Known holder/principal DID → current visible handle claims. The
    /// response invariant `claims[].subject == subject` is enforced via
    /// [`DirectorySubjectHandleList::validate`] before returning.
    pub async fn directory_list_handles_for_subject(
        &self,
        request: &DirectoryListHandlesForSubjectRequestBody,
    ) -> Result<DirectorySubjectHandleList> {
        let body: DirectorySubjectHandleList = self
            .post("/_cokret/find/directory/list-handles-for-subject", request)
            .await?;
        body.validate()?;
        Ok(body)
    }

    pub async fn directory_private_contact_discovery(
        &self,
        request: &DirectoryPrivateContactDiscoveryRequestBody,
    ) -> Result<DirectoryPrivateContactDiscoveryOutcome> {
        self.post("/_cokret/find/directory/private-contact-discovery", request)
            .await
    }

    pub async fn push_register_device(
        &self,
        request: &PushRegisterDeviceRequestBody,
    ) -> Result<PushRegisterDeviceOutcome> {
        self.post("/_cokret/edge/push/register-device", request)
            .await
    }

    pub async fn push_unregister_device(
        &self,
        request: &PushUnregisterDeviceRequestBody,
    ) -> Result<OkOutcome> {
        self.post("/_cokret/edge/push/unregister-device", request)
            .await
    }

    pub async fn push_notify(&self, request: &PushNotifyRequestBody) -> Result<PushNotifyOutcome> {
        self.post("/_cokret/edge/push/notify", request).await
    }

    pub async fn policy_check(
        &self,
        request: &PolicyCheckRequestBody,
    ) -> Result<PolicyCheckOutcome> {
        self.post("/_cokret/self/policy/check", request).await
    }

    pub async fn media_ice_config(
        &self,
        request: &MediaIceConfigRequestBody,
    ) -> Result<MediaIceConfigOutcome> {
        self.post("/_cokret/self/rtc/ice-config", request).await
    }

    pub async fn moderation_report(
        &self,
        request: &ModerationReportRequestBody,
    ) -> Result<ModerationReportOutcome> {
        self.post("/_cokret/self/moderation/report", request).await
    }

    pub async fn mimi_provider_directory(
        &self,
        provider_id: Option<&str>,
        features: &[String],
    ) -> Result<MimiProviderDirectory> {
        let mut builder = self.request(Method::GET, "/_cokret/open/mimi/provider-directory")?;
        if let Some(provider_id) = provider_id {
            builder = builder.query(&[("provider_id", provider_id)]);
        }
        for feature in features {
            builder = builder.query(&[("features", feature)]);
        }
        self.send_json(builder).await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: &MimiReportAbuseRequestBody,
    ) -> Result<MimiReportAbuseOutcome> {
        self.post("/_cokret/open/mimi/report-abuse", request).await
    }

    pub async fn applet_ping(&self) -> Result<AppletPingOutcome> {
        self.get("/_cokret/edge/applet/ping").await
    }

    pub async fn applet_describe(&self) -> Result<AppletDescription> {
        self.get("/_cokret/edge/applet/describe").await
    }

    pub async fn applet_transaction(
        &self,
        idempotency_key: &str,
        request: &AppletTransactionRequestBody,
    ) -> Result<AppletTransactionOutcome> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_cokret/edge/applet/transactions", request, &options)
            .await
    }

    pub async fn applet_actor(&self, actor_id: &str) -> Result<AppletActorView> {
        reject_path_segment(actor_id)?;
        let path = format!("/_cokret/edge/applet/actors/{actor_id}");
        self.get(&path).await
    }

    pub async fn applet_realm(&self, realm_id_or_alias: &str) -> Result<AppletRealmView> {
        reject_path_segment(realm_id_or_alias)?;
        let path = format!("/_cokret/edge/applet/realms/{realm_id_or_alias}");
        self.get(&path).await
    }

    pub async fn applet_protocol(&self, protocol: &str) -> Result<AppletProtocolMetadata> {
        reject_path_segment(protocol)?;
        let path = format!("/_cokret/edge/applet/protocols/{protocol}");
        self.get(&path).await
    }

    /// Query third-party users for an applet.
    pub async fn applet_third_party_users(&self) -> Result<Value> {
        self.get("/_cokret/edge/applet/third_party/users").await
    }

    /// Query third-party locations for an applet.
    pub async fn applet_third_party_locations(&self) -> Result<Value> {
        self.get("/_cokret/edge/applet/third_party/locations").await
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let builder = self.request(Method::GET, path)?;
        self.send_json(builder).await
    }

    pub async fn get_with_options<T: DeserializeOwned>(
        &self,
        path: &str,
        options: &ClientRequestOptions,
    ) -> Result<T> {
        let builder = self.apply_request_options(self.request(Method::GET, path)?, options)?;
        self.send_json(builder).await
    }

    pub async fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.request(Method::POST, path)?.json(body);
        self.send_json(builder).await
    }

    pub async fn post_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::POST, path)?, options)?;
        self.send_json(builder.json(body)).await
    }

    pub async fn put<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.request(Method::PUT, path)?.json(body);
        self.send_json(builder).await
    }

    pub async fn put_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::PUT, path)?, options)?;
        self.send_json(builder.json(body)).await
    }

    pub async fn delete<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        let builder = self.request(Method::DELETE, path)?;
        self.send_json(builder).await
    }

    fn request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        let builder = self.request_unbounded(method, path)?;
        // Bound every regular request when the caller did not configure
        // an explicit client-wide timeout (reqwest's own default is no
        // timeout at all). Streaming endpoints use `request_unbounded`.
        #[cfg(not(target_arch = "wasm32"))]
        let builder = match self.default_timeout {
            Some(timeout) => builder.timeout(timeout),
            None => builder,
        };
        Ok(builder)
    }

    /// Build a request without the per-request default total timeout —
    /// for long-lived NDJSON subscribe streams that stay open by design.
    /// The connect-phase timeout still applies at the transport level.
    fn request_unbounded(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        reject_absolute_path(path)?;
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        reject_query_auth_in_url(&url)?;
        let mut builder = self
            .http
            .request(method, url)
            .header("Accept", "application/json");
        if let Some(user_agent) = &self.user_agent {
            builder = builder.header(USER_AGENT, user_agent);
        }
        Ok(self.apply_auth(builder))
    }

    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            Some(Auth::Bearer(token)) => builder.bearer_auth(token),
            Some(Auth::DeviceProof(proof)) => builder.header("X-Cokret-Device-Proof", proof),
            Some(Auth::ServiceSignature(signature)) => builder
                .header("Signature", signature)
                .header("X-Cokret-Service-Signature", "1"),
            None => builder,
        }
    }

    fn apply_request_options(
        &self,
        mut builder: RequestBuilder,
        options: &ClientRequestOptions,
    ) -> Result<RequestBuilder> {
        if let Some(request_id) = &options.request_id {
            validate_header_value(HEADER_REQUEST_ID, request_id)?;
            builder = builder.header(HEADER_REQUEST_ID, request_id);
        }
        if let Some(idempotency_key) = &options.idempotency_key {
            validate_header_value(HEADER_IDEMPOTENCY_KEY, idempotency_key)?;
            builder = builder.header(HEADER_IDEMPOTENCY_KEY, idempotency_key);
        }
        if let Some(wait_for) = &options.wait_for {
            validate_header_value(HEADER_WAIT_FOR, wait_for)?;
            builder = builder.header(HEADER_WAIT_FOR, wait_for);
        }
        Ok(builder)
    }

    async fn send_json<T: DeserializeOwned>(&self, builder: RequestBuilder) -> Result<T> {
        let response = self.execute(builder).await?;
        let status = response.status();
        if !status.is_success() {
            let error = error_envelope_from_response(response).await;
            return Err(Error::Api {
                status: status.as_u16(),
                error: Box::new(error),
            });
        }

        Ok(response.json().await.map_err(transport_error)?)
    }

    async fn send_empty(&self, builder: RequestBuilder) -> Result<HeaderMap> {
        let response = self.send_response(builder).await?;
        Ok(response.headers().clone())
    }

    async fn send_response(&self, builder: RequestBuilder) -> Result<Response> {
        let response = self.execute(builder).await?;
        let status = response.status();
        if !status.is_success() {
            let error = error_envelope_from_response(response).await;
            return Err(Error::Api {
                status: status.as_u16(),
                error: Box::new(error),
            });
        }

        Ok(response)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        validate_request_builder(&builder)?;
        #[cfg(feature = "tracing")]
        let trace = request_trace_fields(&builder);
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                max_retries = self.retry.max_retries,
                "sending Cokret HTTP request"
            );
        }
        if self.retry.max_retries == 0 {
            let response = builder.send().await.map_err(transport_error)?;
            #[cfg(feature = "tracing")]
            if let Some(trace) = &trace {
                tracing::debug!(
                    method = %trace.method,
                    path = %trace.path,
                    status = response.status().as_u16(),
                    "received Cokret HTTP response"
                );
            }
            return Ok(response);
        }

        let Some(template) = builder.try_clone() else {
            let response = builder.send().await.map_err(transport_error)?;
            #[cfg(feature = "tracing")]
            if let Some(trace) = &trace {
                tracing::debug!(
                    method = %trace.method,
                    path = %trace.path,
                    status = response.status().as_u16(),
                    "received Cokret HTTP response"
                );
            }
            return Ok(response);
        };

        // Blind resends of a non-idempotent request can duplicate a write
        // the server already executed (a 5xx or timeout does not prove the
        // request had no effect). Safe/idempotent HTTP methods are always
        // retryable; POST/PATCH only when the caller attached an
        // `Idempotency-Key`. Everything else only retries connect-level
        // failures, where the request provably never reached the server.
        let idempotent = template
            .try_clone()
            .and_then(|clone| clone.build().ok())
            .map(|request| {
                matches!(
                    *request.method(),
                    Method::GET
                        | Method::HEAD
                        | Method::OPTIONS
                        | Method::TRACE
                        | Method::PUT
                        | Method::DELETE
                ) || request.headers().contains_key(HEADER_IDEMPOTENCY_KEY)
            })
            .unwrap_or(false);

        let mut attempts = 0usize;
        loop {
            let attempt_builder = template.try_clone().ok_or_else(|| {
                Error::Protocol("retryable request could not be cloned".to_owned())
            })?;
            match attempt_builder.send().await {
                Ok(response)
                    if idempotent
                        && attempts < self.retry.max_retries
                        && self.retry.should_retry_status(response.status()) =>
                {
                    attempts += 1;
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::warn!(
                            method = %trace.method,
                            path = %trace.path,
                            status = response.status().as_u16(),
                            attempt = attempts,
                            max_retries = self.retry.max_retries,
                            "retrying Cokret HTTP request after retryable status"
                        );
                    }
                    sleep(
                        self.retry
                            .retry_delay_from_headers(response.headers(), attempts),
                    )
                    .await;
                }
                Ok(response) => {
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::debug!(
                            method = %trace.method,
                            path = %trace.path,
                            status = response.status().as_u16(),
                            attempts = attempts + 1,
                            "received Cokret HTTP response"
                        );
                    }
                    return Ok(response);
                }
                Err(error)
                    if attempts < self.retry.max_retries && self.retry.retry_network_errors =>
                {
                    attempts += 1;
                    // Timeouts may fire after the server received the
                    // request; only idempotent requests may resend then.
                    let retryable = error.is_connect() || (idempotent && error.is_timeout());
                    if !retryable {
                        #[cfg(feature = "tracing")]
                        if let Some(trace) = &trace {
                            tracing::warn!(
                                method = %trace.method,
                                path = %trace.path,
                                error = %error,
                                "Cokret HTTP request failed without retry"
                            );
                        }
                        return Err(transport_error(error));
                    }
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::warn!(
                            method = %trace.method,
                            path = %trace.path,
                            error = %error,
                            attempt = attempts,
                            max_retries = self.retry.max_retries,
                            "retrying Cokret HTTP request after transport error"
                        );
                    }
                    sleep(self.retry.retry_delay(attempts)).await;
                }
                Err(error) => {
                    #[cfg(feature = "tracing")]
                    if let Some(trace) = &trace {
                        tracing::warn!(
                            method = %trace.method,
                            path = %trace.path,
                            error = %error,
                            attempts = attempts + 1,
                            "Cokret HTTP request failed"
                        );
                    }
                    return Err(transport_error(error));
                }
            }
        }
    }

    /// Wasm32 fast path. The browser fetch backend has neither a sleep
    /// primitive we can call from the cokret-http-client crate (no
    /// `tokio::time` driver) nor an `is_connect` accessor on
    /// `reqwest::Error`, and status-based retry windows would require
    /// pulling in `gloo-timers` or similar. We deliberately collapse retry
    /// to a single send on wasm32 and let the caller layer their own
    /// retry on top via `wasm-bindgen-futures` if they need it.
    #[cfg(target_arch = "wasm32")]
    async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        validate_request_builder(&builder)?;
        #[cfg(feature = "tracing")]
        let trace = request_trace_fields(&builder);
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                "sending Cokret HTTP request"
            );
        }
        let response = builder.send().await.map_err(transport_error)?;
        #[cfg(feature = "tracing")]
        if let Some(trace) = &trace {
            tracing::debug!(
                method = %trace.method,
                path = %trace.path,
                status = response.status().as_u16(),
                "received Cokret HTTP response"
            );
        }
        Ok(response)
    }
}

fn validate_base_url(url: &Url, allow_insecure_localhost: bool) -> Result<()> {
    reject_query_auth_in_url(url)?;
    if url.scheme() == "https" {
        return Ok(());
    }

    if allow_insecure_localhost && url.scheme() == "http" && is_localhost(url) {
        return Ok(());
    }

    Err(Error::InsecureUrl(url.to_string()))
}

fn validate_auth(auth: &Auth) -> Result<()> {
    let value = match auth {
        Auth::Bearer(token) | Auth::DeviceProof(token) | Auth::ServiceSignature(token) => token,
    };
    validate_header_value("auth material", value)
}

fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || HeaderValue::from_str(value).is_err() {
        return Err(Error::Protocol(format!(
            "{name} must be non-empty and header-safe"
        )));
    }
    Ok(())
}

fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn reject_absolute_path(path: &str) -> Result<()> {
    if path.starts_with("//") || Url::parse(path).is_ok() {
        return Err(Error::Protocol(
            "request path must be relative to the Cokret service".to_owned(),
        ));
    }
    Ok(())
}

fn reject_query_auth_in_url(url: &Url) -> Result<()> {
    for (key, _) in url.query_pairs() {
        if QUERY_AUTH_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
            return Err(Error::Protocol(
                "query string authentication material is not allowed".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_request_builder(builder: &RequestBuilder) -> Result<()> {
    if let Some(clone) = builder.try_clone() {
        let request = clone.build().map_err(transport_error)?;
        reject_query_auth_in_url(request.url())?;
    }
    Ok(())
}

async fn error_envelope_from_response(response: Response) -> ErrorEnvelope {
    let status = response.status();
    let retry_after_ms = retry_after_ms(response.headers());
    let error = response.json::<ErrorEnvelope>().await.unwrap_or_else(|_| {
        ErrorEnvelope::new(
            "internal_error",
            format!("HTTP request failed with status {status}"),
        )
    });
    if error.retry_after_ms().is_none() {
        error.with_retry_after_ms(retry_after_ms)
    } else {
        error
    }
}

fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
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

fn reject_path_segment(segment: &str) -> Result<()> {
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('?')
        || segment.contains('#')
        || segment.contains('%')
        || segment == "."
        || segment == ".."
    {
        return Err(Error::Protocol(
            "path segment contains reserved characters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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

        use cokret_core::{Did, EventId, EventRequirements, Hlc, RealmId, StrandId};
        use serde_json::json;
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
