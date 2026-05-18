use std::time::Duration;

use reqwest::{
    Method, RequestBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::sleep;
use url::Url;

use contrix_core::{
    AppletActorResponse, AppletDescription, AppletPingResponse, AppletProtocolResponse,
    AppletSpaceResponse, AppletTransactionRequest, AppletTransactionResponse, AuthzCheckRequest,
    AuthzCheckResponse, AuthzInvitesResponse, BackupId, BlobMetadata, BlobRef, BlobUploadMetadata,
    BlobUploadResponse, DeviceMessagesReceiveResponse, DeviceMessagesSendRequest,
    DeviceMessagesSendResponse, DirectoryDescription, DirectoryResolveHandleRequest,
    DirectoryResolveHandleResponse, DirectoryResolveOrganizationRequest,
    DirectoryResolveOrganizationResponse, DirectoryResolveSpaceRequest,
    DirectoryResolveSpaceResponse, DirectorySearchActorsRequest, DirectorySearchActorsResponse,
    DirectorySearchOrganizationsRequest, DirectorySearchOrganizationsResponse,
    DirectorySearchSpacesRequest, DirectorySearchSpacesResponse, DirectorySearchUsersResponse,
    EffectiveGrantsResponse, Error, ErrorEnvelope, IdentityDescription, IdentityDocumentResponse,
    IdentityLogResponse, IdentityReceiptsResponse, IdentityResolveRequest, IdentityResolveResponse,
    KeyBackup, KeyBackupDeleteRequest, KeyBackupDeleteResponse, KeyBackupPutResponse,
    KeyBackupSummary, KeyBackupsListQuery, KeyBackupsListResponse, KeysClaimRequest,
    KeysClaimResponse, KeysQueryRequest, KeysQueryResponse, KeysUploadRequest, KeysUploadResponse,
    MediaIceConfigRequest, MediaIceConfigResponse, ModerationReportRequest,
    ModerationReportResponse, OkResponse, PolicyCheckRequest, PolicyCheckResponse,
    PushNotifyRequest, PushNotifyResponse, PushRegisterDeviceRequest, PushRegisterDeviceResponse,
    PushUnregisterDeviceRequest, Result, ServerDescription, ServiceRequirements,
    SubmitDidOperationRequest, SubmitDidOperationResponse, SyncBackfillResponse, SyncDescription,
    SyncRequest, SyncResponse, SyncSnapshotHeadResponse,
};

pub const HEADER_REQUEST_ID: &str = "X-Contrix-Request-Id";
pub const HEADER_WAIT_FOR: &str = "X-Contrix-Wait-For";
pub const HEADER_IDEMPOTENCY_KEY: &str = "Idempotency-Key";

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
        if self.max_delay.is_zero() { delay } else { std::cmp::min(delay, self.max_delay) }
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
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(connect_timeout) = self.connect_timeout {
            builder = builder.connect_timeout(connect_timeout);
        }
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
    /// in `contrix-http-client`'s `reqwest` profile, so this method exists to
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

    pub fn build(self) -> Result<Client> {
        validate_base_url(&self.base_url, self.allow_insecure_localhost)?;
        if let Some(auth) = &self.auth {
            validate_auth(auth)?;
        }
        if let Some(user_agent) = &self.user_agent {
            validate_header_value("user agent", user_agent)?;
        }
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
            None => self.transport.apply(reqwest::Client::builder()).build()?,
        };
        Ok(Client {
            base_url: self.base_url,
            http,
            auth: self.auth,
            retry: self.retry,
            user_agent: self.user_agent,
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
        self.get("/api/v1/server/describe").await
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
        self.get("/api/v1/identity/describe").await
    }

    pub async fn identity_resolve(
        &self,
        request: &IdentityResolveRequest,
    ) -> Result<IdentityResolveResponse> {
        self.post("/api/v1/identity/resolve", request).await
    }

    pub async fn identity_document(
        &self,
        did: &str,
        version: Option<&str>,
    ) -> Result<IdentityDocumentResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/identity/document")?.query(&[("did", did)]);
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
    ) -> Result<IdentityLogResponse> {
        let mut builder = self.request(Method::GET, "/api/v1/identity/log")?.query(&[("did", did)]);
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
        request: &SubmitDidOperationRequest,
    ) -> Result<SubmitDidOperationResponse> {
        self.post("/api/v1/identity/submit-did-operation", request).await
    }

    pub async fn identity_receipts(
        &self,
        did: &str,
        head: &str,
    ) -> Result<IdentityReceiptsResponse> {
        let builder = self
            .request(Method::GET, "/api/v1/identity/receipts")?
            .query(&[("did", did), ("head", head)]);
        self.send_json(builder).await
    }

    pub async fn sync(&self, request: &SyncRequest) -> Result<SyncResponse> {
        self.post("/api/v1/sync", request).await
    }

    pub async fn sync_describe(&self) -> Result<SyncDescription> {
        self.get("/api/v1/sync/describe").await
    }

    /// Subscribe to the Event stream for one or more Spaces / actors via
    /// `cx.events.subscribe` (`GET /api/v1/events/subscribe`). The selector is
    /// `spaces[]` ∪ `actors[]` repeated query args, and frames use top-level
    /// `kind` with explicit control variants.
    ///
    /// Round C47 (spec e10b6ad): the response Content-Type is now
    /// `application/x-ndjson` (was `text/event-stream`). The client sends an
    /// `Accept: application/x-ndjson` header so old SSE-only servers reject
    /// up front instead of streaming a shape we cannot parse.
    pub async fn events_subscribe_stream(
        &self,
        space_id: &str,
        from: Option<&str>,
    ) -> Result<Response> {
        let mut builder = self
            .request(Method::GET, "/api/v1/events/subscribe")?
            .header("accept", "application/x-ndjson")
            .query(&[("spaces", space_id)]);
        if let Some(from) = from {
            builder = builder.query(&[("from", from)]);
        }
        self.send_response(builder).await
    }

    /// Range-read Events via `cx.events.query` (`GET /api/v1/events`). Pass
    /// `direction=Some("backward")` for reverse traversal; `None` defaults to
    /// forward traversal.
    pub async fn events_query(
        &self,
        space_id: &str,
        from: Option<&str>,
        until: Option<&str>,
        direction: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SyncBackfillResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/events")?.query(&[("spaces", space_id)]);
        if let Some(from) = from {
            builder = builder.query(&[("from", from)]);
        }
        if let Some(until) = until {
            builder = builder.query(&[("until", until)]);
        }
        if let Some(direction) = direction {
            builder = builder.query(&[("direction", direction)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn sync_snapshot_head(&self, space_id: &str) -> Result<SyncSnapshotHeadResponse> {
        let builder = self
            .request(Method::GET, "/api/v1/sync/snapshot-head")?
            .query(&[("space_id", space_id)]);
        self.send_json(builder).await
    }

    pub async fn authz_check(&self, request: &AuthzCheckRequest) -> Result<AuthzCheckResponse> {
        self.post("/api/v1/authz/check", request).await
    }

    /// `cx.profile.agent_workspace.v1` — resolve mirror Flow ID for a given
    /// source Flow ID. Returns `None` when soland reports 404
    /// (`not_provisioned`); returns `Err` for 401/403 / transport errors.
    ///
    /// Privacy invariant (spec §11.1): unauthenticated / non-owner callers
    /// MUST receive 401/403, NOT 404. The 404 path is only valid for the
    /// authenticated workspace owner.
    pub async fn agent_workspace_resolve_mirror_flow(
        &self,
        source_flow_id: &str,
    ) -> Result<Option<AgentWorkspaceMirrorFlow>> {
        let builder = self
            .request(Method::GET, "/api/v1/agent_workspace/mirror_flow")?
            .query(&[("source_flow_id", source_flow_id)]);
        match self.send_json::<AgentWorkspaceMirrorFlow>(builder).await {
            Ok(mapping) => Ok(Some(mapping)),
            Err(err) => {
                // Map soland's "not_provisioned" 404 to None; everything
                // else (401/403/5xx/transport) bubbles up as Err.
                if err.to_string().contains("not_provisioned")
                    || err.to_string().contains("status 404")
                {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// `cx.profile.agent_workspace.v1` — list in-flight agent_task objects
    /// whose execution_state is `pending_source_stub` or `active`. Used by
    /// the client to reconcile unfinished Phase 2/3 work after offline.
    /// Spec §11.2.
    pub async fn agent_workspace_list_pending_tasks(&self) -> Result<AgentWorkspacePendingTasks> {
        self.get("/api/v1/agent_workspace/pending_tasks").await
    }

    pub async fn authz_effective_grants(
        &self,
        space_id: &str,
        subject: &str,
        at: Option<&str>,
    ) -> Result<EffectiveGrantsResponse> {
        let mut builder = self
            .request(Method::GET, "/api/v1/authz/effective-grants")?
            .query(&[("space_id", space_id), ("subject", subject)]);
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn authz_invites(
        &self,
        subject: &str,
        space_id: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<AuthzInvitesResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/authz/invites")?.query(&[("subject", subject)]);
        if let Some(space_id) = space_id {
            builder = builder.query(&[("space_id", space_id)]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        self.send_json(builder).await
    }

    pub async fn blob_metadata(&self, blob_ref: &BlobRef) -> Result<BlobMetadata> {
        let builder = self
            .request(Method::GET, "/api/v1/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_json(builder).await
    }

    pub async fn blob_head(&self, blob_ref: &BlobRef) -> Result<HeaderMap> {
        let builder = self
            .request(Method::HEAD, "/api/v1/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_empty(builder).await
    }

    pub async fn blob_upload(&self, body: &BlobUploadMetadata) -> Result<BlobUploadResponse> {
        self.post("/api/v1/blob/upload", body).await
    }

    pub async fn blob_upload_bytes(
        &self,
        metadata: &BlobUploadMetadata,
        bytes: Vec<u8>,
    ) -> Result<BlobUploadResponse> {
        let mut builder = self
            .request(Method::POST, "/api/v1/blob/upload")?
            .header("X-Contrix-Blob-Metadata", serde_json::to_string(metadata)?);
        if let Some(media_type) = &metadata.media_type {
            builder = builder.header("Content-Type", media_type);
        }
        if let Some(filename) = &metadata.filename {
            builder = builder
                .header("Content-Disposition", format!("attachment; filename=\"{filename}\""));
        }
        if let Some(sha256) = &metadata.sha256 {
            builder = builder.header("Digest", sha256.as_str());
        }
        self.send_json(builder.body(bytes)).await
    }

    pub async fn blob_download(&self, blob_ref: &BlobRef, range: Option<&str>) -> Result<Vec<u8>> {
        let mut builder = self
            .request(Method::GET, "/api/v1/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        if let Some(range) = range {
            builder = builder.header("Range", range);
        }
        let response = self.send_response(builder).await?;
        Ok(response.bytes().await?.to_vec())
    }

    pub async fn keys_upload(&self, request: &KeysUploadRequest) -> Result<KeysUploadResponse> {
        self.post("/api/v1/keys/upload", request).await
    }

    pub async fn keys_query(&self, request: &KeysQueryRequest) -> Result<KeysQueryResponse> {
        self.post("/api/v1/keys/query", request).await
    }

    pub async fn keys_claim(&self, request: &KeysClaimRequest) -> Result<KeysClaimResponse> {
        self.post("/api/v1/keys/claim", request).await
    }

    /// Upload (create or update) an encrypted [`KeyBackup`] envelope.
    /// Spec: `crypto-media/key-management.md` §7.2 +
    /// `sync/service-http-binding.md` §3 (PUT
    /// `/api/v1/keys/backups/{backup_id}`). The envelope's
    /// `ciphertext_digest` is the server-side idempotency / dedup key.
    pub async fn put_key_backup(
        &self,
        backup_id: &BackupId,
        body: &KeyBackup,
    ) -> Result<KeyBackupPutResponse> {
        let path = format!("/api/v1/keys/backups/{}", backup_id.as_str());
        self.put(&path, body).await
    }

    /// List existing key backups for the authorized actor. Honors the
    /// `backup_class` / `cursor` / `limit` filters from
    /// [`KeyBackupsListQuery`] (key-management.md §7.5).
    pub async fn list_key_backups(
        &self,
        query: &KeyBackupsListQuery,
    ) -> Result<KeyBackupsListResponse> {
        let mut builder = self.request(Method::GET, "/api/v1/keys/backups")?;
        if let Some(class) = query.backup_class {
            let class_str = match class {
                contrix_core::BackupClass::DidRecovery => "did_recovery",
                contrix_core::BackupClass::SecretStorage => "secret_storage",
                contrix_core::BackupClass::MlsHistory => "mls_history",
                contrix_core::BackupClass::External => "external",
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
        let response: KeyBackupsListResponse = self
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
    /// (`contrix_crypto::backup::decrypt_vault`).
    pub async fn get_key_backup(&self, backup_id: &BackupId) -> Result<KeyBackup> {
        let path = format!("/api/v1/keys/backups/{}", backup_id.as_str());
        self.get(&path).await
    }

    /// Delete an existing key backup envelope. Spec §7.4 marks this as a
    /// high-risk operation; the caller must supply the typed
    /// [`KeyBackupDeleteRequest`] with a valid proof and (optionally) a
    /// human-readable reason.
    pub async fn delete_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeyBackupDeleteRequest,
    ) -> Result<KeyBackupDeleteResponse> {
        let path = format!("/api/v1/keys/backups/{}", backup_id.as_str());
        let builder = self.request(Method::DELETE, &path)?.json(request);
        self.send_json(builder).await
    }

    pub async fn send_device_messages(
        &self,
        idempotency_key: &str,
        request: &DeviceMessagesSendRequest,
    ) -> Result<DeviceMessagesSendResponse> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/api/v1/device_messages", request, &options).await
    }

    pub async fn receive_device_messages(
        &self,
        from: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DeviceMessagesReceiveResponse> {
        let mut builder = self.request(Method::GET, "/api/v1/device_messages")?;
        if let Some(from) = from {
            builder = builder.query(&[("from", from)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn directory_describe(&self) -> Result<DirectoryDescription> {
        self.get("/api/v1/directory/describe").await
    }

    pub async fn directory_search_spaces(
        &self,
        request: &DirectorySearchSpacesRequest,
    ) -> Result<DirectorySearchSpacesResponse> {
        self.post("/api/v1/directory/search-spaces", request).await
    }

    pub async fn directory_resolve_space(
        &self,
        request: &DirectoryResolveSpaceRequest,
    ) -> Result<DirectoryResolveSpaceResponse> {
        self.post("/api/v1/directory/resolve-space", request).await
    }

    pub async fn directory_search_organizations(
        &self,
        request: &DirectorySearchOrganizationsRequest,
    ) -> Result<DirectorySearchOrganizationsResponse> {
        self.post("/api/v1/directory/search-organizations", request).await
    }

    pub async fn directory_resolve_organization(
        &self,
        request: &DirectoryResolveOrganizationRequest,
    ) -> Result<DirectoryResolveOrganizationResponse> {
        self.post("/api/v1/directory/resolve-organization", request).await
    }

    pub async fn directory_search_actors(
        &self,
        request: &DirectorySearchActorsRequest,
    ) -> Result<DirectorySearchActorsResponse> {
        self.post("/api/v1/directory/search-actors", request).await
    }

    pub async fn directory_search_users(
        &self,
        q: &str,
        space_id: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DirectorySearchUsersResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/directory/search-users")?.query(&[("q", q)]);
        if let Some(space_id) = space_id {
            builder = builder.query(&[("space_id", space_id)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn directory_resolve_handle(
        &self,
        request: &DirectoryResolveHandleRequest,
    ) -> Result<DirectoryResolveHandleResponse> {
        self.post("/api/v1/directory/resolve-handle", request).await
    }

    pub async fn push_register_device(
        &self,
        request: &PushRegisterDeviceRequest,
    ) -> Result<PushRegisterDeviceResponse> {
        self.post("/api/v1/push/register-device", request).await
    }

    pub async fn push_unregister_device(
        &self,
        request: &PushUnregisterDeviceRequest,
    ) -> Result<OkResponse> {
        self.post("/api/v1/push/unregister-device", request).await
    }

    pub async fn push_notify(&self, request: &PushNotifyRequest) -> Result<PushNotifyResponse> {
        self.post("/api/v1/push/notify", request).await
    }

    pub async fn policy_check(&self, request: &PolicyCheckRequest) -> Result<PolicyCheckResponse> {
        self.post("/contrix/v1/check", request).await
    }

    pub async fn media_ice_config(
        &self,
        request: &MediaIceConfigRequest,
    ) -> Result<MediaIceConfigResponse> {
        self.post("/contrix/v1/ice-config", request).await
    }

    pub async fn moderation_report(
        &self,
        request: &ModerationReportRequest,
    ) -> Result<ModerationReportResponse> {
        self.post("/api/v1/moderation/report", request).await
    }

    pub async fn applet_ping(&self) -> Result<AppletPingResponse> {
        self.get("/api/v1/applet/ping").await
    }

    pub async fn applet_describe(&self) -> Result<AppletDescription> {
        self.get("/api/v1/applet/describe").await
    }

    pub async fn applet_transaction(
        &self,
        idempotency_key: &str,
        request: &AppletTransactionRequest,
    ) -> Result<AppletTransactionResponse> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/api/v1/applet/transactions", request, &options).await
    }

    pub async fn applet_actor(&self, actor_id: &str) -> Result<AppletActorResponse> {
        reject_path_segment(actor_id)?;
        let path = format!("/api/v1/applet/actors/{actor_id}");
        self.get(&path).await
    }

    pub async fn applet_space(&self, space_id_or_alias: &str) -> Result<AppletSpaceResponse> {
        reject_path_segment(space_id_or_alias)?;
        let path = format!("/api/v1/applet/spaces/{space_id_or_alias}");
        self.get(&path).await
    }

    pub async fn applet_protocol(&self, protocol: &str) -> Result<AppletProtocolResponse> {
        reject_path_segment(protocol)?;
        let path = format!("/api/v1/applet/protocols/{protocol}");
        self.get(&path).await
    }

    /// Query third-party users for an applet.
    pub async fn applet_third_party_users(&self) -> Result<Value> {
        self.get("/api/v1/applet/third_party/users").await
    }

    /// Query third-party locations for an applet.
    pub async fn applet_third_party_locations(&self) -> Result<Value> {
        self.get("/api/v1/applet/third_party/locations").await
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
        reject_absolute_path(path)?;
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        reject_query_auth_in_url(&url)?;
        let mut builder = self.http.request(method, url).header("Accept", "application/json");
        if let Some(user_agent) = &self.user_agent {
            builder = builder.header(USER_AGENT, user_agent);
        }
        Ok(self.apply_auth(builder))
    }

    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            Some(Auth::Bearer(token)) => builder.bearer_auth(token),
            Some(Auth::DeviceProof(proof)) => builder.header("X-Contrix-Device-Proof", proof),
            Some(Auth::ServiceSignature(signature)) => {
                builder.header("Signature", signature).header("X-Contrix-Service-Signature", "1")
            }
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
            return Err(Error::Api { status: status.as_u16(), error });
        }

        Ok(response.json().await?)
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
            return Err(Error::Api { status: status.as_u16(), error });
        }

        Ok(response)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        validate_request_builder(&builder)?;
        if self.retry.max_retries == 0 {
            return Ok(builder.send().await?);
        }

        let Some(template) = builder.try_clone() else {
            return Ok(builder.send().await?);
        };

        let mut attempts = 0usize;
        loop {
            let attempt_builder = template.try_clone().ok_or_else(|| {
                Error::Protocol("retryable request could not be cloned".to_owned())
            })?;
            match attempt_builder.send().await {
                Ok(response)
                    if attempts < self.retry.max_retries
                        && self.retry.should_retry_status(response.status()) =>
                {
                    attempts += 1;
                    sleep(self.retry.retry_delay_from_headers(response.headers(), attempts)).await;
                }
                Ok(response) => return Ok(response),
                Err(error)
                    if attempts < self.retry.max_retries && self.retry.retry_network_errors =>
                {
                    attempts += 1;
                    if !error.is_connect() && !error.is_timeout() {
                        return Err(error.into());
                    }
                    sleep(self.retry.retry_delay(attempts)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Wasm32 fast path. The browser fetch backend has neither a sleep
    /// primitive we can call from the contrix-http-client crate (no
    /// `tokio::time` driver) nor an `is_connect` accessor on
    /// `reqwest::Error`, and status-based retry windows would require
    /// pulling in `gloo-timers` or similar. We deliberately collapse retry
    /// to a single send on wasm32 and let the caller layer their own
    /// retry on top via `wasm-bindgen-futures` if they need it.
    #[cfg(target_arch = "wasm32")]
    async fn execute(&self, builder: RequestBuilder) -> Result<Response> {
        validate_request_builder(&builder)?;
        Ok(builder.send().await?)
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
        return Err(Error::Protocol(format!("{name} must be non-empty and header-safe")));
    }
    Ok(())
}

fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn reject_absolute_path(path: &str) -> Result<()> {
    if path.starts_with("//") || Url::parse(path).is_ok() {
        return Err(Error::Protocol(
            "request path must be relative to the Contrix service".to_owned(),
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
        let request = clone.build()?;
        reject_query_auth_in_url(request.url())?;
    }
    Ok(())
}

async fn error_envelope_from_response(response: Response) -> ErrorEnvelope {
    let status = response.status();
    let retry_after_ms = retry_after_ms(response.headers());
    let error = response.json::<ErrorEnvelope>().await.unwrap_or_else(|_| {
        ErrorEnvelope::new("internal_error", format!("HTTP request failed with status {status}"))
    });
    if error.retry_after_ms().is_none() { error.with_retry_after_ms(retry_after_ms) } else { error }
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
        return Err(Error::Protocol("path segment contains reserved characters".to_owned()));
    }
    Ok(())
}

// ── `cx.profile.agent_workspace.v1` response types ──────────────────────────
//
// Spec: contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md §11.
// These mirror the soland salvo ToSchema response types in
// `soland/src/routing/agent_workspace.rs` and are kept locally in the
// http-client crate to avoid widening contrix-core's wire surface for a
// profile-gated extension.

/// 200 response from `GET /api/v1/agent_workspace/mirror_flow`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentWorkspaceMirrorFlow {
    pub mirror_flow_id: String,
    pub mirror_space_id: String,
}

/// 200 response from `GET /api/v1/agent_workspace/pending_tasks`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentWorkspacePendingTasks {
    pub tasks: Vec<AgentWorkspacePendingTask>,
}

/// One in-flight agent_task summary. `execution_state` ∈ {pending_source_stub,
/// active}; `transparency` / `source_authority` are optional FSM cell heads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentWorkspacePendingTask {
    pub agent_task_id: String,
    pub execution_state: String,
    pub transparency: Option<String>,
    pub source_authority: Option<String>,
    pub mirror_flow_id: String,
    pub source_flow_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_relative_api_url() {
        let client = Client::new(Url::parse("https://alice.example/contrix/").unwrap()).unwrap();
        let request =
            client.request(Method::GET, "/api/v1/server/describe").unwrap().build().unwrap();
        assert_eq!(request.url().as_str(), "https://alice.example/contrix/api/v1/server/describe");
    }

    #[test]
    fn agent_workspace_resolve_mirror_flow_constructs_query_string() {
        let client = Client::new(Url::parse("https://alice.example/").unwrap()).unwrap();
        let builder = client
            .request(Method::GET, "/api/v1/agent_workspace/mirror_flow")
            .unwrap()
            .query(&[("source_flow_id", "cx:flow:01964200-0000-7000-8000-000000000011")]);
        let request = builder.build().unwrap();
        let s = request.url().as_str();
        assert!(s.contains("/api/v1/agent_workspace/mirror_flow"));
        assert!(s.contains("source_flow_id=cx%3Aflow%3A"));
    }

    #[test]
    fn agent_workspace_pending_tasks_response_roundtrip() {
        let body = serde_json::json!({
            "tasks": [
                {
                    "agent_task_id": "cx:agent_task:01",
                    "execution_state": "active",
                    "transparency": "ok",
                    "source_authority": "ok",
                    "mirror_flow_id": "cx:flow:01",
                    "source_flow_id": "cx:flow:02"
                }
            ]
        });
        let parsed: AgentWorkspacePendingTasks = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.tasks.len(), 1);
        assert_eq!(parsed.tasks[0].execution_state, "active");
    }

    #[test]
    fn rejects_remote_http_by_default() {
        let error = Client::new(Url::parse("http://alice.example/contrix/").unwrap()).unwrap_err();
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
        let client = Client::new(Url::parse("https://alice.example/contrix/").unwrap()).unwrap();
        let error = client.request(Method::GET, "https://evil.example/api").unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn rejects_header_unsafe_auth_material() {
        let error = Client::builder(Url::parse("https://alice.example/contrix/").unwrap())
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
        let client = Client::builder(Url::parse("https://alice.example/contrix/").unwrap())
            .user_agent("contrix-sdk-test/1")
            .build()
            .unwrap();
        let options = ClientRequestOptions::new()
            .request_id("req-1")
            .idempotency_key("idem-1")
            .wait_for("cx:cursor:01");
        let request = client
            .apply_request_options(client.request(Method::PUT, "/api/v1/sync").unwrap(), &options)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.headers()[USER_AGENT], "contrix-sdk-test/1");
        assert_eq!(request.headers()[HEADER_REQUEST_ID], "req-1");
        assert_eq!(request.headers()[HEADER_IDEMPOTENCY_KEY], "idem-1");
        assert_eq!(request.headers()[HEADER_WAIT_FOR], "cx:cursor:01");
    }

    #[test]
    fn request_options_reject_header_injection() {
        let client = Client::new(Url::parse("https://alice.example/contrix/").unwrap()).unwrap();
        let options = ClientRequestOptions::new().request_id("req\r\nX-Evil: true");

        let error = client
            .apply_request_options(
                client.request(Method::GET, "/api/v1/server/describe").unwrap(),
                &options,
            )
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[test]
    fn rejects_query_auth_on_base_path_and_built_request() {
        assert!(
            Client::new(Url::parse("https://alice.example/contrix/?access_token=secret").unwrap())
                .is_err()
        );

        let client = Client::new(Url::parse("https://alice.example/contrix/").unwrap()).unwrap();
        let builder = client
            .request(Method::GET, "/api/v1/events")
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

        assert_eq!(retry.retry_delay_from_headers(&headers, 1), Duration::from_secs(2));
        assert_eq!(
            retry.respect_retry_after(false).retry_delay_from_headers(&headers, 1),
            Duration::from_millis(100)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn transport_options_apply_without_panic() {
        let client = Client::builder(Url::parse("https://alice.example/contrix/").unwrap())
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

        assert_eq!(client.base_url().as_str(), "https://alice.example/contrix/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn proxy_can_be_added_via_builder() {
        let proxy = reqwest::Proxy::http("http://proxy.example:3128").unwrap();
        let client = Client::builder(Url::parse("https://alice.example/contrix/").unwrap())
            .proxy(proxy)
            .build()
            .unwrap();
        assert_eq!(client.base_url().as_str(), "https://alice.example/contrix/");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn transport_options_conflict_with_pre_built_http_client() {
        let http = reqwest::Client::new();
        let error = Client::builder(Url::parse("https://alice.example/contrix/").unwrap())
            .http_client(http)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(message) if message.contains("transport options")));
    }

    #[test]
    fn pre_built_http_client_alone_is_accepted() {
        let http = reqwest::Client::new();
        let client = Client::builder(Url::parse("https://alice.example/contrix/").unwrap())
            .http_client(http)
            .build()
            .unwrap();
        assert_eq!(client.base_url().as_str(), "https://alice.example/contrix/");
    }
}
