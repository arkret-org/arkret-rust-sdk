use std::time::Duration;

use reqwest::{
    Method, RequestBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::time::sleep;
use url::Url;

use contrix_core::{
    AppletActorResponse, AppletDescription, AppletPingResponse, AppletProtocolResponse,
    AppletSpaceResponse, AppletTransactionRequest, AppletTransactionResponse, AuthzCheckRequest,
    AuthzCheckResponse, AuthzInvitesResponse, BlobMetadata, BlobRef, BlobUploadMetadata,
    BlobUploadResponse, CollectionProjectionResponse, Commit, DeviceMessagesReceiveResponse,
    DeviceMessagesSendRequest, DeviceMessagesSendResponse, DirectoryDescription,
    DirectoryResolveHandleRequest, DirectoryResolveHandleResponse,
    DirectoryResolveOrganizationRequest, DirectoryResolveOrganizationResponse,
    DirectoryResolveSpaceRequest, DirectoryResolveSpaceResponse, DirectorySearchActorsRequest,
    DirectorySearchActorsResponse, DirectorySearchOrganizationsRequest,
    DirectorySearchOrganizationsResponse, DirectorySearchSpacesRequest,
    DirectorySearchSpacesResponse, DirectorySearchUsersResponse, EffectiveGrantsResponse, Error,
    ErrorEnvelope, FederationPullOperationsResponse, FederationPushOperationsRequest,
    FederationPushOperationsResponse, FederationSpaceMembersResponse, FederationTransactionRequest,
    FederationTransactionResponse, FederationVerifyActorRequest, FederationVerifyActorResponse,
    IdentityDescription, IdentityDocumentResponse, IdentityLogResponse, IdentityReceiptsResponse,
    IdentityResolveRequest, IdentityResolveResponse, IndexDescription, IndexEntityResponse,
    IndexInboxResponse, IndexNotificationsResponse, IndexSearchRequest, IndexSearchResponse,
    IndexSpaceHierarchyResponse, IndexThreadResponse, KeysClaimRequest, KeysClaimResponse,
    KeysQueryRequest, KeysQueryResponse, KeysUploadRequest, KeysUploadResponse,
    MediaIceConfigRequest, MediaIceConfigResponse, ModerationReportRequest,
    ModerationReportResponse, OkResponse, PolicyCheckRequest, PolicyCheckResponse,
    PushNotifyRequest, PushNotifyResponse, PushRegisterDeviceRequest, PushRegisterDeviceResponse,
    PushUnregisterDeviceRequest, QueryRequest, QueryResponse, RepoCommitResponse,
    RepoCommitsResponse, RepoDescription, RepoOperationsRequest, RepoOperationsResponse,
    RepoSyncRequest, RepoSyncResponse, Result, ServerDescription, ServiceRequirements,
    SubmitCommitResponse, SubmitDidOperationRequest, SubmitDidOperationResponse,
    SyncBackfillResponse, SyncDescription, SyncRequest, SyncResponse, SyncSnapshotHeadResponse,
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

    fn should_retry_status(&self, status: StatusCode) -> bool {
        self.retry_statuses.contains(&status.as_u16())
    }

    fn retry_delay(&self, attempt: usize) -> Duration {
        if self.base_delay.is_zero() {
            return Duration::ZERO;
        }
        let shift = attempt.saturating_sub(1).min(31) as u32;
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        let delay = self.base_delay.saturating_mul(factor);
        if self.max_delay.is_zero() { delay } else { std::cmp::min(delay, self.max_delay) }
    }

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
#[derive(Clone, Debug)]
pub enum RedirectPolicy {
    /// Refuse to follow any redirects (typical service-to-service).
    None,
    /// Follow up to `limit` redirects, then return the last response.
    Limited(usize),
}

impl RedirectPolicy {
    fn into_reqwest(self) -> reqwest::redirect::Policy {
        match self {
            RedirectPolicy::None => reqwest::redirect::Policy::none(),
            RedirectPolicy::Limited(limit) => reqwest::redirect::Policy::limited(limit),
        }
    }
}

/// Network/transport configuration applied to the underlying `reqwest::Client`.
///
/// Every field is optional. `None` means "let `reqwest` keep its default."
/// These options are silently ignored when [`ClientBuilder::http_client`] is
/// used to inject a fully-built `reqwest::Client` — in that mode the caller
/// owns the transport configuration end to end. [`ClientBuilder::build`]
/// returns [`Error::Protocol`] if both a pre-built client and any transport
/// option are set, to avoid silent surprises.
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
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.transport.timeout = Some(timeout);
        self
    }

    /// Cap the connection-establishment phase (TCP + TLS handshake) only.
    /// Independent of the total request timeout set via [`Self::timeout`].
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.transport.connect_timeout = Some(connect_timeout);
        self
    }

    /// Maximum idle time before a pooled connection is reaped. `None` means
    /// `reqwest`'s default. Set a value if your service is behind a proxy or
    /// load balancer with an aggressive idle-connection kill window.
    pub fn pool_idle_timeout(mut self, pool_idle_timeout: Duration) -> Self {
        self.transport.pool_idle_timeout = Some(pool_idle_timeout);
        self
    }

    /// Cap the number of idle connections kept open per remote host.
    pub fn pool_max_idle_per_host(mut self, pool_max_idle_per_host: usize) -> Self {
        self.transport.pool_max_idle_per_host = Some(pool_max_idle_per_host);
        self
    }

    /// Enable / disable TCP_NODELAY on connections. Defaults to reqwest's
    /// choice (currently enabled).
    pub fn tcp_nodelay(mut self, tcp_nodelay: bool) -> Self {
        self.transport.tcp_nodelay = Some(tcp_nodelay);
        self
    }

    /// Enable TCP keepalive with the given interval. Useful when the path
    /// includes long-lived NAT mappings or stateful firewalls that drop
    /// silent connections.
    pub fn tcp_keepalive(mut self, interval: Duration) -> Self {
        self.transport.tcp_keepalive = Some(interval);
        self
    }

    /// Send an HTTP/2 PING frame at this interval.
    pub fn http2_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.transport.http2_keep_alive_interval = Some(interval);
        self
    }

    /// Drop the HTTP/2 connection if a PING is unanswered within this window.
    pub fn http2_keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.transport.http2_keep_alive_timeout = Some(timeout);
        self
    }

    /// Whether to keep sending HTTP/2 PINGs while idle.
    pub fn http2_keep_alive_while_idle(mut self, enabled: bool) -> Self {
        self.transport.http2_keep_alive_while_idle = Some(enabled);
        self
    }

    /// Route requests through an HTTP / HTTPS proxy. Multiple calls compose:
    /// `reqwest` evaluates proxies in order and falls through to no-proxy if
    /// none match. Pair with [`Self::no_proxy`] to disable system proxy
    /// detection from environment variables.
    pub fn proxy(mut self, proxy: reqwest::Proxy) -> Self {
        self.transport.proxies.push(proxy);
        self
    }

    /// Disable proxy auto-detection from environment variables
    /// (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`). Combine with
    /// [`Self::proxy`] for fully explicit routing in production.
    pub fn no_proxy(mut self) -> Self {
        self.transport.no_proxy = true;
        self
    }

    /// Override the default redirect policy. The default is to follow up
    /// to 10 redirects; pass [`RedirectPolicy::None`] for service-to-service
    /// paths where redirect-following is a bug.
    pub fn redirect(mut self, policy: RedirectPolicy) -> Self {
        self.transport.redirect = Some(policy);
        self
    }

    /// Toggle gzip response decoding (the `gzip` feature is on by default
    /// in `contrix-client`'s `reqwest` profile, so this method exists to
    /// let callers turn it *off* when stricter content negotiation matters).
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

    pub async fn submit_commit(&self, commit: &Commit) -> Result<SubmitCommitResponse> {
        self.post("/api/v1/repo/submit-commit", commit).await
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

    pub async fn repo_describe(&self, repo_id: Option<&str>) -> Result<RepoDescription> {
        let mut builder = self.request(Method::GET, "/api/v1/repo/describe")?;
        if let Some(repo_id) = repo_id {
            builder = builder.query(&[("repo_id", repo_id)]);
        }
        self.send_json(builder).await
    }

    pub async fn repo_commits(
        &self,
        repo_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<RepoCommitsResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/repo/commits")?.query(&[("repo_id", repo_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn repo_commit(
        &self,
        commit_id: &str,
        repo_id: Option<&str>,
    ) -> Result<RepoCommitResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/repo/commit")?.query(&[("commit_id", commit_id)]);
        if let Some(repo_id) = repo_id {
            builder = builder.query(&[("repo_id", repo_id)]);
        }
        self.send_json(builder).await
    }

    pub async fn repo_operations(
        &self,
        request: &RepoOperationsRequest,
    ) -> Result<RepoOperationsResponse> {
        self.post("/api/v1/repo/operations", request).await
    }

    pub async fn repo_sync(&self, request: &RepoSyncRequest) -> Result<RepoSyncResponse> {
        self.post("/api/v1/repo/sync", request).await
    }

    pub async fn sync(&self, request: &SyncRequest) -> Result<SyncResponse> {
        self.post("/api/v1/sync", request).await
    }

    pub async fn sync_describe(&self) -> Result<SyncDescription> {
        self.get("/api/v1/sync/describe").await
    }

    /// Subscribe to the Event stream for one or more Spaces / actors via
    /// `cx.events.subscribe` (`GET /api/v1/events/subscribe`). Wire-breaking
    /// rename of the legacy `cx.sync.subscribe` (spec C17, 2026-05-08): the
    /// selector is now `spaces[]` ∪ `actors[]` repeated query args, and the
    /// frame schema's top field changed from `type` to `kind` with new kinds
    /// `dropped` / `epoch_rotation` / `unauthorized` / `resync_required` /
    /// `frontier` / `heartbeat` / `catchup_complete` (clients MUST handle the
    /// new kinds explicitly instead of treating unknown frames as `event`).
    pub async fn events_subscribe_stream(
        &self,
        space_id: &str,
        from: Option<&str>,
    ) -> Result<Response> {
        let mut builder = self
            .request(Method::GET, "/api/v1/events/subscribe")?
            .query(&[("spaces", space_id)]);
        if let Some(from) = from {
            builder = builder.query(&[("from", from)]);
        }
        self.send_response(builder).await
    }

    /// Range-read Events via `cx.events.query` (`GET /api/v1/events`),
    /// folding the legacy `cx.events.list` (forward) and `cx.sync.backfill`
    /// (backward) into a single op (spec C17, 2026-05-08). Pass
    /// `direction=Some("backward")` for backfill semantics; `None` defaults to
    /// forward.
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

    pub async fn index_query<T: DeserializeOwned>(
        &self,
        request: &QueryRequest,
    ) -> Result<QueryResponse<T>> {
        let mut builder = self.request(Method::POST, "/api/v1/index/query")?;
        let mut options = ClientRequestOptions::new();
        if let Some(consistency) = &request.consistency {
            options = options.wait_for(&consistency.wait_for);
        }
        builder = self.apply_request_options(builder, &options)?;
        self.send_json(builder.json(request)).await
    }

    /// T20 — fetch the materialised collection projection for a saved
    /// `View{kind="collection"}` (kanban / board / list / table /
    /// calendar / gantt renderer) per `models/views.md` §6.3.
    ///
    /// Unlike [`Self::index_query`] which returns a flat
    /// `QueryResponse<T>`, this returns a nested
    /// [`CollectionProjectionResponse`] with `groups[].items[]` ready
    /// for a kanban-style render in one pass. The server is expected
    /// to apply authz trimming, locked-discussion lazy_link policy,
    /// and stable rank ordering before responding.
    ///
    /// Wire path: `POST /api/v1/views/{view_id}/projection`. Empty
    /// JSON object body is sent so middleware that requires a body
    /// works; future revisions MAY accept overrides
    /// (sync_token, filter overlays) in the same body.
    ///
    /// `wait_for` is honoured via the `X-Contrix-Wait-For` header so
    /// callers can implement read-your-writes against a known sync
    /// token.
    pub async fn collection_projection(
        &self,
        view_id: &str,
        wait_for: Option<&str>,
    ) -> Result<CollectionProjectionResponse> {
        let path = format!("/api/v1/views/{view_id}/projection");
        let mut builder = self.request(Method::POST, &path)?;
        let mut options = ClientRequestOptions::new();
        if let Some(token) = wait_for {
            options = options.wait_for(token);
        }
        builder = self.apply_request_options(builder, &options)?;
        // Empty object body keeps middleware happy and leaves room for
        // future filter overlays without changing the wire path.
        self.send_json(builder.json(&serde_json::json!({}))).await
    }

    pub async fn authz_check(&self, request: &AuthzCheckRequest) -> Result<AuthzCheckResponse> {
        self.post("/api/v1/authz/check", request).await
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

    pub async fn send_device_messages(
        &self,
        txn_id: &str,
        request: &DeviceMessagesSendRequest,
    ) -> Result<DeviceMessagesSendResponse> {
        reject_path_segment(txn_id)?;
        let path = format!("/api/v1/device_messages/{txn_id}");
        self.put(&path, request).await
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

    pub async fn federation_transaction(
        &self,
        txn_id: &str,
        request: &FederationTransactionRequest,
    ) -> Result<FederationTransactionResponse> {
        reject_path_segment(txn_id)?;
        let path = format!("/api/v1/federation/transactions/{txn_id}");
        self.put(&path, request).await
    }

    pub async fn federation_push_operations(
        &self,
        request: &FederationPushOperationsRequest,
    ) -> Result<FederationPushOperationsResponse> {
        self.post("/api/v1/federation/push-operations", request).await
    }

    pub async fn federation_pull_operations(
        &self,
        space_id: &str,
        after_cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<FederationPullOperationsResponse> {
        let mut builder = self
            .request(Method::GET, "/api/v1/federation/pull-operations")?
            .query(&[("space_id", space_id)]);
        if let Some(after_cursor) = after_cursor {
            builder = builder.query(&[("after_cursor", after_cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn federation_space_members(
        &self,
        space_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<FederationSpaceMembersResponse> {
        let mut builder = self
            .request(Method::GET, "/api/v1/federation/space-members")?
            .query(&[("space_id", space_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn federation_verify_actor(
        &self,
        request: &FederationVerifyActorRequest,
    ) -> Result<FederationVerifyActorResponse> {
        self.post("/api/v1/federation/verify-actor", request).await
    }

    pub async fn index_describe(&self) -> Result<IndexDescription> {
        self.get("/api/v1/index/describe").await
    }

    pub async fn index_entity(
        &self,
        entity_id: &str,
        space_id: Option<&str>,
        at: Option<&str>,
    ) -> Result<IndexEntityResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/index/entity")?.query(&[("entity_id", entity_id)]);
        if let Some(space_id) = space_id {
            builder = builder.query(&[("space_id", space_id)]);
        }
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_thread(
        &self,
        topic_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<IndexThreadResponse> {
        let mut builder =
            self.request(Method::GET, "/api/v1/index/thread")?.query(&[("topic_id", topic_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_notifications(
        &self,
        cursor: Option<&str>,
        state: Option<&str>,
        limit: Option<u32>,
    ) -> Result<IndexNotificationsResponse> {
        let mut builder = self.request(Method::GET, "/api/v1/index/notifications")?;
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(state) = state {
            builder = builder.query(&[("state", state)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_inbox(
        &self,
        scope: Option<&str>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<IndexInboxResponse> {
        let mut builder = self.request(Method::GET, "/api/v1/index/inbox")?;
        if let Some(scope) = scope {
            builder = builder.query(&[("scope", scope)]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_search(&self, request: &IndexSearchRequest) -> Result<IndexSearchResponse> {
        self.post("/api/v1/index/search", request).await
    }

    pub async fn index_space_hierarchy(
        &self,
        space_id: &str,
        depth: Option<u32>,
        include_unconfirmed: Option<bool>,
    ) -> Result<IndexSpaceHierarchyResponse> {
        let mut builder = self
            .request(Method::GET, "/api/v1/index/space-hierarchy")?
            .query(&[("space_id", space_id)]);
        if let Some(depth) = depth {
            builder = builder.query(&[("depth", depth)]);
        }
        if let Some(include_unconfirmed) = include_unconfirmed {
            builder = builder.query(&[("include_unconfirmed", include_unconfirmed)]);
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
        txn_id: &str,
        request: &AppletTransactionRequest,
    ) -> Result<AppletTransactionResponse> {
        reject_path_segment(txn_id)?;
        let path = format!("/api/v1/applet/transactions/{txn_id}");
        self.put(&path, request).await
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
    let mut error = response.json::<ErrorEnvelope>().await.unwrap_or_else(|_| ErrorEnvelope {
        errcode: "cx.error.http_status".to_owned(),
        error: format!("HTTP request failed with status {status}"),
        retry_after_ms: None,
        extra: Default::default(),
    });
    if error.retry_after_ms.is_none() {
        error.retry_after_ms = retry_after_ms;
    }
    error
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
    fn rejects_remote_http_by_default() {
        let error = Client::new(Url::parse("http://alice.example/contrix/").unwrap()).unwrap_err();
        assert!(matches!(error, Error::InsecureUrl(_)));
    }

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
            .request(Method::GET, "/api/v1/index/entity")
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

    #[test]
    fn proxy_can_be_added_via_builder() {
        let proxy = reqwest::Proxy::http("http://proxy.example:3128").unwrap();
        let client = Client::builder(Url::parse("https://alice.example/contrix/").unwrap())
            .proxy(proxy)
            .build()
            .unwrap();
        assert_eq!(client.base_url().as_str(), "https://alice.example/contrix/");
    }

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
