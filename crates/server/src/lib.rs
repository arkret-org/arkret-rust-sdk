//! Server-side protocol endpoint registry.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts to keep route registration and advertised operation IDs aligned
//! with the protocol without pulling a web stack into the SDK.

#[cfg(feature = "salvo")]
pub mod salvo_adapter;

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use contrix_core::{
    AppletActorResponse, AppletDescription, AppletPingResponse, AppletProtocolResponse,
    AppletSpaceResponse, AppletTransactionRequest, AppletTransactionResponse, AuthzCheckRequest,
    AuthzCheckResponse, AuthzInvitesResponse, BlobMetadata, BlobUploadMetadata, BlobUploadResponse,
    DeviceMessagesReceiveResponse, DeviceMessagesSendRequest, DeviceMessagesSendResponse,
    DirectoryDescription, DirectoryResolveHandleRequest, DirectoryResolveHandleResponse,
    DirectoryResolveOrganizationRequest, DirectoryResolveOrganizationResponse,
    DirectoryResolveSpaceRequest, DirectoryResolveSpaceResponse, DirectorySearchActorsRequest,
    DirectorySearchActorsResponse, DirectorySearchOrganizationsRequest,
    DirectorySearchOrganizationsResponse, DirectorySearchSpacesRequest,
    DirectorySearchSpacesResponse, DirectorySearchUsersResponse, EffectiveGrantsResponse,
    FederationPullOperationsResponse, FederationPushOperationsRequest,
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
    RepoSyncRequest, RepoSyncResponse, Result, ServerDescription, SubmitCommitResponse,
    SubmitDidOperationRequest, SubmitDidOperationResponse, SyncBackfillResponse, SyncDescription,
    SyncRequest, SyncResponse, SyncSnapshotHeadResponse, canonical,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointMethod {
    Get,
    Head,
    Post,
    Put,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointContract {
    pub operation_id: &'static str,
    pub method: EndpointMethod,
    pub path: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointParameterLocation {
    Path,
    Query,
    Header,
}

impl EndpointParameterLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointParameter {
    pub name: &'static str,
    pub location: EndpointParameterLocation,
    pub required: bool,
    pub schema: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointSchemaBinding {
    pub operation_id: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
    pub request_body_content_type: Option<&'static str>,
    pub response_body_content_type: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpAdapterRequest {
    pub method: EndpointMethod,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpAdapterResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedEndpoint<'a> {
    pub contract: &'a EndpointContract,
    pub path_parameters: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutedHttpAdapterRequest {
    pub request: HttpAdapterRequest,
    pub operation_id: &'static str,
    pub path_parameters: BTreeMap<String, String>,
}

pub trait TowerLikeEndpointService {
    type Request;
    type Response;

    fn call(&mut self, request: Self::Request) -> Result<Self::Response>;
}

impl<F> TowerLikeEndpointService for F
where
    F: FnMut(HttpAdapterRequest) -> Result<HttpAdapterResponse>,
{
    type Request = HttpAdapterRequest;
    type Response = HttpAdapterResponse;

    fn call(&mut self, request: Self::Request) -> Result<Self::Response> {
        self(request)
    }
}

pub trait RoutedEndpointService {
    fn call(&mut self, request: RoutedHttpAdapterRequest) -> Result<HttpAdapterResponse>;
}

impl<F> RoutedEndpointService for F
where
    F: FnMut(RoutedHttpAdapterRequest) -> Result<HttpAdapterResponse>,
{
    fn call(&mut self, request: RoutedHttpAdapterRequest) -> Result<HttpAdapterResponse> {
        self(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerAuthenticationScheme {
    Anonymous,
    BearerToken,
    HttpMessageSignature,
    MutualTls,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub subject: String,
    pub scheme: ServerAuthenticationScheme,
    pub scopes: BTreeSet<String>,
}

impl AuthenticatedPrincipal {
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".to_owned(),
            scheme: ServerAuthenticationScheme::Anonymous,
            scopes: BTreeSet::new(),
        }
    }

    pub fn bearer(subject: impl Into<String>, scopes: impl IntoIterator<Item = String>) -> Self {
        Self {
            subject: subject.into(),
            scheme: ServerAuthenticationScheme::BearerToken,
            scopes: scopes.into_iter().collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRequestContext {
    pub operation_id: &'static str,
    pub method: EndpointMethod,
    pub path: String,
    pub path_parameters: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

impl ServerRequestContext {
    pub fn from_routed_request(request: &RoutedHttpAdapterRequest) -> Self {
        Self {
            operation_id: request.operation_id,
            method: request.request.method,
            path: request.request.path.clone(),
            path_parameters: request.path_parameters.clone(),
            headers: request.request.headers.clone(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMiddlewareRejection {
    pub status: u16,
    pub errcode: String,
    pub error: String,
    pub headers: BTreeMap<String, String>,
}

impl ServerMiddlewareRejection {
    pub fn new(status: u16, errcode: impl Into<String>, error: impl Into<String>) -> Self {
        Self { status, errcode: errcode.into(), error: error.into(), headers: BTreeMap::new() }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    pub fn into_response(self) -> HttpAdapterResponse {
        let mut response = adapter_error_response(self.status, self.errcode, self.error);
        response.headers.extend(self.headers);
        response
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerAuthenticationDecision {
    Authenticated(AuthenticatedPrincipal),
    Missing,
    Denied(ServerMiddlewareRejection),
}

pub trait ServerAuthenticator {
    fn authenticate(&mut self, context: &ServerRequestContext) -> ServerAuthenticationDecision;
}

#[derive(Clone, Debug, Default)]
pub struct BearerTokenAuthenticator {
    tokens: BTreeMap<String, AuthenticatedPrincipal>,
}

impl BearerTokenAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_token(
        mut self,
        token: impl Into<String>,
        principal: AuthenticatedPrincipal,
    ) -> Self {
        self.tokens.insert(token.into(), principal);
        self
    }

    pub fn insert_token(&mut self, token: impl Into<String>, principal: AuthenticatedPrincipal) {
        self.tokens.insert(token.into(), principal);
    }
}

impl ServerAuthenticator for BearerTokenAuthenticator {
    fn authenticate(&mut self, context: &ServerRequestContext) -> ServerAuthenticationDecision {
        let Some(header) = context.header("authorization") else {
            return ServerAuthenticationDecision::Missing;
        };
        let Some(token) = header.strip_prefix("Bearer ") else {
            return ServerAuthenticationDecision::Denied(ServerMiddlewareRejection::new(
                401,
                "cx.error.unauthorized",
                "Unsupported Authorization scheme",
            ));
        };
        match self.tokens.get(token) {
            Some(principal) => ServerAuthenticationDecision::Authenticated(principal.clone()),
            None => ServerAuthenticationDecision::Denied(ServerMiddlewareRejection::new(
                401,
                "cx.error.unauthorized",
                "Unknown bearer token",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerAuthorizationDecision {
    Allow,
    Deny(ServerMiddlewareRejection),
}

pub trait ServerAuthorizer {
    fn authorize(
        &mut self,
        context: &ServerRequestContext,
        principal: &AuthenticatedPrincipal,
    ) -> ServerAuthorizationDecision;
}

#[derive(Clone, Debug, Default)]
pub struct OperationScopeAuthorizer;

impl OperationScopeAuthorizer {
    pub fn new() -> Self {
        Self
    }
}

impl ServerAuthorizer for OperationScopeAuthorizer {
    fn authorize(
        &mut self,
        context: &ServerRequestContext,
        principal: &AuthenticatedPrincipal,
    ) -> ServerAuthorizationDecision {
        let operation_scope = format!("operation:{}", context.operation_id);
        if principal.scopes.contains("*")
            || principal.scopes.contains(context.operation_id)
            || principal.scopes.contains(&operation_scope)
        {
            ServerAuthorizationDecision::Allow
        } else {
            ServerAuthorizationDecision::Deny(ServerMiddlewareRejection::new(
                403,
                "cx.error.forbidden",
                format!(
                    "principal '{}' lacks scope for {}",
                    principal.subject, context.operation_id
                ),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServerIdempotencyKey {
    pub principal: String,
    pub operation_id: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerIdempotencyDecision {
    Miss,
    Hit(HttpAdapterResponse),
    Conflict(ServerMiddlewareRejection),
}

pub trait ServerIdempotencyStore {
    fn lookup(
        &mut self,
        key: &ServerIdempotencyKey,
        request_digest: &str,
    ) -> ServerIdempotencyDecision;

    fn store(
        &mut self,
        key: ServerIdempotencyKey,
        request_digest: String,
        response: &HttpAdapterResponse,
    );
}

#[derive(Clone, Debug, Default)]
pub struct MemoryIdempotencyStore {
    records: BTreeMap<ServerIdempotencyKey, MemoryIdempotencyRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemoryIdempotencyRecord {
    request_digest: String,
    response: HttpAdapterResponse,
}

impl MemoryIdempotencyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ServerIdempotencyStore for MemoryIdempotencyStore {
    fn lookup(
        &mut self,
        key: &ServerIdempotencyKey,
        request_digest: &str,
    ) -> ServerIdempotencyDecision {
        match self.records.get(key) {
            Some(record) if record.request_digest == request_digest => {
                ServerIdempotencyDecision::Hit(record.response.clone())
            }
            Some(_) => ServerIdempotencyDecision::Conflict(ServerMiddlewareRejection::new(
                409,
                "cx.error.idempotency_conflict",
                "Idempotency-Key was reused with different request bytes",
            )),
            None => ServerIdempotencyDecision::Miss,
        }
    }

    fn store(
        &mut self,
        key: ServerIdempotencyKey,
        request_digest: String,
        response: &HttpAdapterResponse,
    ) {
        self.records
            .insert(key, MemoryIdempotencyRecord { request_digest, response: response.clone() });
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerRateLimitDecision {
    Allow,
    Limited { retry_after_secs: u64 },
}

pub trait ServerRateLimiter {
    fn check(&mut self, key: &str) -> ServerRateLimitDecision;
}

#[derive(Clone, Debug)]
pub struct MemoryRateLimiter {
    max_requests: u32,
    window: Duration,
    buckets: BTreeMap<String, RateLimitBucket>,
}

#[derive(Clone, Debug)]
struct RateLimitBucket {
    window_start: SystemTime,
    count: u32,
}

impl MemoryRateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self { max_requests, window, buckets: BTreeMap::new() }
    }
}

impl Default for MemoryRateLimiter {
    fn default() -> Self {
        Self::new(60, Duration::from_secs(60))
    }
}

impl ServerRateLimiter for MemoryRateLimiter {
    fn check(&mut self, key: &str) -> ServerRateLimitDecision {
        if self.max_requests == 0 {
            return ServerRateLimitDecision::Limited {
                retry_after_secs: self.window.as_secs().max(1),
            };
        }

        let now = SystemTime::now();
        let bucket = self
            .buckets
            .entry(key.to_owned())
            .or_insert(RateLimitBucket { window_start: now, count: 0 });

        let elapsed = now.duration_since(bucket.window_start).unwrap_or_default();
        if elapsed >= self.window {
            bucket.window_start = now;
            bucket.count = 0;
        }

        if bucket.count >= self.max_requests {
            let retry_after_secs = self
                .window
                .checked_sub(elapsed)
                .unwrap_or_else(|| Duration::from_secs(1))
                .as_secs()
                .max(1);
            ServerRateLimitDecision::Limited { retry_after_secs }
        } else {
            bucket.count += 1;
            ServerRateLimitDecision::Allow
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMiddlewareConfig {
    pub require_authentication: bool,
    pub public_operations: BTreeSet<String>,
    pub require_idempotency_key_for_mutations: bool,
    pub enable_idempotency: bool,
    pub enable_rate_limit: bool,
    pub idempotency_header: String,
}

impl Default for ServerMiddlewareConfig {
    fn default() -> Self {
        Self {
            require_authentication: true,
            public_operations: default_public_operations(),
            require_idempotency_key_for_mutations: true,
            enable_idempotency: true,
            enable_rate_limit: true,
            idempotency_header: "Idempotency-Key".to_owned(),
        }
    }
}

pub fn default_public_operations() -> BTreeSet<String> {
    [
        "cx.server.describe",
        "cx.identity.describe_registry",
        "cx.repo.describe",
        "cx.sync.describe",
        "cx.index.describe",
        "cx.directory.describe",
        "cx.applet.ping",
        "cx.applet.describe",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub struct ServerMiddlewareStack<S> {
    service: S,
    config: ServerMiddlewareConfig,
    authenticator: Box<dyn ServerAuthenticator + Send>,
    authorizer: Box<dyn ServerAuthorizer + Send>,
    idempotency_store: Box<dyn ServerIdempotencyStore + Send>,
    rate_limiter: Box<dyn ServerRateLimiter + Send>,
}

impl<S> ServerMiddlewareStack<S> {
    pub fn new(service: S) -> Self {
        Self {
            service,
            config: ServerMiddlewareConfig::default(),
            authenticator: Box::new(BearerTokenAuthenticator::default()),
            authorizer: Box::new(OperationScopeAuthorizer),
            idempotency_store: Box::new(MemoryIdempotencyStore::default()),
            rate_limiter: Box::new(MemoryRateLimiter::default()),
        }
    }

    pub fn with_config(mut self, config: ServerMiddlewareConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_authenticator<A>(mut self, authenticator: A) -> Self
    where
        A: ServerAuthenticator + Send + 'static,
    {
        self.authenticator = Box::new(authenticator);
        self
    }

    pub fn with_authorizer<A>(mut self, authorizer: A) -> Self
    where
        A: ServerAuthorizer + Send + 'static,
    {
        self.authorizer = Box::new(authorizer);
        self
    }

    pub fn with_idempotency_store<I>(mut self, idempotency_store: I) -> Self
    where
        I: ServerIdempotencyStore + Send + 'static,
    {
        self.idempotency_store = Box::new(idempotency_store);
        self
    }

    pub fn with_rate_limiter<R>(mut self, rate_limiter: R) -> Self
    where
        R: ServerRateLimiter + Send + 'static,
    {
        self.rate_limiter = Box::new(rate_limiter);
        self
    }
}

impl<S> RoutedEndpointService for ServerMiddlewareStack<S>
where
    S: RoutedEndpointService,
{
    fn call(&mut self, request: RoutedHttpAdapterRequest) -> Result<HttpAdapterResponse> {
        let context = ServerRequestContext::from_routed_request(&request);
        let public_operation = self.config.public_operations.contains(context.operation_id);

        let auth_decision = self.authenticator.authenticate(&context);
        let principal = match auth_decision {
            ServerAuthenticationDecision::Authenticated(principal) => principal,
            ServerAuthenticationDecision::Missing if public_operation => {
                AuthenticatedPrincipal::anonymous()
            }
            ServerAuthenticationDecision::Missing if self.config.require_authentication => {
                return Ok(ServerMiddlewareRejection::new(
                    401,
                    "cx.error.unauthorized",
                    "Authentication is required for this Contrix endpoint",
                )
                .into_response());
            }
            ServerAuthenticationDecision::Missing => AuthenticatedPrincipal::anonymous(),
            ServerAuthenticationDecision::Denied(rejection) => return Ok(rejection.into_response()),
        };

        if !public_operation {
            match self.authorizer.authorize(&context, &principal) {
                ServerAuthorizationDecision::Allow => {}
                ServerAuthorizationDecision::Deny(rejection) => {
                    return Ok(rejection.into_response());
                }
            }
        }

        let idempotency = self.prepare_idempotency(&request, &principal)?;
        if let PreparedIdempotency::Hit(response) = idempotency {
            return Ok(response);
        }

        if self.config.enable_rate_limit {
            let rate_limit_key = format!("{}:{}", principal.subject, context.operation_id);
            if let ServerRateLimitDecision::Limited { retry_after_secs } =
                self.rate_limiter.check(&rate_limit_key)
            {
                return Ok(ServerMiddlewareRejection::new(
                    429,
                    "cx.error.rate_limited",
                    "Contrix endpoint rate limit exceeded",
                )
                .with_header("Retry-After", retry_after_secs.to_string())
                .into_response());
            }
        }

        let response = self.service.call(request)?;
        if let PreparedIdempotency::Miss { key, request_digest } = idempotency {
            if response.status < 500 {
                self.idempotency_store.store(key, request_digest, &response);
            }
        }
        Ok(response)
    }
}

enum PreparedIdempotency {
    NotApplicable,
    Miss { key: ServerIdempotencyKey, request_digest: String },
    Hit(HttpAdapterResponse),
}

impl<S> ServerMiddlewareStack<S> {
    fn prepare_idempotency(
        &mut self,
        request: &RoutedHttpAdapterRequest,
        principal: &AuthenticatedPrincipal,
    ) -> Result<PreparedIdempotency> {
        if !self.config.enable_idempotency || !is_mutating_method(request.request.method) {
            return Ok(PreparedIdempotency::NotApplicable);
        }

        let Some(header) = header_value(&request.request.headers, &self.config.idempotency_header)
        else {
            if self.config.require_idempotency_key_for_mutations {
                return Ok(PreparedIdempotency::Hit(
                    ServerMiddlewareRejection::new(
                        428,
                        "cx.error.idempotency_required",
                        "Mutating Contrix endpoints require Idempotency-Key",
                    )
                    .into_response(),
                ));
            }
            return Ok(PreparedIdempotency::NotApplicable);
        };

        let key = ServerIdempotencyKey {
            principal: principal.subject.clone(),
            operation_id: request.operation_id.to_owned(),
            key: header.to_owned(),
        };
        let request_digest = routed_request_digest(request);
        match self.idempotency_store.lookup(&key, &request_digest) {
            ServerIdempotencyDecision::Miss => {
                Ok(PreparedIdempotency::Miss { key, request_digest })
            }
            ServerIdempotencyDecision::Hit(response) => Ok(PreparedIdempotency::Hit(response)),
            ServerIdempotencyDecision::Conflict(rejection) => {
                Ok(PreparedIdempotency::Hit(rejection.into_response()))
            }
        }
    }
}

fn is_mutating_method(method: EndpointMethod) -> bool {
    matches!(method, EndpointMethod::Post | EndpointMethod::Put)
}

fn routed_request_digest(request: &RoutedHttpAdapterRequest) -> String {
    let body_digest = canonical::sha256_digest(&request.request.body);
    canonical::sha256_digest(format!(
        "{}\n{}\n{}\n{}",
        request.operation_id,
        request.request.method.as_str(),
        request.request.path,
        body_digest
    ))
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
}

pub fn dispatch_routed_http_request<S>(
    service: &mut S,
    request: HttpAdapterRequest,
) -> HttpAdapterResponse
where
    S: RoutedEndpointService,
{
    if let Err(error) = reject_query_auth(&request.query) {
        return adapter_error_response(400, "cx.error.bad_request", error.to_string());
    }

    let Some(matched) = match_endpoint(request.method, &request.path) else {
        return adapter_error_response(404, "cx.error.not_found", "Contrix endpoint not found");
    };
    let operation_id = matched.contract.operation_id;

    match service.call(RoutedHttpAdapterRequest {
        request,
        operation_id,
        path_parameters: matched.path_parameters,
    }) {
        Ok(mut response) => {
            response
                .headers
                .entry("X-Contrix-Operation-Id".to_owned())
                .or_insert_with(|| operation_id.to_owned());
            response
        }
        Err(error) => adapter_error_response(500, "cx.error.internal", error.to_string()),
    }
}

fn adapter_error_response(
    status: u16,
    errcode: impl Into<String>,
    error: impl Into<String>,
) -> HttpAdapterResponse {
    HttpAdapterResponse {
        status,
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: serde_json::to_vec(&json!({
            "errcode": errcode.into(),
            "error": error.into(),
        }))
        .unwrap_or_default(),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGoldenVector {
    pub name: String,
    pub profile: String,
    pub input: Value,
    pub expected: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireConformanceVector {
    pub name: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub body: Value,
    pub expected_status: u16,
    pub expected_errcode: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolFixtureFlow {
    Server,
    Identity,
    Repo,
    Sync,
    Blob,
    Authz,
    Federation,
    Index,
    Directory,
    Push,
    DeviceMessages,
    Keys,
    Policy,
    Media,
    Moderation,
    Applet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFixtureStep {
    pub flow: ProtocolFixtureFlow,
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub request_schema: String,
    pub response_schema: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFixtureReport {
    pub steps: Vec<ProtocolFixtureStep>,
}

impl ProtocolFixtureReport {
    pub fn covers(&self, flow: ProtocolFixtureFlow) -> bool {
        self.steps.iter().any(|step| step.flow == flow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolServerFixture {
    flows: BTreeSet<ProtocolFixtureFlow>,
}

impl ProtocolServerFixture {
    pub fn new(flows: impl IntoIterator<Item = ProtocolFixtureFlow>) -> Self {
        Self { flows: flows.into_iter().collect() }
    }

    pub fn all_flows() -> Self {
        Self::new([
            ProtocolFixtureFlow::Server,
            ProtocolFixtureFlow::Identity,
            ProtocolFixtureFlow::Repo,
            ProtocolFixtureFlow::Sync,
            ProtocolFixtureFlow::Blob,
            ProtocolFixtureFlow::Authz,
            ProtocolFixtureFlow::Federation,
            ProtocolFixtureFlow::Index,
            ProtocolFixtureFlow::Directory,
            ProtocolFixtureFlow::Push,
            ProtocolFixtureFlow::DeviceMessages,
            ProtocolFixtureFlow::Keys,
            ProtocolFixtureFlow::Policy,
            ProtocolFixtureFlow::Media,
            ProtocolFixtureFlow::Moderation,
            ProtocolFixtureFlow::Applet,
        ])
    }

    pub fn run(&self) -> Result<ProtocolFixtureReport> {
        let contracts_by_operation: BTreeMap<_, _> =
            endpoint_contracts().iter().map(|contract| (contract.operation_id, contract)).collect();
        let mut steps = Vec::new();
        for flow in &self.flows {
            for operation_id in fixture_operations(*flow) {
                let contract = contracts_by_operation.get(operation_id).ok_or_else(|| {
                    contrix_core::Error::Protocol(format!(
                        "fixture operation '{operation_id}' is missing from endpoint registry"
                    ))
                })?;
                let binding = endpoint_schema_binding(contract);
                steps.push(ProtocolFixtureStep {
                    flow: *flow,
                    operation_id: (*operation_id).to_owned(),
                    method: contract.method.as_str().to_owned(),
                    path: contract.path.to_owned(),
                    request_schema: binding.request_schema.to_owned(),
                    response_schema: binding.response_schema.to_owned(),
                });
            }
        }
        Ok(ProtocolFixtureReport { steps })
    }
}

impl Default for ProtocolServerFixture {
    fn default() -> Self {
        Self::all_flows()
    }
}

fn fixture_operations(flow: ProtocolFixtureFlow) -> &'static [&'static str] {
    match flow {
        ProtocolFixtureFlow::Server => &["cx.server.describe"],
        ProtocolFixtureFlow::Identity => &[
            "cx.identity.describe_registry",
            "cx.identity.resolve",
            "cx.identity.get_document",
            "cx.identity.get_log",
            "cx.identity.submit_did_operation",
            "cx.identity.get_receipts",
        ],
        ProtocolFixtureFlow::Repo => {
            &["cx.repo.describe", "cx.repo.submit_commit", "cx.repo.get_operations", "cx.repo.sync"]
        }
        ProtocolFixtureFlow::Sync => &[
            "cx.sync.client_sync",
            "cx.sync.subscribe",
            "cx.sync.backfill",
            "cx.sync.get_snapshot_head",
        ],
        ProtocolFixtureFlow::Blob => &["cx.blob.upload", "cx.blob.head", "cx.blob.get"],
        ProtocolFixtureFlow::Authz => {
            &["cx.authz.get_effective_grants", "cx.authz.get_invites", "cx.authz.check"]
        }
        ProtocolFixtureFlow::Federation => &[
            "cx.federation.transaction",
            "cx.federation.push_operations",
            "cx.federation.pull_operations",
            "cx.federation.space_members",
            "cx.federation.verify_actor",
        ],
        ProtocolFixtureFlow::Index => &[
            "cx.index.describe",
            "cx.index.get_entity",
            "cx.index.query",
            "cx.index.thread",
            "cx.index.notifications",
            "cx.index.inbox",
            "cx.index.search",
            "cx.index.space_hierarchy",
        ],
        ProtocolFixtureFlow::Directory => &[
            "cx.directory.describe",
            "cx.directory.search_spaces",
            "cx.directory.resolve_space",
            "cx.directory.search_organizations",
            "cx.directory.resolve_organization",
            "cx.directory.search_actors",
            "cx.directory.search_users",
            "cx.directory.resolve_handle",
        ],
        ProtocolFixtureFlow::Push => {
            &["cx.push.register_device", "cx.push.unregister_device", "cx.push.notify"]
        }
        ProtocolFixtureFlow::DeviceMessages => {
            &["cx.device_messages.put", "cx.device_messages.get"]
        }
        ProtocolFixtureFlow::Keys => &["cx.keys.upload", "cx.keys.query", "cx.keys.claim"],
        ProtocolFixtureFlow::Policy => &["cx.policy.check"],
        ProtocolFixtureFlow::Media => &["cx.media.ice_config"],
        ProtocolFixtureFlow::Moderation => &["cx.moderation.report"],
        ProtocolFixtureFlow::Applet => &[
            "cx.applet.ping",
            "cx.applet.describe",
            "cx.applet.transaction",
            "cx.applet.query_actor",
            "cx.applet.query_space",
            "cx.applet.protocol_metadata",
            "cx.applet.third_party_users",
            "cx.applet.third_party_locations",
        ],
    }
}

pub const ENDPOINT_CONTRACTS: &[EndpointContract] = &[
    EndpointContract {
        operation_id: "cx.server.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/server/describe",
    },
    EndpointContract {
        operation_id: "cx.identity.describe_registry",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/describe",
    },
    EndpointContract {
        operation_id: "cx.identity.resolve",
        method: EndpointMethod::Post,
        path: "/api/v1/identity/resolve",
    },
    EndpointContract {
        operation_id: "cx.identity.get_document",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/document",
    },
    EndpointContract {
        operation_id: "cx.identity.get_log",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/log",
    },
    EndpointContract {
        operation_id: "cx.identity.submit_did_operation",
        method: EndpointMethod::Post,
        path: "/api/v1/identity/submit-did-operation",
    },
    EndpointContract {
        operation_id: "cx.identity.get_receipts",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/receipts",
    },
    EndpointContract {
        operation_id: "cx.repo.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/repo/describe",
    },
    EndpointContract {
        operation_id: "cx.repo.list_commits",
        method: EndpointMethod::Get,
        path: "/api/v1/repo/commits",
    },
    EndpointContract {
        operation_id: "cx.repo.get_commit",
        method: EndpointMethod::Get,
        path: "/api/v1/repo/commit",
    },
    EndpointContract {
        operation_id: "cx.repo.get_operations",
        method: EndpointMethod::Post,
        path: "/api/v1/repo/operations",
    },
    EndpointContract {
        operation_id: "cx.repo.sync",
        method: EndpointMethod::Post,
        path: "/api/v1/repo/sync",
    },
    EndpointContract {
        operation_id: "cx.repo.submit_commit",
        method: EndpointMethod::Post,
        path: "/api/v1/repo/submit-commit",
    },
    EndpointContract {
        operation_id: "cx.sync.client_sync",
        method: EndpointMethod::Post,
        path: "/api/v1/sync",
    },
    EndpointContract {
        operation_id: "cx.sync.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/describe",
    },
    EndpointContract {
        operation_id: "cx.sync.subscribe",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/subscribe",
    },
    EndpointContract {
        operation_id: "cx.sync.backfill",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/backfill",
    },
    EndpointContract {
        operation_id: "cx.sync.get_snapshot_head",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/snapshot-head",
    },
    EndpointContract {
        operation_id: "cx.federation.transaction",
        method: EndpointMethod::Put,
        path: "/api/v1/federation/transactions/{txn_id}",
    },
    EndpointContract {
        operation_id: "cx.federation.push_operations",
        method: EndpointMethod::Post,
        path: "/api/v1/federation/push-operations",
    },
    EndpointContract {
        operation_id: "cx.federation.pull_operations",
        method: EndpointMethod::Get,
        path: "/api/v1/federation/pull-operations",
    },
    EndpointContract {
        operation_id: "cx.federation.space_members",
        method: EndpointMethod::Get,
        path: "/api/v1/federation/space-members",
    },
    EndpointContract {
        operation_id: "cx.federation.verify_actor",
        method: EndpointMethod::Post,
        path: "/api/v1/federation/verify-actor",
    },
    EndpointContract {
        operation_id: "cx.index.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/index/describe",
    },
    EndpointContract {
        operation_id: "cx.index.get_entity",
        method: EndpointMethod::Get,
        path: "/api/v1/index/entity",
    },
    EndpointContract {
        operation_id: "cx.index.query",
        method: EndpointMethod::Post,
        path: "/api/v1/index/query",
    },
    EndpointContract {
        operation_id: "cx.index.thread",
        method: EndpointMethod::Get,
        path: "/api/v1/index/thread",
    },
    EndpointContract {
        operation_id: "cx.index.notifications",
        method: EndpointMethod::Get,
        path: "/api/v1/index/notifications",
    },
    EndpointContract {
        operation_id: "cx.index.inbox",
        method: EndpointMethod::Get,
        path: "/api/v1/index/inbox",
    },
    EndpointContract {
        operation_id: "cx.index.search",
        method: EndpointMethod::Post,
        path: "/api/v1/index/search",
    },
    EndpointContract {
        operation_id: "cx.index.space_hierarchy",
        method: EndpointMethod::Get,
        path: "/api/v1/index/space-hierarchy",
    },
    EndpointContract {
        operation_id: "cx.directory.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/directory/describe",
    },
    EndpointContract {
        operation_id: "cx.directory.search_spaces",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/search-spaces",
    },
    EndpointContract {
        operation_id: "cx.directory.resolve_space",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/resolve-space",
    },
    EndpointContract {
        operation_id: "cx.directory.search_organizations",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/search-organizations",
    },
    EndpointContract {
        operation_id: "cx.directory.resolve_organization",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/resolve-organization",
    },
    EndpointContract {
        operation_id: "cx.directory.search_actors",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/search-actors",
    },
    EndpointContract {
        operation_id: "cx.directory.search_users",
        method: EndpointMethod::Get,
        path: "/api/v1/directory/search-users",
    },
    EndpointContract {
        operation_id: "cx.directory.resolve_handle",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/resolve-handle",
    },
    EndpointContract {
        operation_id: "cx.directory.private_contact_discovery",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/private-contact-discovery",
    },
    EndpointContract {
        operation_id: "cx.blob.upload",
        method: EndpointMethod::Post,
        path: "/api/v1/blob/upload",
    },
    EndpointContract {
        operation_id: "cx.blob.head",
        method: EndpointMethod::Head,
        path: "/api/v1/blob/get",
    },
    EndpointContract {
        operation_id: "cx.blob.get",
        method: EndpointMethod::Get,
        path: "/api/v1/blob/get",
    },
    EndpointContract {
        operation_id: "cx.push.register_device",
        method: EndpointMethod::Post,
        path: "/api/v1/push/register-device",
    },
    EndpointContract {
        operation_id: "cx.push.unregister_device",
        method: EndpointMethod::Post,
        path: "/api/v1/push/unregister-device",
    },
    EndpointContract {
        operation_id: "cx.push.notify",
        method: EndpointMethod::Post,
        path: "/api/v1/push/notify",
    },
    EndpointContract {
        operation_id: "cx.device_messages.put",
        method: EndpointMethod::Put,
        path: "/api/v1/device_messages/{txn_id}",
    },
    EndpointContract {
        operation_id: "cx.device_messages.get",
        method: EndpointMethod::Get,
        path: "/api/v1/device_messages",
    },
    EndpointContract {
        operation_id: "cx.keys.upload",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/upload",
    },
    EndpointContract {
        operation_id: "cx.keys.query",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/query",
    },
    EndpointContract {
        operation_id: "cx.keys.claim",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/claim",
    },
    EndpointContract {
        operation_id: "cx.keys.keypackages.upload",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/keypackages/upload",
    },
    EndpointContract {
        operation_id: "cx.keys.keypackages.claim",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/keypackages/claim",
    },
    EndpointContract {
        operation_id: "cx.keys.keypackages.consume",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/keypackages/consume",
    },
    EndpointContract {
        operation_id: "cx.keys.keypackages.revoke",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/keypackages/revoke",
    },
    EndpointContract {
        operation_id: "cx.authz.get_effective_grants",
        method: EndpointMethod::Get,
        path: "/api/v1/authz/effective-grants",
    },
    EndpointContract {
        operation_id: "cx.authz.get_invites",
        method: EndpointMethod::Get,
        path: "/api/v1/authz/invites",
    },
    EndpointContract {
        operation_id: "cx.authz.check",
        method: EndpointMethod::Post,
        path: "/api/v1/authz/check",
    },
    EndpointContract {
        operation_id: "cx.policy.check",
        method: EndpointMethod::Post,
        path: "/contrix/v1/check",
    },
    EndpointContract {
        operation_id: "cx.media.ice_config",
        method: EndpointMethod::Post,
        path: "/contrix/v1/ice-config",
    },
    EndpointContract {
        operation_id: "cx.moderation.report",
        method: EndpointMethod::Post,
        path: "/api/v1/moderation/report",
    },
    EndpointContract {
        operation_id: "cx.mimi.provider_directory",
        method: EndpointMethod::Get,
        path: "/api/v1/mimi/provider-directory",
    },
    EndpointContract {
        operation_id: "cx.mimi.key_material",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/key-material",
    },
    EndpointContract {
        operation_id: "cx.mimi.room_update",
        method: EndpointMethod::Put,
        path: "/api/v1/mimi/rooms/{room_id}/update",
    },
    EndpointContract {
        operation_id: "cx.mimi.notify",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/rooms/{room_id}/notify",
    },
    EndpointContract {
        operation_id: "cx.mimi.submit_message",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/rooms/{room_id}/messages",
    },
    EndpointContract {
        operation_id: "cx.mimi.group_info",
        method: EndpointMethod::Get,
        path: "/api/v1/mimi/rooms/{room_id}/group-info",
    },
    EndpointContract {
        operation_id: "cx.mimi.request_consent",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/consent/request",
    },
    EndpointContract {
        operation_id: "cx.mimi.update_consent",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/consent/update",
    },
    EndpointContract {
        operation_id: "cx.mimi.identifier_query",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/identifiers/query",
    },
    EndpointContract {
        operation_id: "cx.mimi.report_abuse",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/report-abuse",
    },
    EndpointContract {
        operation_id: "cx.mimi.proxy_download",
        method: EndpointMethod::Post,
        path: "/api/v1/mimi/proxy-download",
    },
    EndpointContract {
        operation_id: "cx.account.issue_session_grant",
        method: EndpointMethod::Post,
        path: "/api/v1/auth/account/session-grants",
    },
    EndpointContract {
        operation_id: "cx.account.device_pair",
        method: EndpointMethod::Post,
        path: "/api/v1/auth/account/device-pair",
    },
    EndpointContract {
        operation_id: "cx.account.oidc_callback",
        method: EndpointMethod::Post,
        path: "/api/v1/auth/account/oidc/callback",
    },
    EndpointContract {
        operation_id: "cx.admin.get_server_status",
        method: EndpointMethod::Get,
        path: "/api/v1/admin/server/status",
    },
    EndpointContract {
        operation_id: "cx.admin.update_account_status",
        method: EndpointMethod::Post,
        path: "/api/v1/admin/accounts/{account_id}/status",
    },
    EndpointContract {
        operation_id: "cx.admin.revoke_device",
        method: EndpointMethod::Post,
        path: "/api/v1/admin/devices/{device_id}/revoke",
    },
    EndpointContract {
        operation_id: "cx.admin.get_moderation_queue",
        method: EndpointMethod::Get,
        path: "/api/v1/admin/moderation/queue",
    },
    EndpointContract {
        operation_id: "cx.applet.ping",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/ping",
    },
    EndpointContract {
        operation_id: "cx.applet.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/describe",
    },
    EndpointContract {
        operation_id: "cx.applet.transaction",
        method: EndpointMethod::Put,
        path: "/api/v1/applet/transactions/{txn_id}",
    },
    EndpointContract {
        operation_id: "cx.applet.query_actor",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/actors/{actor_id}",
    },
    EndpointContract {
        operation_id: "cx.applet.query_space",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/spaces/{space_id_or_alias}",
    },
    EndpointContract {
        operation_id: "cx.applet.protocol_metadata",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/protocols/{protocol}",
    },
    EndpointContract {
        operation_id: "cx.applet.third_party_users",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/third_party/users",
    },
    EndpointContract {
        operation_id: "cx.applet.third_party_locations",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/third_party/locations",
    },
];

pub fn endpoint_contracts() -> &'static [EndpointContract] {
    ENDPOINT_CONTRACTS
}

impl EndpointMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Post => "post",
            Self::Put => "put",
        }
    }
}

pub fn endpoint_schema_bindings() -> Vec<EndpointSchemaBinding> {
    endpoint_contracts().iter().map(endpoint_schema_binding).collect()
}

pub fn endpoint_schema_binding(endpoint: &EndpointContract) -> EndpointSchemaBinding {
    let (request_schema, response_schema) = match endpoint.operation_id {
        "cx.server.describe" => ("ServerDescribeRequest", "ServerDescription"),
        "cx.identity.describe_registry" => ("IdentityDescribeRequest", "IdentityDescription"),
        "cx.identity.resolve" => ("IdentityResolveRequest", "IdentityResolveResponse"),
        "cx.identity.get_document" => ("IdentityDocumentQuery", "IdentityDocumentResponse"),
        "cx.identity.get_log" => ("IdentityLogQuery", "IdentityLogResponse"),
        "cx.identity.submit_did_operation" => {
            ("SubmitDidOperationRequest", "SubmitDidOperationResponse")
        }
        "cx.identity.get_receipts" => ("IdentityReceiptsQuery", "IdentityReceiptsResponse"),
        "cx.repo.describe" => ("RepoDescribeQuery", "RepoDescription"),
        "cx.repo.list_commits" => ("RepoCommitsQuery", "RepoCommitsResponse"),
        "cx.repo.get_commit" => ("RepoCommitQuery", "RepoCommitResponse"),
        "cx.repo.get_operations" => ("RepoOperationsRequest", "RepoOperationsResponse"),
        "cx.repo.sync" => ("RepoSyncRequest", "RepoSyncResponse"),
        "cx.repo.submit_commit" => ("Commit", "SubmitCommitResponse"),
        "cx.sync.client_sync" => ("SyncRequest", "SyncResponse"),
        "cx.sync.describe" => ("SyncDescribeRequest", "SyncDescription"),
        "cx.sync.subscribe" => ("SyncSubscribeQuery", "SyncSubscribeFrame"),
        "cx.sync.backfill" => ("SyncBackfillQuery", "SyncBackfillResponse"),
        "cx.sync.get_snapshot_head" => ("SyncSnapshotHeadQuery", "SyncSnapshotHeadResponse"),
        "cx.federation.transaction" => {
            ("FederationTransactionRequest", "FederationTransactionResponse")
        }
        "cx.federation.push_operations" => {
            ("FederationPushOperationsRequest", "FederationPushOperationsResponse")
        }
        "cx.federation.pull_operations" => {
            ("FederationPullOperationsQuery", "FederationPullOperationsResponse")
        }
        "cx.federation.space_members" => {
            ("FederationSpaceMembersQuery", "FederationSpaceMembersResponse")
        }
        "cx.federation.verify_actor" => {
            ("FederationVerifyActorRequest", "FederationVerifyActorResponse")
        }
        "cx.index.describe" => ("IndexDescribeRequest", "IndexDescription"),
        "cx.index.get_entity" => ("IndexEntityQuery", "IndexEntityResponse"),
        "cx.index.query" => ("QueryRequest", "QueryResponse"),
        "cx.index.thread" => ("IndexThreadQuery", "IndexThreadResponse"),
        "cx.index.notifications" => ("IndexNotificationsQuery", "IndexNotificationsResponse"),
        "cx.index.inbox" => ("IndexInboxQuery", "IndexInboxResponse"),
        "cx.index.search" => ("IndexSearchRequest", "IndexSearchResponse"),
        "cx.index.space_hierarchy" => ("IndexSpaceHierarchyQuery", "IndexSpaceHierarchyResponse"),
        "cx.directory.describe" => ("DirectoryDescribeRequest", "DirectoryDescription"),
        "cx.directory.search_spaces" => {
            ("DirectorySearchSpacesRequest", "DirectorySearchSpacesResponse")
        }
        "cx.directory.resolve_space" => {
            ("DirectoryResolveSpaceRequest", "DirectoryResolveSpaceResponse")
        }
        "cx.directory.search_organizations" => {
            ("DirectorySearchOrganizationsRequest", "DirectorySearchOrganizationsResponse")
        }
        "cx.directory.resolve_organization" => {
            ("DirectoryResolveOrganizationRequest", "DirectoryResolveOrganizationResponse")
        }
        "cx.directory.search_actors" => {
            ("DirectorySearchActorsRequest", "DirectorySearchActorsResponse")
        }
        "cx.directory.search_users" => {
            ("DirectorySearchUsersQuery", "DirectorySearchUsersResponse")
        }
        "cx.directory.resolve_handle" => {
            ("DirectoryResolveHandleRequest", "DirectoryResolveHandleResponse")
        }
        "cx.directory.private_contact_discovery" => {
            ("PrivateContactDiscoveryRequest", "PrivateContactDiscoveryResponse")
        }
        "cx.blob.upload" => ("BlobUploadMetadata", "BlobUploadResponse"),
        "cx.blob.head" => ("BlobGetQuery", "BlobMetadataHeaders"),
        "cx.blob.get" => ("BlobGetQuery", "BinaryBlobBody"),
        "cx.push.register_device" => ("PushRegisterDeviceRequest", "PushRegisterDeviceResponse"),
        "cx.push.unregister_device" => ("PushUnregisterDeviceRequest", "OkResponse"),
        "cx.push.notify" => ("PushNotifyRequest", "PushNotifyResponse"),
        "cx.device_messages.put" => ("DeviceMessagesSendRequest", "DeviceMessagesSendResponse"),
        "cx.device_messages.get" => ("DeviceMessagesGetQuery", "DeviceMessagesReceiveResponse"),
        "cx.keys.upload" => ("KeysUploadRequest", "KeysUploadResponse"),
        "cx.keys.query" => ("KeysQueryRequest", "KeysQueryResponse"),
        "cx.keys.claim" => ("KeysClaimRequest", "KeysClaimResponse"),
        "cx.keys.keypackages.upload" => ("KeyPackagesUploadRequest", "OkResponse"),
        "cx.keys.keypackages.claim" => ("KeyPackagesClaimRequest", "KeyPackagesClaimResponse"),
        "cx.keys.keypackages.consume" => ("KeyPackagesConsumeRequest", "OkResponse"),
        "cx.keys.keypackages.revoke" => ("KeyPackagesRevokeRequest", "OkResponse"),
        "cx.authz.get_effective_grants" => ("AuthzEffectiveGrantsQuery", "EffectiveGrantsResponse"),
        "cx.authz.get_invites" => ("AuthzInvitesQuery", "AuthzInvitesResponse"),
        "cx.authz.check" => ("AuthzCheckRequest", "AuthzCheckResponse"),
        "cx.policy.check" => ("PolicyCheckRequest", "PolicyCheckResponse"),
        "cx.media.ice_config" => ("MediaIceConfigRequest", "MediaIceConfigResponse"),
        "cx.moderation.report" => ("ModerationReportRequest", "ModerationReportResponse"),
        "cx.mimi.provider_directory" => ("MimiProviderDirectoryRequest", "JsonValue"),
        "cx.mimi.key_material" => ("MimiKeyMaterialRequest", "JsonValue"),
        "cx.mimi.room_update" => ("MimiRoomUpdateRequest", "JsonValue"),
        "cx.mimi.notify" => ("MimiNotifyRequest", "JsonValue"),
        "cx.mimi.submit_message" => ("MimiSubmitMessageRequest", "JsonValue"),
        "cx.mimi.group_info" => ("MimiGroupInfoQuery", "JsonValue"),
        "cx.mimi.request_consent" => ("MimiConsentRequest", "JsonValue"),
        "cx.mimi.update_consent" => ("MimiConsentUpdateRequest", "JsonValue"),
        "cx.mimi.identifier_query" => ("MimiIdentifierQueryRequest", "JsonValue"),
        "cx.mimi.report_abuse" => ("MimiReportAbuseRequest", "OkResponse"),
        "cx.mimi.proxy_download" => ("MimiProxyDownloadRequest", "JsonValue"),
        "cx.account.issue_session_grant" => {
            ("AccountSessionGrantRequest", "AccountSessionGrantResponse")
        }
        "cx.account.device_pair" => ("AccountDevicePairRequest", "AccountDevicePairResponse"),
        "cx.account.oidc_callback" => ("AccountOidcCallbackRequest", "AccountOidcCallbackResponse"),
        "cx.admin.get_server_status" => ("AdminServerStatusQuery", "JsonValue"),
        "cx.admin.update_account_status" => ("AdminAccountStatusRequest", "OkResponse"),
        "cx.admin.revoke_device" => ("AdminRevokeDeviceRequest", "OkResponse"),
        "cx.admin.get_moderation_queue" => ("AdminModerationQueueQuery", "JsonValue"),
        "cx.applet.ping" => ("AppletPingRequest", "AppletPingResponse"),
        "cx.applet.describe" => ("AppletDescribeRequest", "AppletDescription"),
        "cx.applet.transaction" => ("AppletTransactionRequest", "AppletTransactionResponse"),
        "cx.applet.query_actor" => ("AppletActorPath", "AppletActorResponse"),
        "cx.applet.query_space" => ("AppletSpacePath", "AppletSpaceResponse"),
        "cx.applet.protocol_metadata" => ("AppletProtocolPath", "AppletProtocolResponse"),
        "cx.applet.third_party_users" => ("AppletThirdPartyUsersRequest", "JsonValue"),
        "cx.applet.third_party_locations" => ("AppletThirdPartyLocationsRequest", "JsonValue"),
        _ => ("JsonValue", "JsonValue"),
    };

    EndpointSchemaBinding {
        operation_id: endpoint.operation_id,
        request_schema,
        response_schema,
        request_body_content_type: request_body_content_type(endpoint),
        response_body_content_type: response_body_content_type(endpoint),
    }
}

pub fn endpoint_parameters(endpoint: &EndpointContract) -> Vec<EndpointParameter> {
    let mut parameters = path_parameters(endpoint.path);
    parameters.extend(query_parameters(endpoint.operation_id));
    parameters.extend(header_parameters(endpoint.operation_id));
    parameters.push(EndpointParameter {
        name: "X-Contrix-Request-Id",
        location: EndpointParameterLocation::Header,
        required: false,
        schema: "String",
    });
    parameters.push(EndpointParameter {
        name: "Traceparent",
        location: EndpointParameterLocation::Header,
        required: false,
        schema: "String",
    });
    parameters
}

pub fn match_endpoint(method: EndpointMethod, path: &str) -> Option<MatchedEndpoint<'static>> {
    endpoint_contracts().iter().filter(|endpoint| endpoint.method == method).find_map(|endpoint| {
        match_path_template(endpoint.path, path)
            .map(|path_parameters| MatchedEndpoint { contract: endpoint, path_parameters })
    })
}

pub fn reject_query_auth(parameters: &BTreeMap<String, String>) -> Result<()> {
    for name in parameters.keys() {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "access_token"
                | "auth"
                | "authorization"
                | "bearer"
                | "device_proof"
                | "service_signature"
                | "signature"
        ) {
            return Err(contrix_core::Error::Protocol(
                "authentication material must be sent in headers, not query parameters".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn protocol_golden_vectors() -> Vec<ProtocolGoldenVector> {
    vec![
        ProtocolGoldenVector {
            name: "did_uuid_v4_layout".to_owned(),
            profile: "cx.conformance.identifiers.v1".to_owned(),
            input: json!({"did": "did:uuid:550e8400-e29b-41d4-a716-446655440000"}),
            expected: json!({"valid": true, "method": "uuid"}),
        },
        ProtocolGoldenVector {
            name: "cursor_prefix".to_owned(),
            profile: "cx.conformance.cursor.v1".to_owned(),
            input: json!({"cursor": "cx:cursor:sync:01JS0SP000000000000000000"}),
            expected: json!({"valid": true}),
        },
        ProtocolGoldenVector {
            name: "canonical_digest_prefix".to_owned(),
            profile: "cx.conformance.digest.v1".to_owned(),
            input: json!({"hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}),
            expected: json!({"valid": true, "algorithm": "sha256"}),
        },
        ProtocolGoldenVector {
            name: "canonical_json_object_order".to_owned(),
            profile: "cx.conformance.canonical_json.v1".to_owned(),
            input: json!({"b": 2, "a": 1}),
            expected: json!({"canonical": "{\"a\":1,\"b\":2}"}),
        },
        ProtocolGoldenVector {
            name: "hlc_shape".to_owned(),
            profile: "cx.conformance.hlc.v1".to_owned(),
            input: json!({"hlc": "2026-04-29T00:00:00.000Z-0000-node"}),
            expected: json!({"valid": true, "monotonic_components": ["wall_time", "counter", "node"]}),
        },
    ]
}

pub fn wire_negative_vectors() -> Vec<WireConformanceVector> {
    vec![
        WireConformanceVector {
            name: "query_auth_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v1/server/describe".to_owned(),
            query: BTreeMap::from([("access_token".to_owned(), "redacted".to_owned())]),
            headers: BTreeMap::new(),
            body: Value::Null,
            expected_status: 400,
            expected_errcode: "cx.error.query_auth_forbidden".to_owned(),
        },
        WireConformanceVector {
            name: "encoded_path_separator_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v1/federation/transactions/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_path_segment".to_owned(),
        },
        WireConformanceVector {
            name: "identity_invalid_did_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/identity/resolve".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"did": "alice.example"}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_id".to_owned(),
        },
        WireConformanceVector {
            name: "sync_stale_cursor_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"since": "cx:cursor:expired"}),
            expected_status: 410,
            expected_errcode: "cx.error.stale_cursor".to_owned(),
        },
        WireConformanceVector {
            name: "index_query_auth_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v1/index/entity".to_owned(),
            query: BTreeMap::from([
                ("entity_id".to_owned(), "cx:entity:1".to_owned()),
                ("access_token".to_owned(), "redacted".to_owned()),
            ]),
            headers: BTreeMap::new(),
            body: Value::Null,
            expected_status: 400,
            expected_errcode: "cx.error.query_auth_forbidden".to_owned(),
        },
        WireConformanceVector {
            name: "directory_invalid_handle_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/directory/resolve-handle".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"handle": ""}),
            expected_status: 400,
            expected_errcode: "cx.error.bad_request".to_owned(),
        },
        WireConformanceVector {
            name: "stale_cursor_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v1/federation/pull-operations".to_owned(),
            query: BTreeMap::from([
                ("space_id".to_owned(), "cx:space:01JS0SP000000000000000000".to_owned()),
                ("after_cursor".to_owned(), "cx:cursor:expired".to_owned()),
            ]),
            headers: BTreeMap::new(),
            body: Value::Null,
            expected_status: 410,
            expected_errcode: "cx.error.stale_cursor".to_owned(),
        },
        WireConformanceVector {
            name: "bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/blob/upload".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Digest".to_owned(), "sha256:not-hex".to_owned())]),
            body: json!({"size": 4}),
            expected_status: 400,
            expected_errcode: "cx.error.bad_digest".to_owned(),
        },
        WireConformanceVector {
            name: "push_bad_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/push/register-device".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer ".to_owned())]),
            body: json!({}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
        WireConformanceVector {
            name: "device_messages_invalid_txn_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v1/device_messages/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"messages": {}}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_path_segment".to_owned(),
        },
        WireConformanceVector {
            name: "keys_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/keys/query".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({"device_keys": {}}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
        WireConformanceVector {
            name: "authz_invalid_actor_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/authz/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"actor_id": "alice", "action": "read", "resource": {}}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_id".to_owned(),
        },
        WireConformanceVector {
            name: "policy_bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/contrix/v1/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"request_canonical_hash": "sha256:not-hex"}),
            expected_status: 400,
            expected_errcode: "cx.error.bad_digest".to_owned(),
        },
        WireConformanceVector {
            name: "media_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/contrix/v1/ice-config".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
        WireConformanceVector {
            name: "moderation_invalid_space_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/moderation/report".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"space_id": "room", "target_ref": "x", "reason": "spam", "reporter": "did:web:alice.example"}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_id".to_owned(),
        },
        WireConformanceVector {
            name: "applet_invalid_txn_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v1/applet/transactions/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 400,
            expected_errcode: "cx.error.invalid_path_segment".to_owned(),
        },
        WireConformanceVector {
            name: "missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/repo/submit-commit".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
        WireConformanceVector {
            name: "missing_idempotency_key_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 428,
            expected_errcode: "cx.error.idempotency_required".to_owned(),
        },
        WireConformanceVector {
            name: "idempotency_conflict_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([
                ("Authorization".to_owned(), "Bearer redacted".to_owned()),
                ("Idempotency-Key".to_owned(), "sync-1".to_owned()),
            ]),
            body: json!({"conflict": true}),
            expected_status: 409,
            expected_errcode: "cx.error.idempotency_conflict".to_owned(),
        },
    ]
}

#[derive(Clone, Debug)]
pub enum ServerRequest {
    ServerDescribe,
    IdentityDescribe,
    IdentityResolve(IdentityResolveRequest),
    IdentityDocument { did: String, version: Option<String> },
    IdentityLog { did: String, cursor: Option<String>, limit: Option<u32> },
    IdentitySubmitDidOperation(SubmitDidOperationRequest),
    IdentityReceipts { did: String, head: String },
    RepoDescribe { repo_id: Option<String> },
    RepoCommits { repo_id: String, cursor: Option<String>, limit: Option<u32> },
    RepoCommit { commit_id: String, repo_id: Option<String> },
    RepoOperations(RepoOperationsRequest),
    RepoSync(RepoSyncRequest),
    RepoSubmitCommit(contrix_core::Commit),
    Sync(SyncRequest),
    SyncDescribe,
    SyncBackfill { space_id: String, cursor: Option<String>, limit: Option<u32> },
    SyncSnapshotHead { space_id: String },
    FederationTransaction { txn_id: String, request: FederationTransactionRequest },
    FederationPushOperations(FederationPushOperationsRequest),
    FederationPullOperations { space_id: String, after_cursor: Option<String>, limit: Option<u32> },
    FederationSpaceMembers { space_id: String, cursor: Option<String>, limit: Option<u32> },
    FederationVerifyActor(FederationVerifyActorRequest),
    IndexDescribe,
    IndexEntity { entity_id: String, space_id: Option<String>, at: Option<String> },
    IndexQuery(Box<QueryRequest>),
    IndexThread { topic_id: String, cursor: Option<String>, limit: Option<u32> },
    IndexNotifications { cursor: Option<String>, state: Option<String>, limit: Option<u32> },
    IndexInbox { scope: Option<String>, cursor: Option<String>, limit: Option<u32> },
    IndexSearch(IndexSearchRequest),
    IndexSpaceHierarchy { space_id: String, depth: Option<u32>, include_unconfirmed: Option<bool> },
    DirectoryDescribe,
    DirectorySearchSpaces(DirectorySearchSpacesRequest),
    DirectoryResolveSpace(DirectoryResolveSpaceRequest),
    DirectorySearchOrganizations(DirectorySearchOrganizationsRequest),
    DirectoryResolveOrganization(DirectoryResolveOrganizationRequest),
    DirectorySearchActors(DirectorySearchActorsRequest),
    DirectorySearchUsers { q: String, space_id: Option<String>, limit: Option<u32> },
    DirectoryResolveHandle(DirectoryResolveHandleRequest),
    BlobUpload { metadata: BlobUploadMetadata, bytes: Option<Vec<u8>> },
    BlobHead { blob_ref: String },
    BlobGet { blob_ref: String, range: Option<String> },
    PushRegisterDevice(PushRegisterDeviceRequest),
    PushUnregisterDevice(PushUnregisterDeviceRequest),
    PushNotify(PushNotifyRequest),
    DeviceMessagesPut { txn_id: String, request: DeviceMessagesSendRequest },
    DeviceMessagesGet { from: Option<String>, limit: Option<u32> },
    KeysUpload(KeysUploadRequest),
    KeysQuery(KeysQueryRequest),
    KeysClaim(KeysClaimRequest),
    AuthzEffectiveGrants { space_id: String, subject: String, at: Option<String> },
    AuthzInvites { subject: String, space_id: Option<String>, cursor: Option<String> },
    AuthzCheck(AuthzCheckRequest),
    PolicyCheck(PolicyCheckRequest),
    MediaIceConfig(MediaIceConfigRequest),
    ModerationReport(ModerationReportRequest),
    AppletPing,
    AppletDescribe,
    AppletTransaction { txn_id: String, request: AppletTransactionRequest },
    AppletActor { actor_id: String },
    AppletSpace { space_id_or_alias: String },
    AppletProtocol { protocol: String },
    AppletThirdPartyUsers,
    AppletThirdPartyLocations,
}

#[derive(Clone, Debug)]
pub enum ServerResponse {
    ServerDescription(ServerDescription),
    IdentityDescription(IdentityDescription),
    IdentityResolve(IdentityResolveResponse),
    IdentityDocument(IdentityDocumentResponse),
    IdentityLog(IdentityLogResponse),
    SubmitDidOperation(SubmitDidOperationResponse),
    IdentityReceipts(IdentityReceiptsResponse),
    RepoDescription(RepoDescription),
    RepoCommits(RepoCommitsResponse),
    RepoCommit(RepoCommitResponse),
    RepoOperations(RepoOperationsResponse),
    RepoSync(RepoSyncResponse),
    SubmitCommit(SubmitCommitResponse),
    Sync(SyncResponse),
    SyncDescription(SyncDescription),
    SyncBackfill(SyncBackfillResponse),
    SyncSnapshotHead(SyncSnapshotHeadResponse),
    FederationTransaction(FederationTransactionResponse),
    FederationPushOperations(FederationPushOperationsResponse),
    FederationPullOperations(FederationPullOperationsResponse),
    FederationSpaceMembers(FederationSpaceMembersResponse),
    FederationVerifyActor(FederationVerifyActorResponse),
    IndexDescription(IndexDescription),
    IndexEntity(IndexEntityResponse),
    IndexQuery(QueryResponse<Value>),
    IndexThread(IndexThreadResponse),
    IndexNotifications(IndexNotificationsResponse),
    IndexInbox(IndexInboxResponse),
    IndexSearch(IndexSearchResponse),
    IndexSpaceHierarchy(IndexSpaceHierarchyResponse),
    DirectoryDescription(DirectoryDescription),
    DirectorySearchSpaces(DirectorySearchSpacesResponse),
    DirectoryResolveSpace(DirectoryResolveSpaceResponse),
    DirectorySearchOrganizations(DirectorySearchOrganizationsResponse),
    DirectoryResolveOrganization(DirectoryResolveOrganizationResponse),
    DirectorySearchActors(DirectorySearchActorsResponse),
    DirectorySearchUsers(DirectorySearchUsersResponse),
    DirectoryResolveHandle(DirectoryResolveHandleResponse),
    BlobUpload(BlobUploadResponse),
    BlobHead(BlobMetadata),
    BlobBytes(Vec<u8>),
    PushRegisterDevice(PushRegisterDeviceResponse),
    Ok(OkResponse),
    PushNotify(PushNotifyResponse),
    DeviceMessagesSend(DeviceMessagesSendResponse),
    DeviceMessagesReceive(DeviceMessagesReceiveResponse),
    KeysUpload(KeysUploadResponse),
    KeysQuery(KeysQueryResponse),
    KeysClaim(KeysClaimResponse),
    EffectiveGrants(EffectiveGrantsResponse),
    AuthzInvites(AuthzInvitesResponse),
    AuthzCheck(AuthzCheckResponse),
    PolicyCheck(PolicyCheckResponse),
    MediaIceConfig(MediaIceConfigResponse),
    ModerationReport(ModerationReportResponse),
    AppletPing(AppletPingResponse),
    AppletDescription(AppletDescription),
    AppletTransaction(AppletTransactionResponse),
    AppletActor(AppletActorResponse),
    AppletSpace(AppletSpaceResponse),
    AppletProtocol(AppletProtocolResponse),
    AppletThirdPartyUsers(Value),
    AppletThirdPartyLocations(Value),
}

pub trait EndpointHandler {
    fn handle(&mut self, request: ServerRequest) -> Result<ServerResponse>;
}

fn request_body_content_type(endpoint: &EndpointContract) -> Option<&'static str> {
    match endpoint.method {
        EndpointMethod::Post | EndpointMethod::Put => Some("application/json"),
        EndpointMethod::Get | EndpointMethod::Head => None,
    }
}

fn response_body_content_type(endpoint: &EndpointContract) -> Option<&'static str> {
    match endpoint.operation_id {
        "cx.blob.head" => None,
        "cx.blob.get" => Some("application/octet-stream"),
        "cx.sync.subscribe" => Some("application/x-ndjson"),
        _ => Some("application/json"),
    }
}

fn path_parameters(path: &'static str) -> Vec<EndpointParameter> {
    path.split('/')
        .filter_map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                Some(EndpointParameter {
                    name: &segment[1..segment.len() - 1],
                    location: EndpointParameterLocation::Path,
                    required: true,
                    schema: "String",
                })
            } else {
                None
            }
        })
        .collect()
}

fn query_parameters(operation_id: &str) -> Vec<EndpointParameter> {
    let query: &[(&str, bool, &str)] = match operation_id {
        "cx.identity.get_document" => &[("did", true, "Did"), ("version", false, "String")],
        "cx.identity.get_log" => {
            &[("did", true, "Did"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.identity.get_receipts" => &[("did", true, "Did"), ("head", true, "Hash")],
        "cx.repo.describe" => &[("repo_id", false, "Did")],
        "cx.repo.list_commits" => {
            &[("repo_id", true, "Did"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.repo.get_commit" => &[("commit_id", true, "String"), ("repo_id", false, "Did")],
        "cx.sync.subscribe" => &[("space_id", true, "SpaceId"), ("cursor", false, "String")],
        "cx.sync.backfill" => {
            &[("space_id", true, "SpaceId"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.sync.get_snapshot_head" => &[("space_id", true, "SpaceId")],
        "cx.federation.pull_operations" => &[
            ("space_id", true, "SpaceId"),
            ("after_cursor", false, "String"),
            ("limit", false, "Limit"),
        ],
        "cx.federation.space_members" => {
            &[("space_id", true, "SpaceId"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.get_entity" => &[
            ("entity_id", true, "String"),
            ("space_id", false, "SpaceId"),
            ("at", false, "String"),
        ],
        "cx.index.thread" => {
            &[("topic_id", true, "String"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.notifications" => {
            &[("cursor", false, "String"), ("state", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.inbox" => {
            &[("scope", false, "String"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.space_hierarchy" => &[
            ("space_id", true, "SpaceId"),
            ("depth", false, "Limit"),
            ("include_unconfirmed", false, "Bool"),
        ],
        "cx.directory.search_users" => {
            &[("q", true, "String"), ("space_id", false, "SpaceId"), ("limit", false, "Limit")]
        }
        "cx.blob.head" | "cx.blob.get" => &[("blob_ref", true, "BlobRef")],
        "cx.device_messages.get" => &[("from", false, "String"), ("limit", false, "Limit")],
        "cx.authz.get_effective_grants" => {
            &[("space_id", true, "SpaceId"), ("subject", true, "Did"), ("at", false, "String")]
        }
        "cx.authz.get_invites" => {
            &[("subject", true, "Did"), ("space_id", false, "SpaceId"), ("cursor", false, "String")]
        }
        _ => &[],
    };

    query
        .iter()
        .map(|(name, required, schema)| EndpointParameter {
            name,
            location: EndpointParameterLocation::Query,
            required: *required,
            schema,
        })
        .collect()
}

fn header_parameters(operation_id: &str) -> Vec<EndpointParameter> {
    let headers: &[(&str, bool, &str)] = match operation_id {
        "cx.index.query" => &[("X-Contrix-Wait-For", false, "String")],
        "cx.blob.upload" => &[
            ("X-Contrix-Blob-Metadata", false, "BlobUploadMetadata"),
            ("Content-Type", false, "String"),
            ("Content-Disposition", false, "String"),
            ("Digest", false, "Hash"),
        ],
        "cx.blob.get" => &[("Range", false, "String")],
        _ => &[],
    };

    headers
        .iter()
        .map(|(name, required, schema)| EndpointParameter {
            name,
            location: EndpointParameterLocation::Header,
            required: *required,
            schema,
        })
        .collect()
}

fn match_path_template(template: &str, path: &str) -> Option<BTreeMap<String, String>> {
    let template_segments = template.trim_matches('/').split('/');
    let path_segments = path.trim_matches('/').split('/');
    let mut parameters = BTreeMap::new();

    for (template_segment, path_segment) in template_segments.zip(path_segments) {
        if template_segment.starts_with('{') && template_segment.ends_with('}') {
            let name = &template_segment[1..template_segment.len() - 1];
            parameters.insert(name.to_owned(), path_segment.to_owned());
        } else if template_segment != path_segment {
            return None;
        }
    }

    if template.trim_matches('/').split('/').count() != path.trim_matches('/').split('/').count() {
        return None;
    }

    Some(parameters)
}

pub fn openapi_document() -> Value {
    let mut paths = Map::new();
    for endpoint in endpoint_contracts() {
        let binding = endpoint_schema_binding(endpoint);
        let mut methods = paths
            .remove(endpoint.path)
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();

        let mut operation = Map::new();
        operation.insert("operationId".to_owned(), json!(endpoint.operation_id));
        operation.insert("tags".to_owned(), json!([endpoint_tag(endpoint.operation_id)]));
        operation.insert(
            "x-contrix-request-schema".to_owned(),
            json!(format!("#/components/schemas/{}", binding.request_schema)),
        );
        operation.insert(
            "x-contrix-response-schema".to_owned(),
            json!(format!("#/components/schemas/{}", binding.response_schema)),
        );
        operation.insert("security".to_owned(), operation_security(endpoint.operation_id));
        operation.insert(
            "parameters".to_owned(),
            Value::Array(
                endpoint_parameters(endpoint).into_iter().map(openapi_parameter).collect(),
            ),
        );

        if let Some(content_type) = binding.request_body_content_type {
            operation.insert(
                "requestBody".to_owned(),
                openapi_request_body(content_type, binding.request_schema, endpoint.operation_id),
            );
        }

        operation.insert(
            "responses".to_owned(),
            openapi_responses(binding.response_body_content_type, binding.response_schema),
        );

        methods.insert(endpoint.method.as_str().to_owned(), Value::Object(operation));
        paths.insert(endpoint.path.to_owned(), Value::Object(methods));
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Contrix v1 Service HTTP Binding",
            "version": "1.0"
        },
        "paths": paths,
        "components": {
            "schemas": openapi_schema_components(),
            "responses": openapi_response_components(),
            "parameters": openapi_parameter_components(),
            "examples": openapi_examples(),
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer" },
                "bearerAuth": { "type": "http", "scheme": "bearer" },
                "deviceProof": { "type": "apiKey", "in": "header", "name": "X-Contrix-Device-Proof" },
                "serviceSignature": { "type": "apiKey", "in": "header", "name": "Signature" },
                "httpMessageSignature": { "type": "apiKey", "in": "header", "name": "Signature" },
                "mutualTls": { "type": "mutualTLS" }
            }
        }
    })
}

fn endpoint_tag(operation_id: &str) -> &str {
    operation_id
        .strip_prefix("cx.")
        .and_then(|rest| rest.split_once('.').map(|(tag, _)| tag))
        .unwrap_or("core")
}

fn operation_security(operation_id: &str) -> Value {
    if matches!(
        operation_id,
        "cx.server.describe"
            | "cx.identity.describe_registry"
            | "cx.sync.describe"
            | "cx.index.describe"
            | "cx.directory.describe"
            | "cx.applet.ping"
            | "cx.applet.describe"
    ) {
        json!([{}])
    } else if operation_id.starts_with("cx.federation.") {
        json!([{ "serviceSignature": [] }])
    } else {
        json!([{ "bearer": [] }, { "deviceProof": [] }, { "serviceSignature": [] }])
    }
}

fn openapi_parameter(parameter: EndpointParameter) -> Value {
    let schema = parameter_schema(parameter.schema);
    json!({
        "name": parameter.name,
        "in": parameter.location.as_str(),
        "required": parameter.required,
        "schema": schema
    })
}

fn parameter_schema(name: &str) -> Value {
    match name {
        "Bool" => json!({ "type": "boolean" }),
        "Limit" => json!({ "type": "integer", "minimum": 1, "maximum": 1000 }),
        "String" => json!({ "type": "string" }),
        _ => json!({ "$ref": format!("#/components/schemas/{name}") }),
    }
}

fn openapi_request_body(content_type: &str, schema: &str, operation_id: &str) -> Value {
    if operation_id == "cx.blob.upload" {
        return json!({
            "required": true,
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/BlobUploadMetadata" },
                    "examples": {
                        "blobUpload": { "$ref": "#/components/examples/BlobUploadMetadata" }
                    }
                },
                "application/octet-stream": {
                    "schema": { "$ref": "#/components/schemas/BinaryBlobBody" }
                }
            }
        });
    }

    let mut content = Map::new();
    let mut media = Map::new();
    media.insert("schema".to_owned(), json!({ "$ref": format!("#/components/schemas/{schema}") }));

    if let Some(example) = request_example_ref(operation_id) {
        media.insert("examples".to_owned(), json!({ "default": { "$ref": example } }));
    }

    content.insert(content_type.to_owned(), Value::Object(media));
    json!({ "required": true, "content": content })
}

fn openapi_responses(content_type: Option<&str>, schema: &str) -> Value {
    let success = if let Some(content_type) = content_type {
        json!({
            "description": "Successful Contrix response",
            "content": {
                content_type: {
                    "schema": { "$ref": format!("#/components/schemas/{schema}") }
                }
            }
        })
    } else {
        json!({ "description": "Successful Contrix response with headers only" })
    };

    json!({
        "200": success,
        "400": { "$ref": "#/components/responses/BadRequestError" },
        "401": { "$ref": "#/components/responses/UnauthorizedError" },
        "403": { "$ref": "#/components/responses/ForbiddenError" },
        "404": { "$ref": "#/components/responses/NotFoundPrivacyError" },
        "405": { "$ref": "#/components/responses/MethodNotAllowedError" },
        "409": { "$ref": "#/components/responses/IdempotencyConflictError" },
        "410": { "$ref": "#/components/responses/StaleCursorError" },
        "428": { "$ref": "#/components/responses/IdempotencyRequiredError" },
        "429": { "$ref": "#/components/responses/RateLimitedError" },
        "503": { "$ref": "#/components/responses/UnavailableError" }
    })
}

fn openapi_schema_components() -> Value {
    let mut schema_names = BTreeSet::from([
        "ApiConventionMetadata",
        "BinaryBlobBody",
        "BlobMetadataHeaders",
        "Bool",
        "Commit",
        "Did",
        "ErrorEnvelope",
        "FacetName",
        "Hash",
        "HttpMessageSignature",
        "HttpTraceMetadata",
        "JsonValue",
        "Limit",
        "QuotaMetadata",
        "RateLimitMetadata",
        "ServiceDidAllowlist",
        "SpaceId",
        "String",
        "ViewRenderer",
        "WellKnownContrixServer",
    ]);

    for binding in endpoint_schema_bindings() {
        schema_names.insert(binding.request_schema);
        schema_names.insert(binding.response_schema);
    }

    let mut schemas = Map::new();
    for name in schema_names {
        schemas.insert(name.to_owned(), generic_schema(name));
    }

    schemas.insert("Did".to_owned(), json!({ "type": "string", "pattern": "^did:[a-z0-9]+:.+$" }));
    schemas.insert("SpaceId".to_owned(), json!({ "type": "string", "pattern": "^cx:space:.+$" }));
    schemas
        .insert("Hash".to_owned(), json!({ "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" }));
    schemas.insert("String".to_owned(), json!({ "type": "string" }));
    schemas.insert(
        "FacetName".to_owned(),
        json!({
            "type": "string",
            "enum": [
                "container", "replyable", "schedulable", "assignable", "stateful",
                "rankable", "reviewable", "notifiable", "documentable", "renderable"
            ]
        }),
    );
    schemas.insert(
        "ViewRenderer".to_owned(),
        json!({
            "type": "string",
            "enum": [
                "board", "card", "row", "table", "calendar", "gantt", "timeline",
                "thread", "chat", "forum", "graph", "tree", "document", "dashboard", "custom"
            ]
        }),
    );
    schemas.insert(
        "QueryRequest".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "space_ids": { "type": "array", "items": { "$ref": "#/components/schemas/SpaceId" } },
                "entity_types": { "type": "array", "items": { "type": "string" } },
                "facets": { "type": "array", "items": { "$ref": "#/components/schemas/FacetName" }, "uniqueItems": true },
                "renderer": { "$ref": "#/components/schemas/ViewRenderer" },
                "anchor_entity_id": { "type": "string" },
                "filters": { "type": "array", "items": { "$ref": "#/components/schemas/JsonValue" } },
                "relation": { "$ref": "#/components/schemas/JsonValue" },
                "context": { "$ref": "#/components/schemas/JsonValue" },
                "order_by": { "type": "array", "items": { "$ref": "#/components/schemas/JsonValue" } },
                "projection": { "type": "array", "items": { "type": "string" } },
                "cursor": { "type": "string" },
                "limit": { "$ref": "#/components/schemas/Limit" },
                "consistency": { "$ref": "#/components/schemas/JsonValue" }
            },
            "additionalProperties": true
        }),
    );
    schemas.insert("Bool".to_owned(), json!({ "type": "boolean" }));
    schemas.insert("Limit".to_owned(), json!({ "type": "integer", "minimum": 1, "maximum": 1000 }));
    schemas.insert(
        "JsonValue".to_owned(),
        json!({ "description": "Arbitrary JSON value accepted by extension points" }),
    );
    schemas.insert("BinaryBlobBody".to_owned(), json!({ "type": "string", "format": "binary" }));
    schemas.insert(
        "ErrorEnvelope".to_owned(),
        json!({
            "type": "object",
            "required": ["errcode", "error"],
            "properties": {
                "errcode": { "type": "string" },
                "error": { "type": "string" },
                "retry_after_ms": { "type": "integer", "minimum": 0 },
                "trace": { "$ref": "#/components/schemas/HttpTraceMetadata" },
                "rate_limit": { "$ref": "#/components/schemas/RateLimitMetadata" },
                "quota": { "$ref": "#/components/schemas/QuotaMetadata" }
            },
            "additionalProperties": true
        }),
    );
    schemas.insert(
        "ServerDescription".to_owned(),
        json!({
            "type": "object",
            "required": ["service_did", "service_type", "protocol_version"],
            "properties": {
                "service_did": { "$ref": "#/components/schemas/Did" },
                "service_type": { "type": "string" },
                "protocol_version": { "type": "string" },
                "supported_operations": { "type": "array", "items": { "type": "string" } },
                "auth_metadata": { "$ref": "#/components/schemas/JsonValue" },
                "limits": { "$ref": "#/components/schemas/JsonValue" }
            },
            "additionalProperties": true
        }),
    );
    schemas.insert(
        "FederationTransactionRequest".to_owned(),
        json!({
            "type": "object",
            "required": ["origin", "destination", "service_binding_ref", "operations"],
            "properties": {
                "origin": { "$ref": "#/components/schemas/Did" },
                "destination": { "$ref": "#/components/schemas/Did" },
                "service_binding_ref": { "type": "string" },
                "operations": { "type": "array", "items": { "$ref": "#/components/schemas/JsonValue" } },
                "receipts": { "type": "array", "items": { "$ref": "#/components/schemas/JsonValue" } },
                "frontier": { "type": "string" }
            },
            "additionalProperties": false
        }),
    );
    schemas.insert(
        "HttpTraceMetadata".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "request_id": { "type": "string" },
                "actor_id": { "$ref": "#/components/schemas/Did" },
                "device_id": { "type": "string" },
                "space_id": { "$ref": "#/components/schemas/SpaceId" },
                "operation_id": { "type": "string" },
                "commit_id": { "type": "string" }
            },
            "additionalProperties": false
        }),
    );

    Value::Object(schemas)
}

fn generic_schema(name: &str) -> Value {
    json!({
        "type": "object",
        "description": format!("Contrix SDK model {name}. Field-level validation lives in the Rust type and protocol validators."),
        "x-contrix-rust-type": name,
        "additionalProperties": true
    })
}

fn openapi_response_components() -> Value {
    let error_response = |description: &str, example: &str| {
        json!({
            "description": description,
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ErrorEnvelope" },
                    "examples": {
                        "default": { "$ref": format!("#/components/examples/{example}") }
                    }
                }
            }
        })
    };

    json!({
        "BadRequestError": error_response("Malformed request or protocol validation failure", "BadRequestError"),
        "UnauthorizedError": error_response("Authentication is missing or invalid", "UnauthorizedError"),
        "ForbiddenError": error_response("Authenticated principal is not authorized", "ForbiddenError"),
        "NotFoundPrivacyError": error_response("Resource is nonexistent or invisible under privacy-preserving not-found semantics", "NotFoundPrivacyError"),
        "MethodNotAllowedError": error_response("HTTP method is not registered for this endpoint", "MethodNotAllowedError"),
        "IdempotencyConflictError": error_response("Idempotency-Key was reused with different request bytes", "IdempotencyConflictError"),
        "StaleCursorError": error_response("Cursor is expired or no longer replayable", "StaleCursorError"),
        "IdempotencyRequiredError": error_response("Mutating endpoint requires Idempotency-Key", "IdempotencyRequiredError"),
        "RateLimitedError": error_response("Request was rate limited", "RateLimitedError"),
        "UnavailableError": error_response("Service is temporarily unavailable", "UnavailableError"),
        "ErrorEnvelope": error_response("Standard Contrix error envelope", "BadRequestError")
    })
}

fn openapi_parameter_components() -> Value {
    json!({
        "RequestId": {
            "name": "X-Contrix-Request-Id",
            "in": "header",
            "required": false,
            "schema": { "type": "string" }
        },
        "Traceparent": {
            "name": "Traceparent",
            "in": "header",
            "required": false,
            "schema": { "type": "string" }
        }
    })
}

fn openapi_examples() -> Value {
    json!({
        "ServerDescription": {
            "summary": "Principal service description",
            "value": {
                "service_did": "did:web:svc.example",
                "service_type": "principal_server",
                "protocol_version": contrix_core::PROTOCOL_VERSION,
                "supported_operations": ["cx.server.describe", "cx.sync.client_sync"]
            }
        },
        "SyncRequest": {
            "summary": "Incremental sync request",
            "value": {
                "since": "cx:cursor:sync:01JS0SP000000000000000000",
                "space_ids": ["cx:space:01JS0SP000000000000000000"],
                "timeout_ms": 30000
            }
        },
        "FederationTransactionRequest": {
            "summary": "Federated operation transaction",
            "value": {
                "origin": "did:web:a.example",
                "destination": "did:web:b.example",
                "service_binding_ref": "did:web:a.example#contrix-federation",
                "operations": [],
                "frontier": "cx:cursor:federation:01JS0SP000000000000000000"
            }
        },
        "BlobUploadMetadata": {
            "summary": "Blob upload metadata",
            "value": {
                "space_id": "cx:space:01JS0SP000000000000000000",
                "size": 4,
                "media_type": "text/plain",
                "sha256": "sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
            }
        },
        "BadRequestError": {
            "value": { "errcode": "cx.error.bad_request", "error": "Malformed Contrix request" }
        },
        "UnauthorizedError": {
            "value": { "errcode": "cx.error.unauthorized", "error": "Authentication required" }
        },
        "ForbiddenError": {
            "value": { "errcode": "cx.error.forbidden", "error": "Not authorized" }
        },
        "NotFoundPrivacyError": {
            "value": { "errcode": "cx.error.not_found", "error": "Resource not found" }
        },
        "MethodNotAllowedError": {
            "value": { "errcode": "cx.error.method_not_allowed", "error": "Method not allowed" }
        },
        "IdempotencyConflictError": {
            "value": { "errcode": "cx.error.idempotency_conflict", "error": "Idempotency-Key was reused with different request bytes" }
        },
        "StaleCursorError": {
            "value": { "errcode": "cx.error.stale_cursor", "error": "Cursor is expired" }
        },
        "IdempotencyRequiredError": {
            "value": { "errcode": "cx.error.idempotency_required", "error": "Mutating Contrix endpoints require Idempotency-Key" }
        },
        "RateLimitedError": {
            "value": {
                "errcode": "cx.error.rate_limited",
                "error": "Too many requests",
                "retry_after_ms": 1000,
                "rate_limit": { "scope": "actor", "limit": 60, "remaining": 0 }
            }
        },
        "UnavailableError": {
            "value": { "errcode": "cx.error.unavailable", "error": "Service unavailable" }
        }
    })
}

fn request_example_ref(operation_id: &str) -> Option<&'static str> {
    match operation_id {
        "cx.sync.client_sync" => Some("#/components/examples/SyncRequest"),
        "cx.federation.transaction" => Some("#/components/examples/FederationTransactionRequest"),
        "cx.blob.upload" => Some("#/components/examples/BlobUploadMetadata"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_operation_ids_are_unique() {
        let mut ids = BTreeSet::new();
        for endpoint in endpoint_contracts() {
            assert!(ids.insert(endpoint.operation_id), "duplicate {}", endpoint.operation_id);
            assert!(
                endpoint.path.starts_with("/api/v1/") || endpoint.path.starts_with("/contrix/v1/")
            );
        }
    }

    #[test]
    fn endpoint_registry_matches_required_spec_operations() {
        let actual = endpoint_contracts()
            .iter()
            .map(|endpoint| (endpoint.operation_id, endpoint.path))
            .collect::<BTreeMap<_, _>>();
        for (operation_id, path) in [
            ("cx.identity.resolve", "/api/v1/identity/resolve"),
            ("cx.repo.submit_commit", "/api/v1/repo/submit-commit"),
            ("cx.repo.get_operations", "/api/v1/repo/operations"),
            ("cx.sync.client_sync", "/api/v1/sync"),
            ("cx.sync.subscribe", "/api/v1/sync/subscribe"),
            ("cx.sync.backfill", "/api/v1/sync/backfill"),
            ("cx.federation.transaction", "/api/v1/federation/transactions/{txn_id}"),
            ("cx.index.query", "/api/v1/index/query"),
            ("cx.directory.resolve_handle", "/api/v1/directory/resolve-handle"),
            (
                "cx.directory.private_contact_discovery",
                "/api/v1/directory/private-contact-discovery",
            ),
            ("cx.blob.upload", "/api/v1/blob/upload"),
            ("cx.push.register_device", "/api/v1/push/register-device"),
            ("cx.device_messages.put", "/api/v1/device_messages/{txn_id}"),
            ("cx.keys.upload", "/api/v1/keys/upload"),
            ("cx.keys.keypackages.upload", "/api/v1/keys/keypackages/upload"),
            ("cx.keys.keypackages.claim", "/api/v1/keys/keypackages/claim"),
            ("cx.keys.keypackages.consume", "/api/v1/keys/keypackages/consume"),
            ("cx.keys.keypackages.revoke", "/api/v1/keys/keypackages/revoke"),
            ("cx.authz.check", "/api/v1/authz/check"),
            ("cx.policy.check", "/contrix/v1/check"),
            ("cx.media.ice_config", "/contrix/v1/ice-config"),
            ("cx.moderation.report", "/api/v1/moderation/report"),
            ("cx.mimi.provider_directory", "/api/v1/mimi/provider-directory"),
            ("cx.mimi.key_material", "/api/v1/mimi/key-material"),
            ("cx.mimi.room_update", "/api/v1/mimi/rooms/{room_id}/update"),
            ("cx.mimi.notify", "/api/v1/mimi/rooms/{room_id}/notify"),
            ("cx.mimi.submit_message", "/api/v1/mimi/rooms/{room_id}/messages"),
            ("cx.mimi.group_info", "/api/v1/mimi/rooms/{room_id}/group-info"),
            ("cx.mimi.request_consent", "/api/v1/mimi/consent/request"),
            ("cx.mimi.update_consent", "/api/v1/mimi/consent/update"),
            ("cx.mimi.identifier_query", "/api/v1/mimi/identifiers/query"),
            ("cx.mimi.report_abuse", "/api/v1/mimi/report-abuse"),
            ("cx.mimi.proxy_download", "/api/v1/mimi/proxy-download"),
            ("cx.account.issue_session_grant", "/api/v1/auth/account/session-grants"),
            ("cx.account.device_pair", "/api/v1/auth/account/device-pair"),
            ("cx.account.oidc_callback", "/api/v1/auth/account/oidc/callback"),
            ("cx.admin.get_server_status", "/api/v1/admin/server/status"),
            ("cx.admin.update_account_status", "/api/v1/admin/accounts/{account_id}/status"),
            ("cx.admin.revoke_device", "/api/v1/admin/devices/{device_id}/revoke"),
            ("cx.admin.get_moderation_queue", "/api/v1/admin/moderation/queue"),
            ("cx.applet.transaction", "/api/v1/applet/transactions/{txn_id}"),
        ] {
            assert_eq!(actual.get(operation_id), Some(&path), "{operation_id}");
        }
    }

    #[test]
    fn openapi_document_contains_standard_error_envelope() {
        let document = openapi_document();
        assert_eq!(document["openapi"], "3.1.0");
        assert!(document["paths"]["/api/v1/sync"]["post"]["responses"]["429"].is_object());
        assert!(document["paths"]["/api/v1/sync"]["post"]["responses"]["428"].is_object());
        assert!(document["components"]["schemas"]["ErrorEnvelope"].is_object());
        assert!(document["components"]["responses"]["RateLimitedError"].is_object());
        assert!(document["components"]["responses"]["IdempotencyConflictError"].is_object());
        assert!(document["components"]["securitySchemes"].get("queryToken").is_none());
        assert!(document["components"]["securitySchemes"]["bearerAuth"].is_object());
        assert!(document["components"]["securitySchemes"]["httpMessageSignature"].is_object());
        assert!(document["components"]["securitySchemes"]["mutualTls"].is_object());
    }

    #[test]
    fn openapi_document_has_schema_binding_for_every_endpoint() {
        let document = openapi_document();
        for endpoint in endpoint_contracts() {
            let binding = endpoint_schema_binding(endpoint);
            assert!(
                document["components"]["schemas"].get(binding.request_schema).is_some(),
                "{} request schema {}",
                endpoint.operation_id,
                binding.request_schema
            );
            assert!(
                document["components"]["schemas"].get(binding.response_schema).is_some(),
                "{} response schema {}",
                endpoint.operation_id,
                binding.response_schema
            );
            assert_eq!(
                document["paths"][endpoint.path][endpoint.method.as_str()]["operationId"],
                endpoint.operation_id
            );
        }
        assert!(
            document["paths"]["/api/v1/federation/transactions/{txn_id}"]["put"]["requestBody"]
                .is_object()
        );
        assert!(
            document["components"]["examples"]["FederationTransactionRequest"]["value"].is_object()
        );
    }

    #[test]
    fn endpoint_matcher_extracts_path_parameters_for_framework_adapters() {
        let matched =
            match_endpoint(EndpointMethod::Put, "/api/v1/applet/transactions/txn_123").unwrap();
        assert_eq!(matched.contract.operation_id, "cx.applet.transaction");
        assert_eq!(matched.path_parameters["txn_id"], "txn_123");
        assert!(
            match_endpoint(EndpointMethod::Get, "/api/v1/applet/transactions/txn_123").is_none()
        );
    }

    #[test]
    fn tower_like_endpoint_service_can_wrap_framework_closure() {
        let mut service = |request: HttpAdapterRequest| {
            let matched = match_endpoint(request.method, &request.path)
                .ok_or_else(|| contrix_core::Error::Protocol("no route".to_owned()))?;
            Ok(HttpAdapterResponse {
                status: 200,
                headers: BTreeMap::from([(
                    "X-Contrix-Operation-Id".to_owned(),
                    matched.contract.operation_id.to_owned(),
                )]),
                body: Vec::new(),
            })
        };

        let response = TowerLikeEndpointService::call(
            &mut service,
            HttpAdapterRequest {
                method: EndpointMethod::Get,
                path: "/api/v1/server/describe".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(response.headers["X-Contrix-Operation-Id"], "cx.server.describe");
    }

    #[test]
    fn routed_http_dispatch_matches_registry_and_path_params() {
        let mut service = |request: RoutedHttpAdapterRequest| {
            assert_eq!(request.operation_id, "cx.applet.transaction");
            assert_eq!(request.path_parameters["txn_id"], "txn_123");
            Ok(HttpAdapterResponse {
                status: 202,
                headers: BTreeMap::new(),
                body: request.request.body,
            })
        };

        let response = dispatch_routed_http_request(
            &mut service,
            HttpAdapterRequest {
                method: EndpointMethod::Put,
                path: "/api/v1/applet/transactions/txn_123".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: br#"{"ok":true}"#.to_vec(),
            },
        );

        assert_eq!(response.status, 202);
        assert_eq!(response.headers["X-Contrix-Operation-Id"], "cx.applet.transaction");
        assert_eq!(response.body, br#"{"ok":true}"#);
    }

    #[test]
    fn routed_http_dispatch_rejects_query_auth_and_unknown_routes() {
        use std::cell::Cell;

        let called = Cell::new(false);
        let mut service = |_request: RoutedHttpAdapterRequest| {
            called.set(true);
            Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
        };

        let rejected = dispatch_routed_http_request(
            &mut service,
            HttpAdapterRequest {
                method: EndpointMethod::Get,
                path: "/api/v1/server/describe".to_owned(),
                query: BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]),
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(rejected.status, 400);
        assert!(!called.get());

        let missing = dispatch_routed_http_request(
            &mut service,
            HttpAdapterRequest {
                method: EndpointMethod::Get,
                path: "/api/v1/nope".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(missing.status, 404);
        assert!(!called.get());
    }

    #[test]
    fn server_middleware_allows_public_describe_without_auth() {
        use std::cell::Cell;

        let called = Cell::new(false);
        let service = |_request: RoutedHttpAdapterRequest| {
            called.set(true);
            Ok(HttpAdapterResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: br#"{"ok":true}"#.to_vec(),
            })
        };
        let mut service = ServerMiddlewareStack::new(service);

        let response = dispatch_routed_http_request(
            &mut service,
            HttpAdapterRequest {
                method: EndpointMethod::Get,
                path: "/api/v1/server/describe".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
        );

        assert_eq!(response.status, 200);
        assert!(called.get());
    }

    #[test]
    fn server_middleware_requires_auth_for_private_operations() {
        use std::cell::Cell;

        let called = Cell::new(false);
        let service = |_request: RoutedHttpAdapterRequest| {
            called.set(true);
            Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
        };
        let mut service = ServerMiddlewareStack::new(service);

        let response = dispatch_routed_http_request(
            &mut service,
            HttpAdapterRequest {
                method: EndpointMethod::Post,
                path: "/api/v1/sync".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: br#"{}"#.to_vec(),
            },
        );

        assert_eq!(response.status, 401);
        assert!(!called.get());
    }

    #[test]
    fn server_middleware_enforces_operation_scope_and_idempotency() {
        use std::cell::Cell;

        let calls = Cell::new(0);
        let service = |_request: RoutedHttpAdapterRequest| {
            let call = calls.get() + 1;
            calls.set(call);
            Ok(HttpAdapterResponse {
                status: 202,
                headers: BTreeMap::new(),
                body: format!("call-{call}").into_bytes(),
            })
        };
        let authenticator = BearerTokenAuthenticator::new().with_token(
            "sync-token",
            AuthenticatedPrincipal::bearer(
                "did:web:alice.example",
                ["operation:cx.sync.client_sync".to_owned()],
            ),
        );
        let mut service = ServerMiddlewareStack::new(service).with_authenticator(authenticator);

        let request = || HttpAdapterRequest {
            method: EndpointMethod::Post,
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([
                ("Authorization".to_owned(), "Bearer sync-token".to_owned()),
                ("Idempotency-Key".to_owned(), "sync-1".to_owned()),
            ]),
            body: br#"{"since":"s1"}"#.to_vec(),
        };

        let first = dispatch_routed_http_request(&mut service, request());
        let second = dispatch_routed_http_request(&mut service, request());
        assert_eq!(first.status, 202);
        assert_eq!(second.status, 202);
        assert_eq!(first.body, b"call-1");
        assert_eq!(second.body, b"call-1");
        assert_eq!(calls.get(), 1);

        let conflict = dispatch_routed_http_request(
            &mut service,
            HttpAdapterRequest { body: br#"{"since":"s2"}"#.to_vec(), ..request() },
        );
        assert_eq!(conflict.status, 409);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn server_middleware_rejects_missing_scope_and_missing_idempotency_key() {
        let service = |_request: RoutedHttpAdapterRequest| {
            Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
        };
        let authenticator = BearerTokenAuthenticator::new().with_token(
            "wrong-token",
            AuthenticatedPrincipal::bearer(
                "did:web:alice.example",
                ["operation:cx.repo.sync".to_owned()],
            ),
        );
        let mut missing_scope =
            ServerMiddlewareStack::new(service).with_authenticator(authenticator);

        let forbidden = dispatch_routed_http_request(
            &mut missing_scope,
            HttpAdapterRequest {
                method: EndpointMethod::Post,
                path: "/api/v1/sync".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::from([
                    ("Authorization".to_owned(), "Bearer wrong-token".to_owned()),
                    ("Idempotency-Key".to_owned(), "sync-1".to_owned()),
                ]),
                body: br#"{}"#.to_vec(),
            },
        );
        assert_eq!(forbidden.status, 403);

        let authenticator = BearerTokenAuthenticator::new().with_token(
            "sync-token",
            AuthenticatedPrincipal::bearer(
                "did:web:alice.example",
                ["operation:cx.sync.client_sync".to_owned()],
            ),
        );
        let service = |_request: RoutedHttpAdapterRequest| {
            Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
        };
        let mut missing_idempotency =
            ServerMiddlewareStack::new(service).with_authenticator(authenticator);
        let rejected = dispatch_routed_http_request(
            &mut missing_idempotency,
            HttpAdapterRequest {
                method: EndpointMethod::Post,
                path: "/api/v1/sync".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::from([(
                    "Authorization".to_owned(),
                    "Bearer sync-token".to_owned(),
                )]),
                body: br#"{}"#.to_vec(),
            },
        );
        assert_eq!(rejected.status, 428);
    }

    #[test]
    fn server_middleware_rate_limits_before_service_call() {
        use std::cell::Cell;

        let calls = Cell::new(0);
        let service = |_request: RoutedHttpAdapterRequest| {
            calls.set(calls.get() + 1);
            Ok(HttpAdapterResponse { status: 200, headers: BTreeMap::new(), body: Vec::new() })
        };
        let mut service = ServerMiddlewareStack::new(service)
            .with_rate_limiter(MemoryRateLimiter::new(1, Duration::from_secs(60)));

        let request = || HttpAdapterRequest {
            method: EndpointMethod::Get,
            path: "/api/v1/server/describe".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };

        let first = dispatch_routed_http_request(&mut service, request());
        let second = dispatch_routed_http_request(&mut service, request());
        assert_eq!(first.status, 200);
        assert_eq!(second.status, 429);
        let retry_after = second.headers["Retry-After"].parse::<u64>().unwrap();
        assert!((1..=60).contains(&retry_after));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn query_auth_and_wire_negative_vectors_are_available() {
        let query = BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]);
        assert!(reject_query_auth(&query).is_err());

        let vectors = wire_negative_vectors();
        assert!(vectors.iter().any(|vector| vector.name == "query_auth_rejected"));
        assert!(vectors.iter().any(|vector| vector.expected_errcode == "cx.error.bad_digest"));
        assert!(
            vectors.iter().any(|vector| vector.expected_errcode == "cx.error.idempotency_required")
        );

        let golden = protocol_golden_vectors();
        assert!(golden.iter().any(|vector| vector.profile == "cx.conformance.digest.v1"));
    }

    #[test]
    fn protocol_server_fixture_covers_core_flow_groups() {
        let report = ProtocolServerFixture::default().run().unwrap();

        for flow in [
            ProtocolFixtureFlow::Server,
            ProtocolFixtureFlow::Identity,
            ProtocolFixtureFlow::Repo,
            ProtocolFixtureFlow::Sync,
            ProtocolFixtureFlow::Blob,
            ProtocolFixtureFlow::Authz,
            ProtocolFixtureFlow::Federation,
            ProtocolFixtureFlow::Index,
            ProtocolFixtureFlow::Directory,
            ProtocolFixtureFlow::Push,
            ProtocolFixtureFlow::DeviceMessages,
            ProtocolFixtureFlow::Keys,
            ProtocolFixtureFlow::Policy,
            ProtocolFixtureFlow::Media,
            ProtocolFixtureFlow::Moderation,
            ProtocolFixtureFlow::Applet,
        ] {
            assert!(report.covers(flow));
        }
        assert!(report.steps.iter().any(|step| {
            step.flow == ProtocolFixtureFlow::Blob
                && step.operation_id == "cx.blob.get"
                && step.response_schema == "BinaryBlobBody"
        }));
        assert!(report.steps.iter().any(|step| {
            step.flow == ProtocolFixtureFlow::Federation
                && step.operation_id == "cx.federation.push_operations"
        }));
    }

    #[test]
    fn framework_independent_handler_shape_can_be_mocked() {
        struct MockHandler;

        impl EndpointHandler for MockHandler {
            fn handle(&mut self, request: ServerRequest) -> Result<ServerResponse> {
                match request {
                    ServerRequest::ServerDescribe => {
                        Ok(ServerResponse::ServerDescription(ServerDescription {
                            service_did: contrix_core::Did::new("did:web:svc.example").unwrap(),
                            service_type: "principal_server".to_owned(),
                            protocol_version: contrix_core::PROTOCOL_VERSION.to_owned(),
                            supported_profiles: vec![],
                            supported_features: vec![],
                            supported_operations: endpoint_contracts()
                                .iter()
                                .map(|endpoint| endpoint.operation_id.to_owned())
                                .collect(),
                            supported_bindings: vec![],
                            supported_reducer_profiles: vec![],
                            supported_schema_profiles: vec![],
                            auth_metadata: Value::Null,
                            limits: Value::Null,
                        }))
                    }
                    _ => Err(contrix_core::Error::Protocol(
                        "mock endpoint not implemented".to_owned(),
                    )),
                }
            }
        }

        let mut handler = MockHandler;
        let response = handler.handle(ServerRequest::ServerDescribe).unwrap();
        let ServerResponse::ServerDescription(description) = response else {
            panic!("unexpected response");
        };
        assert!(description.supported_operations.contains(&"cx.sync.client_sync".to_owned()));
    }
}
