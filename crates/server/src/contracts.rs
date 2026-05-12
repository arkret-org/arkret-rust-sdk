use super::middleware::{adapter_error_response, header_value};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
}

impl EndpointMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Post => "post",
            Self::Put => "put",
            Self::Delete => "delete",
        }
    }
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
